package io.threatlens.core.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import io.threatlens.MainActivity
import io.threatlens.ui.screens.ThreatBlockedActivity
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

class ThreatLensVpnService : VpnService() {

    companion object {
        const val ACTION_START = "io.threatlens.vpn.START"
        const val ACTION_STOP = "io.threatlens.vpn.STOP"
        private const val NOTIFICATION_ID = 9021
        private const val CHANNEL_ID = "threatlens_vpn_channel"

        private val _isVpnActive = MutableStateFlow(false)
        val isVpnActive: StateFlow<Boolean> = _isVpnActive.asStateFlow()

        private val _activeDnsProvider = MutableStateFlow(DnsProviders.ADGUARD)
        val activeDnsProvider: StateFlow<DnsProvider> = _activeDnsProvider.asStateFlow()

        fun setDnsProvider(provider: DnsProvider) {
            _activeDnsProvider.value = provider
        }
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnJob: Job? = null
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                stopSelf()
            }
            ACTION_START, null -> {
                startVpn()
            }
        }
        return START_STICKY
    }

    private fun startVpn() {
        if (_isVpnActive.value) return

        try {
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(
                    NOTIFICATION_ID,
                    buildVpnNotification(),
                    android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                )
            } else {
                startForeground(NOTIFICATION_ID, buildVpnNotification())
            }
        } catch (_: Exception) {}

        try {
            val builder = Builder()
                .setSession("ThreatLens Web & Link Shield")
                .addAddress("10.111.222.1", 24)
                .addDnsServer("10.111.222.1")
                // Only route the fake DNS server IP through the VPN interface!
                // All normal TCP/UDP web and app traffic completely bypasses VPN with 0 latency & 0 battery drain.
                .addRoute("10.111.222.1", 32)
                .setMtu(1500)
                .setBlocking(true)

            // Apply VPN Exclusions (Apps that completely bypass the VPN interface)
            val bypassedPackages = io.threatlens.core.exclusions.ExclusionManager.getVpnBypassedApps()
            for (pkg in bypassedPackages) {
                try {
                    builder.addDisallowedApplication(pkg)
                } catch (_: Exception) {}
            }

            vpnInterface = builder.establish()
            if (vpnInterface == null) {
                stopSelf()
                return
            }

            _isVpnActive.value = true

            vpnJob = serviceScope.launch {
                runVpnPacketLoop(vpnInterface!!)
            }
        } catch (e: Exception) {
            stopVpn()
            stopSelf()
        }
    }

    private suspend fun runVpnPacketLoop(pfd: ParcelFileDescriptor) = withContext(Dispatchers.IO) {
        val input = FileInputStream(pfd.fileDescriptor)
        val output = FileOutputStream(pfd.fileDescriptor)
        val buffer = ByteArray(4096)

        // Protect socket for upstream DNS communication so it doesn't loop back to VPN
        val upstreamSocket = DatagramSocket()
        protect(upstreamSocket)
        upstreamSocket.soTimeout = 2500

        try {
            while (isActive && _isVpnActive.value) {
                val length = input.read(buffer)
                if (length <= 0) continue

                val query = DnsPacketParser.parseQuery(buffer, length) ?: continue
                val domain = query.domain
                val decision = DomainFilterEngine.evaluateDomain(domain)

                when (decision.action) {
                    FilterAction.BLOCK_AD -> {
                        // Return 0.0.0.0 sinkhole response immediately
                        val sinkholePacket = DnsPacketParser.buildSinkholeResponsePacket(query)
                        output.write(sinkholePacket)
                    }
                    FilterAction.BLOCK_MALWARE -> {
                        // Return sinkhole response so browser cannot reach attacker
                        val sinkholePacket = DnsPacketParser.buildSinkholeResponsePacket(query)
                        output.write(sinkholePacket)

                        // Launch full-screen Threat Intercept Page!
                        launchThreatBlockedActivity(
                            domain = domain,
                            category = decision.category.label,
                            sources = decision.sources,
                            reason = decision.reason
                        )
                    }
                    FilterAction.ALLOW -> {
                        // Forward query via Encrypted DoH or Protected Fast UDP
                        try {
                            var dnsResponse: ByteArray? = null

                            // 1. Try Encrypted DNS-over-HTTPS (DoH) if enabled and supported
                            val dohUrl = _activeDnsProvider.value.dohUrl
                            if (DohResolver.isDohEnabled.value && !dohUrl.isNullOrBlank()) {
                                dnsResponse = DohResolver.resolveQuery(dohUrl, query.rawDnsPayload)
                            }

                            // 2. Fall back to standard protected UDP Port 53 Anycast
                            if (dnsResponse == null) {
                                val upstreamIp = _activeDnsProvider.value.primaryIp
                                val upstreamAddr = InetAddress.getByName(upstreamIp)
                                val sendPacket = DatagramPacket(
                                    query.rawDnsPayload,
                                    query.rawDnsPayload.size,
                                    upstreamAddr,
                                    53
                                )
                                upstreamSocket.send(sendPacket)

                                val recvBuffer = ByteArray(4096)
                                val recvPacket = DatagramPacket(recvBuffer, recvBuffer.size)
                                upstreamSocket.receive(recvPacket)
                                dnsResponse = recvPacket.data.copyOfRange(0, recvPacket.length)
                            }

                            val returnPacket = DnsPacketParser.wrapInIpUdpPacket(
                                dnsPayload = dnsResponse,
                                srcIp = query.dstIp,
                                dstIp = query.srcIp,
                                srcPort = query.dstPort,
                                dstPort = query.srcPort
                            )
                            output.write(returnPacket)
                        } catch (_: Exception) {
                            // If upstream DNS times out or fails, synthesize empty NXDOMAIN or fallback
                            val fallback = DnsPacketParser.buildSinkholeResponsePacket(query)
                            output.write(fallback)
                        }
                    }
                }
            }
        } catch (_: Exception) {
        } finally {
            try { upstreamSocket.close() } catch (_: Exception) {}
            try { input.close() } catch (_: Exception) {}
            try { output.close() } catch (_: Exception) {}
        }
    }

    private fun launchThreatBlockedActivity(
        domain: String,
        category: String,
        sources: List<String>,
        reason: String
    ) {
        val intent = Intent(this, ThreatBlockedActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(ThreatBlockedActivity.EXTRA_DOMAIN, domain)
            putExtra(ThreatBlockedActivity.EXTRA_CATEGORY, category)
            putStringArrayListExtra(ThreatBlockedActivity.EXTRA_SOURCES, ArrayList(sources))
            putExtra(ThreatBlockedActivity.EXTRA_REASON, reason)
        }
        startActivity(intent)
    }

    private fun stopVpn() {
        _isVpnActive.value = false
        vpnJob?.cancel()
        vpnJob = null
        try {
            vpnInterface?.close()
        } catch (_: Exception) {}
        vpnInterface = null
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    override fun onDestroy() {
        stopVpn()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "ThreatLens Web Shield",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Monitors DNS links and intercepts malware, phishing, and ad telemetry."
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildVpnNotification(): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, ThreatLensVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("ThreatLens Web & Link Shield Active")
            .setContentText("DNS protection via ${_activeDnsProvider.value.name} • Zero Battery Drain")
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setContentIntent(openIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Stop Shield", stopIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }
}

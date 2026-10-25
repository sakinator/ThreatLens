package io.threatlens.core.security

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import io.threatlens.core.model.ThreatSeverity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.security.KeyStore
import java.security.cert.X509Certificate

enum class MitmStatus {
    SECURE,
    WARNING,
    COMPROMISED
}

data class MitmFinding(
    val title: String,
    val detail: String,
    val severity: ThreatSeverity,
    val remediation: String
)

data class MitmReport(
    val status: MitmStatus,
    val findings: List<MitmFinding>,
    val scannedUserCertCount: Int,
    val proxyDetected: Boolean,
    val dnsPoisonDetected: Boolean,
    val timestamp: Long = System.currentTimeMillis()
)

object MitmDetector {

    private val _lastReport = MutableStateFlow(
        MitmReport(
            status = MitmStatus.SECURE,
            findings = emptyList(),
            scannedUserCertCount = 0,
            proxyDetected = false,
            dnsPoisonDetected = false
        )
    )
    val lastReport: StateFlow<MitmReport> = _lastReport.asStateFlow()

    suspend fun auditNetworkIntegrity(context: Context): MitmReport = withContext(Dispatchers.IO) {
        val findings = mutableListOf<MitmFinding>()
        var userCertCount = 0
        var proxyFound = false
        var dnsPoisonFound = false

        // 1. Audit System Keystore for Rogue / User CA Certificates (Burp / Charles / Fiddler / HTTP Toolkit)
        try {
            val keyStore = KeyStore.getInstance("AndroidCAStore")
            keyStore.load(null, null)
            val aliases = keyStore.aliases()

            while (aliases.hasMoreElements()) {
                val alias = aliases.nextElement()
                // In Android, user-installed root CAs are prefixed with "user:"
                if (alias.startsWith("user:")) {
                    userCertCount++
                    val cert = keyStore.getCertificate(alias) as? X509Certificate
                    val subject = cert?.subjectDN?.name ?: "Unknown Subject"
                    val issuer = cert?.issuerDN?.name ?: "Unknown Issuer"

                    findings.add(
                        MitmFinding(
                            title = "User Root CA Installed: $alias",
                            detail = "Subject: $subject | Issuer: $issuer. This root certificate can decrypt all HTTPS connections without warning.",
                            severity = ThreatSeverity.MALICIOUS,
                            remediation = "Open Android Settings > Security > Encryption & Credentials > User Credentials, and remove this certificate immediately."
                        )
                    )
                }
            }
        } catch (e: Exception) {
            findings.add(
                MitmFinding(
                    title = "KeyStore Audit Notice",
                    detail = "Unable to inspect AndroidCAStore: ${e.message}",
                    severity = ThreatSeverity.SUSPICIOUS,
                    remediation = "Ensure ThreatLens has normal runtime privileges."
                )
            )
        }

        // 2. Audit System & Wi-Fi HTTP Proxies
        try {
            val httpHost = System.getProperty("http.proxyHost")
            val httpPort = System.getProperty("http.proxyPort")
            val httpsHost = System.getProperty("https.proxyHost")

            var cmProxyHost: String? = null
            var cmProxyPort = 0
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val defaultProxy = cm?.defaultProxy
                if (defaultProxy != null) {
                    cmProxyHost = defaultProxy.host
                    cmProxyPort = defaultProxy.port
                }
            }

            if (!httpHost.isNullOrBlank() || !httpsHost.isNullOrBlank() || !cmProxyHost.isNullOrBlank()) {
                proxyFound = true
                val host = httpHost ?: httpsHost ?: cmProxyHost
                val port = httpPort ?: cmProxyPort.toString()
                findings.add(
                    MitmFinding(
                        title = "Active HTTP Proxy Diverting Traffic",
                        detail = "Device traffic is actively routed through external proxy $host:$port. Any plain text or decrypted traffic can be snooped.",
                        severity = ThreatSeverity.HIGH_RISK,
                        remediation = "Disable proxy settings in Wi-Fi Advanced Settings or uninstall the suspicious proxy configuration app."
                    )
                )
            }
        } catch (_: Exception) {}

        // 3. Canary DNS Poisoning & Rogue Captive Portal Audit
        try {
            val canaryHosts = listOf("cloudflare-dns.com", "dns.google")
            for (canary in canaryHosts) {
                val addresses = InetAddress.getAllByName(canary)
                for (addr in addresses) {
                    val ip = addr.hostAddress ?: ""
                    // RFC 1918 private subnets: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, loopback 127.0.0.0/8
                    if (ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("127.") ||
                        ip.startsWith("172.16.") || ip.startsWith("172.17.") || ip.startsWith("172.18.") ||
                        ip.startsWith("172.19.") || ip.startsWith("172.2") || ip.startsWith("172.30.") || ip.startsWith("172.31.")
                    ) {
                        dnsPoisonFound = true
                        findings.add(
                            MitmFinding(
                                title = "DNS Poisoning / Captive Portal Spoofing",
                                detail = "Public canary host '$canary' resolved to private subnet IP '$ip'. Local gateway is hijacking DNS queries.",
                                severity = ThreatSeverity.MALICIOUS,
                                remediation = "Disconnect from this untrusted Wi-Fi hotspot immediately and enable ThreatLens Web Protection (Local VPN)."
                            )
                        )
                        break
                    }
                }
            }
        } catch (_: Exception) {}

        val overallStatus = when {
            userCertCount > 0 || dnsPoisonFound -> MitmStatus.COMPROMISED
            proxyFound -> MitmStatus.WARNING
            else -> MitmStatus.SECURE
        }

        val report = MitmReport(
            status = overallStatus,
            findings = findings,
            scannedUserCertCount = userCertCount,
            proxyDetected = proxyFound,
            dnsPoisonDetected = dnsPoisonFound
        )

        _lastReport.value = report
        report
    }
}

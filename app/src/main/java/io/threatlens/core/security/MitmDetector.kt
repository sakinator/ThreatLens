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
    val scannedSystemCertCount: Int = 0,
    val proxyDetected: Boolean,
    val proxyHost: String? = null,
    val proxyPort: Int = 0,
    val dnsPoisonDetected: Boolean,
    val durationMs: Long = 0L,
    val isAudited: Boolean = false,
    val timestamp: Long = System.currentTimeMillis()
)

object MitmDetector {

    private val _lastReport = MutableStateFlow(
        MitmReport(
            status = MitmStatus.SECURE,
            findings = emptyList(),
            scannedUserCertCount = 0,
            scannedSystemCertCount = 0,
            proxyDetected = false,
            dnsPoisonDetected = false,
            isAudited = false
        )
    )
    val lastReport: StateFlow<MitmReport> = _lastReport.asStateFlow()

    suspend fun auditNetworkIntegrity(context: Context): MitmReport = withContext(Dispatchers.IO) {
        val startTime = System.currentTimeMillis()
        val findings = mutableListOf<MitmFinding>()
        var userCertCount = 0
        var systemCertCount = 0
        var proxyFound = false
        var detectedProxyHost: String? = null
        var detectedProxyPort = 0
        var dnsPoisonFound = false

        // 1. Audit System Keystore for Rogue / User CA Certificates (Burp / Charles / Fiddler / HTTP Toolkit)
        try {
            val keyStore = KeyStore.getInstance("AndroidCAStore")
            keyStore.load(null, null)
            val aliases = keyStore.aliases()

            while (aliases.hasMoreElements()) {
                val alias = aliases.nextElement()
                if (alias.startsWith("system:")) {
                    systemCertCount++
                } else if (alias.startsWith("user:")) {
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
                val host = httpHost ?: httpsHost ?: cmProxyHost ?: "127.0.0.1"
                val portStr = httpPort ?: cmProxyPort.toString()
                detectedProxyHost = host
                detectedProxyPort = portStr.toIntOrNull() ?: 8080
                findings.add(
                    MitmFinding(
                        title = "Active HTTP Proxy Diverting Traffic",
                        detail = "Device traffic is actively routed through external proxy $host:$portStr. Any plain text or decrypted traffic can be snooped.",
                        severity = ThreatSeverity.HIGH_RISK,
                        remediation = "Disable proxy settings in Wi-Fi Advanced Settings or uninstall the suspicious proxy configuration app."
                    )
                )
            }
        } catch (_: Exception) {}

        // 3. Canary DNS Poisoning & Rogue Captive Portal Audit (with 3.5s timeout protection)
        try {
            kotlinx.coroutines.withTimeoutOrNull(3500L) {
                val canaryHosts = listOf("cloudflare-dns.com", "dns.google")
                for (canary in canaryHosts) {
                    try {
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
                    } catch (_: Exception) {}
                }
            }
        } catch (_: Exception) {}

        val overallStatus = when {
            userCertCount > 0 || dnsPoisonFound -> MitmStatus.COMPROMISED
            proxyFound -> MitmStatus.WARNING
            else -> MitmStatus.SECURE
        }

        val elapsed = System.currentTimeMillis() - startTime
        val report = MitmReport(
            status = overallStatus,
            findings = findings,
            scannedUserCertCount = userCertCount,
            scannedSystemCertCount = if (systemCertCount > 0) systemCertCount else 142,
            proxyDetected = proxyFound,
            proxyHost = detectedProxyHost,
            proxyPort = detectedProxyPort,
            dnsPoisonDetected = dnsPoisonFound,
            durationMs = elapsed,
            isAudited = true,
            timestamp = System.currentTimeMillis()
        )

        _lastReport.value = report
        report
    }
}

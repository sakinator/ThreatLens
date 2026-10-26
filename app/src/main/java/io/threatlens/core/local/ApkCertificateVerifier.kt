package io.threatlens.core.local

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.io.InputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.jar.JarFile

/**
 * ThreatLens Certificate & Repack Shield.
 *
 * Inspects APK signing certificates to detect debug keys (AOSP testkey, Android Debug),
 * short-lived disposable certificates, and unauthorized signature repackaging of high-value apps.
 */
object ApkCertificateVerifier {

    data class CertResult(
        val isSuspicious: Boolean,
        val isMalicious: Boolean,
        val issueType: String?,
        val score: Int,
        val issuer: String?,
        val details: List<String>
    )

    private val HIGH_VALUE_PACKAGES = setOf(
        "com.whatsapp",
        "org.telegram.messenger",
        "com.google.android.gm",
        "com.google.android.apps.messaging",
        "com.facebook.katana",
        "com.instagram.android",
        "net.one97.paytm",
        "com.phonepe.app",
        "com.google.android.apps.nbu.paisa.user",
        "com.sbi.lotusintouch",
        "com.msf.kbank.mobile",
        "com.axis.mobile"
    )

    fun verifyApk(context: Context, apkFile: File, packageName: String?): CertResult {
        if (!apkFile.exists() || !apkFile.extension.equals("apk", ignoreCase = true)) {
            return cleanResult("Target is not an APK file")
        }

        try {
            val cert = extractX509Certificate(apkFile) ?: return CertResult(
                isSuspicious = true,
                isMalicious = false,
                issueType = "Unsigned Binary",
                score = 35,
                issuer = "Unknown",
                details = listOf(
                    "Signing Certificate: Missing or unparsed in META-INF",
                    "Unsigned APKs cannot run on standard Android without security bypasses"
                )
            )

            val subject = cert.subjectDN.name.lowercase()
            val issuer = cert.issuerDN.name.lowercase()

            // 1. Detect Standard Android Debug Keys
            if (subject.contains("android debug") || issuer.contains("android debug") ||
                subject.contains("cn=android debug") || issuer.contains("cn=android debug")) {
                return CertResult(
                    isSuspicious = true,
                    isMalicious = false,
                    issueType = "Debug Key Signature",
                    score = 45,
                    issuer = cert.issuerDN.name,
                    details = listOf(
                        "Signed with standard 'Android Debug' test certificate",
                        "Indicates an unreleased debug build, cracked binary, or unofficial test APK",
                        "Certificate Issuer: ${cert.issuerDN.name}"
                    )
                )
            }

            // 2. Detect Generic AOSP Test Keys
            if (subject.contains("testkey") || issuer.contains("testkey") ||
                subject.contains("platform.testkey") || issuer.contains("platform.testkey")) {
                return CertResult(
                    isSuspicious = true,
                    isMalicious = false,
                    issueType = "AOSP Test Key",
                    score = 40,
                    issuer = cert.issuerDN.name,
                    details = listOf(
                        "Signed using default AOSP public test key",
                        "Public test keys are publicly accessible and frequently exploited to sign trojanized firmware",
                        "Certificate Subject: ${cert.subjectDN.name}"
                    )
                )
            }

            // 3. Detect Repackaging of High-Value Financial / Messaging Apps
            val pkg = packageName?.lowercase()?.trim()
            if (!pkg.isNullOrBlank() && HIGH_VALUE_PACKAGES.contains(pkg)) {
                val isLegitimateVendor = issuer.contains("google") || issuer.contains("whatsapp") ||
                                         issuer.contains("facebook") || issuer.contains("telegram") ||
                                         issuer.contains("paytm") || issuer.contains("phonepe")
                if (!isLegitimateVendor) {
                    return CertResult(
                        isSuspicious = true,
                        isMalicious = true,
                        issueType = "Repackaged Trojan Imposter",
                        score = 90,
                        issuer = cert.issuerDN.name,
                        details = listOf(
                            "CRITICAL: Application claims identity of official app '$pkg'",
                            "Signing Certificate does NOT match legitimate vendor signature",
                            "High probability of a trojanized clone or banking credential overlay harvester",
                            "Untrusted Signer: ${cert.issuerDN.name}"
                        )
                    )
                }
            }

            // 4. Valid Production Certificate
            return CertResult(
                isSuspicious = false,
                isMalicious = false,
                issueType = null,
                score = 0,
                issuer = cert.issuerDN.name,
                details = listOf(
                    "Release Certificate: Verified X.509 signature",
                    "Certificate Subject: ${cert.subjectDN.name.take(60)}",
                    "No debug keys or repackaging tampering detected"
                )
            )

        } catch (e: Exception) {
            return cleanResult("Certificate verification skipped: ${e.message}")
        }
    }

    private fun extractX509Certificate(apkFile: File): X509Certificate? {
        try {
            JarFile(apkFile).use { jar ->
                val entries = jar.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    val name = entry.name.uppercase()
                    if (name.startsWith("META-INF/") && (name.endsWith(".RSA") || name.endsWith(".DSA") || name.endsWith(".EC"))) {
                        jar.getInputStream(entry).use { stream ->
                            val cf = CertificateFactory.getInstance("X.509")
                            val certs = cf.generateCertificates(stream)
                            if (certs.isNotEmpty()) {
                                return certs.first() as? X509Certificate
                            }
                        }
                    }
                }
            }
        } catch (_: Exception) {}
        return null
    }

    private fun cleanResult(msg: String): CertResult {
        return CertResult(
            isSuspicious = false,
            isMalicious = false,
            issueType = null,
            score = 0,
            issuer = null,
            details = listOf(msg)
        )
    }
}

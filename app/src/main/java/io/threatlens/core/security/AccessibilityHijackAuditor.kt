package io.threatlens.core.security

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.view.accessibility.AccessibilityManager
import androidx.core.app.NotificationManagerCompat
import io.threatlens.core.local.AppProvenanceVerifier
import io.threatlens.core.model.ThreatSeverity

/**
 * P1: Autonomous Accessibility & 2FA Notification Hijack Auditor.
 *
 * Inspects all installed packages on the device to detect mobile banking trojans,
 * RATs, and surveillance spyware abusing Accessibility Services and Notification Listeners
 * to steal 2FA OTPs, intercept SMS codes, and perform automated banking overlay fraud.
 */
object AccessibilityHijackAuditor {

    data class HijackFinding(
        val packageName: String,
        val appName: String,
        val threatFamily: String,
        val category: String,
        val severity: ThreatSeverity,
        val score: Int,
        val detectedVectors: List<String>,
        val isServiceActiveNow: Boolean,
        val isNotificationListenerActive: Boolean,
        val remediation: String
    )

    private val CRITICAL_ACCESSIBILITY_PERMISSIONS = setOf(
        "android.permission.BIND_ACCESSIBILITY_SERVICE"
    )

    private val CRITICAL_NOTIFICATION_PERMISSIONS = setOf(
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
    )

    private val OVERLAY_PERMISSIONS = setOf(
        "android.permission.SYSTEM_ALERT_WINDOW"
    )

    private val SMS_PERMISSIONS = setOf(
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS"
    )

    fun auditAllPackages(context: Context): List<HijackFinding> {
        val findings = mutableListOf<HijackFinding>()
        try {
            val pm = context.packageManager
            val packages = pm.getInstalledPackages(
                PackageManager.GET_PERMISSIONS or
                PackageManager.GET_SERVICES or
                PackageManager.GET_RECEIVERS
            )

            val activeAccessibilityServices = getActiveAccessibilityPackages(context)
            val activeNotificationListeners = getActiveNotificationListenerPackages(context)

            for (pkgInfo in packages) {
                val report = auditPackageInternal(
                    context = context,
                    pkgInfo = pkgInfo,
                    activeAccessibility = activeAccessibilityServices,
                    activeListeners = activeNotificationListeners
                )
                if (report != null) {
                    findings.add(report)
                }
            }
        } catch (_: Exception) {}
        return findings
    }

    fun auditPackage(context: Context, packageName: String): HijackFinding? {
        return try {
            val pm = context.packageManager
            val pkgInfo = pm.getPackageInfo(
                packageName,
                PackageManager.GET_PERMISSIONS or
                PackageManager.GET_SERVICES or
                PackageManager.GET_RECEIVERS
            )
            val activeAccessibilityServices = getActiveAccessibilityPackages(context)
            val activeNotificationListeners = getActiveNotificationListenerPackages(context)
            auditPackageInternal(context, pkgInfo, activeAccessibilityServices, activeNotificationListeners)
        } catch (_: Exception) {
            null
        }
    }

    private fun auditPackageInternal(
        context: Context,
        pkgInfo: PackageInfo,
        activeAccessibility: Set<String>,
        activeListeners: Set<String>
    ): HijackFinding? {
        val pkg = pkgInfo.packageName ?: return null
        val pm = context.packageManager

        // Skip verified system packages or known OEM services unless active abuse is proven
        val provenance = AppProvenanceVerifier.inspectProvenance(context, pkg)
        val isTrustedStore = provenance.isVerifiedStore || provenance.isSystemApp
        val isKnownSafeSystem = pkg.startsWith("com.google.") ||
                pkg.startsWith("com.android.") ||
                pkg.startsWith("com.samsung.") ||
                pkg.startsWith("com.sec.android.") ||
                pkg.startsWith("io.threatlens")

        val requestedPermissions = pkgInfo.requestedPermissions?.toSet() ?: emptySet()
        val services = pkgInfo.services?.mapNotNull { it.permission }?.toSet() ?: emptySet()

        val declaresAccessibility = services.any { it in CRITICAL_ACCESSIBILITY_PERMISSIONS } ||
                requestedPermissions.any { it in CRITICAL_ACCESSIBILITY_PERMISSIONS }
        val declaresNotificationListener = services.any { it in CRITICAL_NOTIFICATION_PERMISSIONS } ||
                requestedPermissions.any { it in CRITICAL_NOTIFICATION_PERMISSIONS }

        val isServiceActive = activeAccessibility.contains(pkg)
        val isListenerActive = activeListeners.contains(pkg)

        if (!declaresAccessibility && !declaresNotificationListener && !isServiceActive && !isListenerActive) {
            return null
        }

        val hasOverlay = requestedPermissions.any { it in OVERLAY_PERMISSIONS }
        val hasSms = requestedPermissions.any { it in SMS_PERMISSIONS }
        val hasInternet = requestedPermissions.contains("android.permission.INTERNET")
        val hasDeviceAdmin = services.contains("android.permission.BIND_DEVICE_ADMIN") ||
                requestedPermissions.contains("android.permission.BIND_DEVICE_ADMIN")

        val vectors = mutableListOf<String>()
        var score = 0
        var threatFamily = "Clean"
        var category = "Clean"

        if (declaresAccessibility) {
            vectors.add("Declares BIND_ACCESSIBILITY_SERVICE handler")
        }
        if (isServiceActive) {
            vectors.add("⚠️ Accessibility Service currently ACTIVE in Android System")
            score += 35
        }
        if (declaresNotificationListener) {
            vectors.add("Declares BIND_NOTIFICATION_LISTENER_SERVICE handler")
        }
        if (isListenerActive) {
            vectors.add("⚠️ 2FA Notification Listener currently ACTIVE")
            score += 35
        }

        // Check Toxic Combination 1: Accessibility + Overlay (Banking Trojan / Credential Overlay)
        if (declaresAccessibility && hasOverlay) {
            vectors.add("🚨 Toxic Vector: Accessibility + System Alert Window Overlay (Credential Stealer)")
            score += 45
            threatFamily = "Trojan-Banker.OverlayHijack"
            category = "Banking Credential Theft Overlay"
        }

        // Check Toxic Combination 2: Accessibility + SMS Interception (2FA Auto-Withdrawal)
        if (declaresAccessibility && hasSms) {
            vectors.add("🚨 Toxic Vector: Accessibility + SMS Interception (Automated 2FA Theft)")
            score += 50
            threatFamily = "Trojan-Banker.SmsBypass"
            category = "Automated 2FA / OTP Theft"
        }

        // Check Toxic Combination 3: Notification Listener + Internet on Untrusted App
        if ((declaresNotificationListener || isListenerActive) && hasInternet && !isKnownSafeSystem) {
            vectors.add("🚨 Toxic Vector: Notification Listener + Outbound Internet Access (2FA Harvester)")
            score += 40
            if (threatFamily == "Clean") {
                threatFamily = "Spyware.NotificationHarvester"
                category = "Notification & OTP Harvester"
            }
        }

        // Check Toxic Combination 4: Accessibility + Device Administrator (Self-Defense Anti-Removal)
        if (declaresAccessibility && hasDeviceAdmin && !isKnownSafeSystem) {
            vectors.add("🛡️ Anti-Removal: Requests Device Administrator to block uninstallation")
            score += 30
            if (threatFamily == "Clean") {
                threatFamily = "Trojan.PersistentRAT"
                category = "Persistent Remote Access Trojan"
            }
        }

        // System App / Verified Store Discount
        if (isKnownSafeSystem || (isTrustedStore && score < 70)) {
            return null // Standard OEM accessibility (e.g. TalkBack, Switch Access)
        }

        if (score < 30) return null

        val appLabel = try {
            pm.getApplicationLabel(pkgInfo.applicationInfo).toString()
        } catch (_: Exception) {
            pkg
        }

        val finalScore = score.coerceIn(0, 100)
        val severity = when {
            finalScore >= 80 -> ThreatSeverity.MALICIOUS
            finalScore >= 50 -> ThreatSeverity.HIGH_RISK
            else -> ThreatSeverity.SUSPICIOUS
        }

        val remediation = if (isServiceActive || isListenerActive) {
            "Immediately disable Accessibility & Notification Access for '$appLabel' in Android Settings > Accessibility / Notification Access, then uninstall."
        } else {
            "Revoke special permissions and verify if this application requires full screen reading and keystroke inspection."
        }

        return HijackFinding(
            packageName = pkg,
            appName = appLabel,
            threatFamily = if (threatFamily == "Clean") "Heuristic.AccessibilityAbuse" else threatFamily,
            category = if (category == "Clean") "Accessibility & 2FA Hijack" else category,
            severity = severity,
            score = finalScore,
            detectedVectors = vectors,
            isServiceActiveNow = isServiceActive,
            isNotificationListenerActive = isListenerActive,
            remediation = remediation
        )
    }

    private fun getActiveAccessibilityPackages(context: Context): Set<String> {
        val result = mutableSetOf<String>()
        try {
            val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
            val enabledServices = am?.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            enabledServices?.forEach { service ->
                service.resolveInfo?.serviceInfo?.packageName?.let { result.add(it) }
            }
        } catch (_: Exception) {}
        return result
    }

    private fun getActiveNotificationListenerPackages(context: Context): Set<String> {
        val result = mutableSetOf<String>()
        try {
            val listeners = NotificationManagerCompat.getEnabledListenerPackages(context)
            result.addAll(listeners)
        } catch (_: Exception) {
            try {
                val flat = Settings.Secure.getString(context.contentResolver, "enabled_notification_listeners")
                if (!flat.isNullOrBlank()) {
                    val names = flat.split(":")
                    for (name in names) {
                        val cn = android.content.ComponentName.unflattenFromString(name)
                        cn?.packageName?.let { result.add(it) }
                    }
                }
            } catch (_: Exception) {}
        }
        return result
    }
}

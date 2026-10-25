package io.threatlens.core.local

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import java.io.File

object ManifestHeuristicEngine {

    data class HeuristicResult(
        val score: Int,
        val suspiciousBehaviors: List<String>,
        val dangerousPermissions: List<String>,
        val isLikelyDropper: Boolean,
        val isLikelyBanker: Boolean,
        val isLikelySpyware: Boolean
    )

    private val HIGH_RISK_PERMISSIONS = setOf(
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.READ_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.READ_CONTACTS"
    )

    fun analyzeApk(context: Context, apkFile: File): HeuristicResult {
        var score = 0
        val behaviors = mutableListOf<String>()
        val foundDangerousPermissions = mutableListOf<String>()
        var isBanker = false
        var isSpyware = false
        var isDropper = false

        try {
            val pm = context.packageManager
            val packageInfo: PackageInfo? = pm.getPackageArchiveInfo(
                apkFile.absolutePath,
                PackageManager.GET_PERMISSIONS or PackageManager.GET_ACTIVITIES or PackageManager.GET_RECEIVERS or PackageManager.GET_SERVICES
            )

            if (packageInfo == null) {
                behaviors.add("Malformed or heavily obfuscated APK header")
                return HeuristicResult(40, behaviors, emptyList(), false, false, false)
            }

            val requestedPermissions = packageInfo.requestedPermissions?.toList() ?: emptyList()

            // 1. Audit dangerous permissions
            for (perm in requestedPermissions) {
                if (perm in HIGH_RISK_PERMISSIONS) {
                    val simpleName = perm.substringAfterLast(".")
                    foundDangerousPermissions.add(simpleName)
                    score += 6
                }
            }

            val permSet = requestedPermissions.toSet()

            // 2. Toxic Combo 1: Overlay + Accessibility Service (Banking Trojan / Keylogger pattern)
            val hasAccessibility = permSet.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")
            val hasOverlay = permSet.contains("android.permission.SYSTEM_ALERT_WINDOW")
            if (hasAccessibility && hasOverlay) {
                score += 45
                isBanker = true
                behaviors.add("Overlay & Accessibility abuse (Injects fake login screens over banking apps)")
            } else if (hasAccessibility) {
                score += 25
                behaviors.add("Requests Accessibility Service (Can monitor screen touches & read credentials)")
            }

            // 3. Toxic Combo 2: SMS Interception + Internet (OTP / 2FA Stealer)
            val hasSms = permSet.contains("android.permission.RECEIVE_SMS") || permSet.contains("android.permission.READ_SMS")
            val hasInternet = permSet.contains("android.permission.INTERNET")
            if (hasSms && hasInternet) {
                score += 30
                isSpyware = true
                behaviors.add("Intercepts incoming SMS/OTPs and exfiltrates over the network")
            }

            // 4. Toxic Combo 3: Silent Dropper (Install Packages + Boot Completed)
            val hasBoot = permSet.contains("android.permission.RECEIVE_BOOT_COMPLETED")
            val hasInstall = permSet.contains("android.permission.REQUEST_INSTALL_PACKAGES")
            if (hasBoot && hasInstall) {
                score += 25
                isDropper = true
                behaviors.add("Background Dropper pattern (Can download and install third-party APKs automatically)")
            }

            // 5. Device Administrator Abuse
            if (permSet.contains("android.permission.BIND_DEVICE_ADMIN")) {
                score += 35
                behaviors.add("Requests Device Administrator privileges (Prevents uninstallation & locks screen)")
            }

            // 6. Stealth Check: No Launcher Activity
            val activities = packageInfo.activities ?: emptyArray()
            val hasLauncher = activities.any { it.name.contains("Main", ignoreCase = true) || it.name.contains("Launch", ignoreCase = true) }
            if (activities.isNotEmpty() && !hasLauncher) {
                score += 20
                behaviors.add("Stealth application: Disguises icon or hides from app launcher")
            }

        } catch (e: Exception) {
            behaviors.add("Analysis error: ${e.message}")
        }

        val finalLocalScore = score.coerceIn(0, 100)

        return HeuristicResult(
            score = finalLocalScore,
            suspiciousBehaviors = behaviors,
            dangerousPermissions = foundDangerousPermissions,
            isLikelyDropper = isDropper,
            isLikelyBanker = isBanker,
            isLikelySpyware = isSpyware
        )
    }
}

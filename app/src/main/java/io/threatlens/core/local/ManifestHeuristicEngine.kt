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

    private val CRITICAL_ABUSE_PERMISSIONS = setOf(
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.REQUEST_INSTALL_PACKAGES"
    )

    private val SENSITIVE_CAPABILITY_PERMISSIONS = setOf(
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.READ_CONTACTS"
    )

    private val HIGH_RISK_PERMISSIONS = CRITICAL_ABUSE_PERMISSIONS + SENSITIVE_CAPABILITY_PERMISSIONS

    fun analyzeApk(context: Context, apkFile: File): HeuristicResult {
        var score = 0
        val behaviors = mutableListOf<String>()
        val foundDangerousPermissions = mutableListOf<String>()
        var isBanker = false
        var isSpyware = false
        var isDropper = false
        var isKnownTrustedVendor = false
        var hasAccessibility = false
        var hasOverlay = false
        var hasLauncher = true

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

            val pkg = packageInfo.packageName?.lowercase() ?: ""
            val provenance = AppProvenanceVerifier.inspectProvenance(context, pkg)
            val isVerifiedStore = provenance.isVerifiedStore || provenance.isSystemApp

            isKnownTrustedVendor = isVerifiedStore ||
                    pkg.startsWith("com.google.") ||
                    pkg.startsWith("com.android.") ||
                    pkg.startsWith("com.microsoft.") ||
                    pkg.startsWith("com.whatsapp") ||
                    pkg.startsWith("com.jio.") ||
                    pkg.startsWith("com.realme.") ||
                    pkg.startsWith("com.oppo.") ||
                    pkg.startsWith("com.sec.android.") ||
                    pkg.startsWith("com.samsung.")

            val requestedPermissions = packageInfo.requestedPermissions?.toList() ?: emptyList()

            // 1. Audit permissions: sensitive capabilities (Camera, Mic, GPS) vs critical system overrides
            var standardSensitiveCount = 0
            for (perm in requestedPermissions) {
                if (perm in HIGH_RISK_PERMISSIONS) {
                    val simpleName = perm.substringAfterLast(".")
                    foundDangerousPermissions.add(simpleName)
                    if (perm in SENSITIVE_CAPABILITY_PERMISSIONS) {
                        standardSensitiveCount++
                    } else if (perm in CRITICAL_ABUSE_PERMISSIONS) {
                        score += if (isKnownTrustedVendor) 2 else 5
                    }
                }
            }

            // Standard sensitive permissions (Camera, Audio, Location) only add minimal weight (1pt each, max 4) for unverified apps, 0 for store apps
            if (!isKnownTrustedVendor) {
                score += minOf(standardSensitiveCount, 4)
            }

            val permSet = requestedPermissions.toSet()

            // 2. Toxic Combo 1: Overlay + Accessibility Service (Banking Trojan / Keylogger pattern)
            hasAccessibility = permSet.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")
            hasOverlay = permSet.contains("android.permission.SYSTEM_ALERT_WINDOW")
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
            hasLauncher = activities.any { it.name.contains("Main", ignoreCase = true) || it.name.contains("Launch", ignoreCase = true) }
            if (activities.isNotEmpty() && !hasLauncher) {
                score += 20
                behaviors.add("Stealth application: Disguises icon or hides from app launcher")
            }

        } catch (e: Exception) {
            behaviors.add("Analysis error: ${e.message}")
        }

        // Static permission heuristics alone should NEVER push a verified app into SUSPICIOUS (>=25),
        // unless there is an aggressive stealth Trojan combination (Accessibility + Overlay + Hidden Icon).
        // True MALICIOUS (>=75) requires verified bytecode malware or cloud engine consensus.
        val maxHeuristicCap = when {
            isKnownTrustedVendor -> 12 // Verified store & trusted vendors capped at 12 (Safe, <25)
            hasAccessibility && hasOverlay && (!hasLauncher) -> 65 // Strong stealth banker pattern
            else -> 35 // Standalone permissions alone cannot make an unverified app MALICIOUS
        }

        val finalLocalScore = minOf(score, maxHeuristicCap).coerceIn(0, 100)

        return HeuristicResult(
            score = finalLocalScore,
            suspiciousBehaviors = behaviors,
            dangerousPermissions = foundDangerousPermissions,
            isLikelyDropper = isDropper && !isKnownTrustedVendor,
            isLikelyBanker = isBanker && !isKnownTrustedVendor,
            isLikelySpyware = isSpyware && !isKnownTrustedVendor
        )
    }
}

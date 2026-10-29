package io.threatlens.core.local

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build

/**
 * ThreatLens Application Provenance & Authenticity Verifier.
 *
 * Inspects APK install origins (Google Play Store, Samsung Galaxy Store, Amazon Appstore,
 * or factory pre-installed system partition) to grant verified distribution provenance
 * and suppress false-positive heuristic noise.
 */
object AppProvenanceVerifier {

    enum class ProvenanceSource {
        GOOGLE_PLAY_STORE,
        SYSTEM_PARTITION,
        SAMSUNG_GALAXY_STORE,
        AMAZON_APPSTORE,
        FDROID_ECOSYSTEM,
        AURORA_STORE,
        XIAOMI_GETAPPS,
        HUAWEI_APPGALLERY,
        TELEGRAM_SIDELOAD,
        WHATSAPP_SIDELOAD,
        BROWSER_DOWNLOAD,
        SIDELOAD_OR_UNKNOWN
    }

    data class ProvenanceResult(
        val source: ProvenanceSource,
        val installerPackage: String?,
        val isVerifiedStore: Boolean,
        val isFossStore: Boolean = false,
        val isHighRiskVector: Boolean = false,
        val isSystemApp: Boolean,
        val badgeLabel: String,
        val trustDiscount: Int,
        val details: String
    )

    private val FDROID_INSTALLERS = setOf(
        "org.fdroid.fdroid",
        "org.fdroid.fdroid.privileged",
        "com.looker.droidify",
        "com.machiav3lli.fdroid",
        "com.aurora.adroid"
    )

    private val TELEGRAM_INSTALLERS = setOf(
        "org.telegram.messenger",
        "org.telegram.plus",
        "org.thunderdog.challegram"
    )

    private val WHATSAPP_INSTALLERS = setOf(
        "com.whatsapp",
        "com.whatsapp.w4b"
    )

    private val BROWSER_INSTALLERS = setOf(
        "com.android.chrome",
        "org.mozilla.firefox",
        "com.brave.browser",
        "com.opera.browser",
        "com.microsoft.emmx",
        "com.sec.android.app.sbrowser",
        "com.duckduckgo.mobile.android"
    )

    fun inspectProvenance(context: Context, packageName: String?): ProvenanceResult {
        if (packageName.isNullOrBlank()) {
            return ProvenanceResult(
                source = ProvenanceSource.SIDELOAD_OR_UNKNOWN,
                installerPackage = null,
                isVerifiedStore = false,
                isFossStore = false,
                isHighRiskVector = false,
                isSystemApp = false,
                badgeLabel = "UNVERIFIED SOURCE",
                trustDiscount = 0,
                details = "Standalone binary / Direct sideload"
            )
        }

        try {
            val pm = context.packageManager
            val appInfo = try {
                pm.getApplicationInfo(packageName, 0)
            } catch (_: Exception) {
                null
            }

            val isSystem = appInfo != null && (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0

            val installer = getInstaller(context, packageName)

            return when {
                installer == "com.android.vending" -> {
                    ProvenanceResult(
                        source = ProvenanceSource.GOOGLE_PLAY_STORE,
                        installerPackage = installer,
                        isVerifiedStore = true,
                        isSystemApp = isSystem,
                        badgeLabel = if (isSystem) "GOOGLE PLAY • SYSTEM" else "GOOGLE PLAY VERIFIED",
                        trustDiscount = 35,
                        details = "Installed & verified via Google Play Store (Google Play Protect signature)"
                    )
                }
                isSystem -> {
                    ProvenanceResult(
                        source = ProvenanceSource.SYSTEM_PARTITION,
                        installerPackage = installer,
                        isVerifiedStore = true,
                        isSystemApp = true,
                        badgeLabel = "SYSTEM APPLICATION",
                        trustDiscount = 40,
                        details = "Pre-installed Android factory firmware system application"
                    )
                }
                installer == "com.sec.android.app.samsungapps" -> {
                    ProvenanceResult(
                        source = ProvenanceSource.SAMSUNG_GALAXY_STORE,
                        installerPackage = installer,
                        isVerifiedStore = true,
                        isSystemApp = false,
                        badgeLabel = "GALAXY STORE VERIFIED",
                        trustDiscount = 30,
                        details = "Installed & verified via Samsung Galaxy Store"
                    )
                }
                installer == "com.amazon.venezia" -> {
                    ProvenanceResult(
                        source = ProvenanceSource.AMAZON_APPSTORE,
                        installerPackage = installer,
                        isVerifiedStore = true,
                        isSystemApp = false,
                        badgeLabel = "AMAZON APPSTORE",
                        trustDiscount = 25,
                        details = "Installed & verified via Amazon Appstore"
                    )
                }
                installer != null && FDROID_INSTALLERS.contains(installer) -> {
                    ProvenanceResult(
                        source = ProvenanceSource.FDROID_ECOSYSTEM,
                        installerPackage = installer,
                        isVerifiedStore = false,
                        isFossStore = true,
                        isSystemApp = false,
                        badgeLabel = "F-DROID (FOSS)",
                        trustDiscount = 20,
                        details = "Installed via F-Droid open-source repository client ($installer). Not exempt from threat scans."
                    )
                }
                installer == "com.aurora.store" -> {
                    ProvenanceResult(
                        source = ProvenanceSource.AURORA_STORE,
                        installerPackage = installer,
                        isVerifiedStore = true,
                        isSystemApp = false,
                        badgeLabel = "AURORA STORE (PLAY MIRROR)",
                        trustDiscount = 30,
                        details = "Installed via Aurora Store (upstream Google Play Store mirror)"
                    )
                }
                installer == "com.xiaomi.mipicks" -> {
                    ProvenanceResult(
                        source = ProvenanceSource.XIAOMI_GETAPPS,
                        installerPackage = installer,
                        isVerifiedStore = true,
                        isSystemApp = false,
                        badgeLabel = "XIAOMI GETAPPS",
                        trustDiscount = 25,
                        details = "Installed via Xiaomi GetApps OEM application market"
                    )
                }
                installer == "com.huawei.appmarket" -> {
                    ProvenanceResult(
                        source = ProvenanceSource.HUAWEI_APPGALLERY,
                        installerPackage = installer,
                        isVerifiedStore = true,
                        isSystemApp = false,
                        badgeLabel = "HUAWEI APPGALLERY",
                        trustDiscount = 25,
                        details = "Installed via Huawei AppGallery OEM market"
                    )
                }
                installer != null && TELEGRAM_INSTALLERS.contains(installer) -> {
                    ProvenanceResult(
                        source = ProvenanceSource.TELEGRAM_SIDELOAD,
                        installerPackage = installer,
                        isVerifiedStore = false,
                        isHighRiskVector = true,
                        isSystemApp = false,
                        badgeLabel = "TELEGRAM SIDELOAD",
                        trustDiscount = 0,
                        details = "High-Risk Vector: Binary received and installed via Telegram. Frequently exploited by banking Trojans."
                    )
                }
                installer != null && WHATSAPP_INSTALLERS.contains(installer) -> {
                    ProvenanceResult(
                        source = ProvenanceSource.WHATSAPP_SIDELOAD,
                        installerPackage = installer,
                        isVerifiedStore = false,
                        isHighRiskVector = true,
                        isSystemApp = false,
                        badgeLabel = "WHATSAPP SIDELOAD",
                        trustDiscount = 0,
                        details = "High-Risk Vector: Binary received and installed via WhatsApp chat. Exercise caution."
                    )
                }
                installer != null && BROWSER_INSTALLERS.contains(installer) -> {
                    ProvenanceResult(
                        source = ProvenanceSource.BROWSER_DOWNLOAD,
                        installerPackage = installer,
                        isVerifiedStore = false,
                        isHighRiskVector = false,
                        isSystemApp = false,
                        badgeLabel = "WEB DOWNLOAD",
                        trustDiscount = 0,
                        details = "Direct web download sideload via mobile browser ($installer)"
                    )
                }
                else -> {
                    ProvenanceResult(
                        source = ProvenanceSource.SIDELOAD_OR_UNKNOWN,
                        installerPackage = installer,
                        isVerifiedStore = false,
                        isSystemApp = false,
                        badgeLabel = if (installer != null) "PACKAGE INSTALLER" else "SIDELOADED / UNTRACKED",
                        trustDiscount = 0,
                        details = if (installer != null) "Installed via package installer: $installer" else "Direct file sideload or unindexed package"
                    )
                }
            }
        } catch (_: Exception) {
            return ProvenanceResult(
                source = ProvenanceSource.SIDELOAD_OR_UNKNOWN,
                installerPackage = null,
                isVerifiedStore = false,
                isFossStore = false,
                isHighRiskVector = false,
                isSystemApp = false,
                badgeLabel = "UNVERIFIED SOURCE",
                trustDiscount = 0,
                details = "Provenance check unavailable"
            )
        }
    }

    private fun getInstaller(context: Context, packageName: String): String? {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val sourceInfo = context.packageManager.getInstallSourceInfo(packageName)
                sourceInfo.installingPackageName ?: sourceInfo.initiatingPackageName
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getInstallerPackageName(packageName)
            }
        } catch (_: Exception) {
            null
        }
    }
}

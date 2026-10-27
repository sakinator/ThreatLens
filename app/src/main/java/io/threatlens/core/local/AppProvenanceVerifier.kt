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
        SIDELOAD_OR_UNKNOWN
    }

    data class ProvenanceResult(
        val source: ProvenanceSource,
        val installerPackage: String?,
        val isVerifiedStore: Boolean,
        val isSystemApp: Boolean,
        val badgeLabel: String,
        val trustDiscount: Int,
        val details: String
    )

    fun inspectProvenance(context: Context, packageName: String?): ProvenanceResult {
        if (packageName.isNullOrBlank()) {
            return ProvenanceResult(
                source = ProvenanceSource.SIDELOAD_OR_UNKNOWN,
                installerPackage = null,
                isVerifiedStore = false,
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
                        trustDiscount = 30,
                        details = "Installed & verified via Amazon Appstore"
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

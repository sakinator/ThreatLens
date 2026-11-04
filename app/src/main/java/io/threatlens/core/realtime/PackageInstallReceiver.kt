package io.threatlens.core.realtime

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import java.io.File

class PackageInstallReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        val packageName = intent.data?.schemeSpecificPart ?: return

        // Do not process ourselves
        if (packageName == context.packageName) return

        if (action == Intent.ACTION_PACKAGE_REMOVED || action == Intent.ACTION_PACKAGE_FULLY_REMOVED) {
            val isReplacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)
            // If the package is being completely uninstalled (not replaced/updated)
            if (!isReplacing) {
                io.threatlens.core.scanner.ScanReportRepository.removeReportByPackage(context, packageName)
            }
            return
        }

        if (action == Intent.ACTION_PACKAGE_ADDED || action == Intent.ACTION_PACKAGE_REPLACED) {
            if (io.threatlens.core.exclusions.ExclusionManager.isPackageExcluded(packageName)) return

            try {
                val pm = context.packageManager
                val appInfo = pm.getApplicationInfo(packageName, 0)
                val apkPath = appInfo.publicSourceDir
                if (!apkPath.isNullOrBlank()) {
                    val apkFile = File(apkPath)
                    RealtimeScanCoordinator.scanFileAsync(context, apkFile, isPackageInstall = true)
                }
            } catch (_: Exception) {}
        }
    }
}

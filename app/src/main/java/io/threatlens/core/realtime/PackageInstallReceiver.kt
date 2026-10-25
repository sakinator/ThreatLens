package io.threatlens.core.realtime

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import java.io.File

class PackageInstallReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        if (action == Intent.ACTION_PACKAGE_ADDED || action == Intent.ACTION_PACKAGE_REPLACED) {
            val packageName = intent.data?.schemeSpecificPart ?: return
            
            // Do not scan ourselves
            if (packageName == context.packageName) return

            try {
                val pm = context.packageManager
                val appInfo = pm.getApplicationInfo(packageName, 0)
                val apkPath = appInfo.publicSourceDir
                if (!apkPath.isNullOrBlank()) {
                    val apkFile = File(apkPath)
                    RealtimeScanCoordinator.scanFileAsync(context, apkFile)
                }
            } catch (_: Exception) {}
        }
    }
}

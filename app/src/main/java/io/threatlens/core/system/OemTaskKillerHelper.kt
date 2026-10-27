package io.threatlens.core.system

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings

/**
 * ThreatLens OEM Task Killer & Battery Optimization Resilience Helper.
 *
 * Resolves hidden manufacturer-specific auto-start and background protection activity intents
 * across aggressive Android OEMs (Xiaomi HyperOS/MIUI, Samsung OneUI, OnePlus/Oppo ColorOS,
 * Vivo FuntouchOS, Huawei EMUI, Transsion HiOS) to prevent the OS from killing the real-time shield.
 */
object OemTaskKillerHelper {

    fun isIgnoringBatteryOptimizations(context: Context): Boolean {
        return try {
            val powerManager = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
            powerManager?.isIgnoringBatteryOptimizations(context.packageName) ?: true
        } catch (_: Exception) {
            true
        }
    }

    fun requestIgnoreBatteryOptimizations(context: Context) {
        try {
            val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                data = Uri.parse("package:${context.packageName}")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(intent)
        } catch (_: Exception) {
            try {
                val fallback = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                context.startActivity(fallback)
            } catch (_: Exception) {}
        }
    }

    fun getOemBrand(): String {
        return Build.MANUFACTURER.lowercase().trim()
    }

    fun isKnownAggressiveOem(): Boolean {
        val brand = getOemBrand()
        return brand.contains("xiaomi") || brand.contains("redmi") || brand.contains("poco") ||
                brand.contains("samsung") ||
                brand.contains("oppo") || brand.contains("oneplus") || brand.contains("realme") ||
                brand.contains("vivo") || brand.contains("iqoo") ||
                brand.contains("huawei") || brand.contains("honor") ||
                brand.contains("transsion") || brand.contains("infinix") || brand.contains("tecno")
    }

    /**
     * Resolves and launches the device-specific OEM autostart / background app management activity.
     */
    fun openOemAutostartSettings(context: Context): Boolean {
        val brand = getOemBrand()
        val intents = mutableListOf<Intent>()

        when {
            brand.contains("xiaomi") || brand.contains("redmi") || brand.contains("poco") -> {
                intents.add(Intent().setComponent(ComponentName("com.miui.securitycenter", "com.miui.permcenter.autostart.AutoStartManagementActivity")))
                intents.add(Intent("miui.intent.action.OP_AUTO_START").addCategory(Intent.CATEGORY_DEFAULT))
                intents.add(Intent().setComponent(ComponentName("com.miui.securitycenter", "com.miui.powercenter.PowerSettings")))
            }
            brand.contains("samsung") -> {
                intents.add(Intent().setComponent(ComponentName("com.samsung.android.lool", "com.samsung.android.sm.battery.ui.BatteryActivity")))
                intents.add(Intent().setComponent(ComponentName("com.samsung.android.sm", "com.samsung.android.sm.ui.battery.BatteryActivity")))
                intents.add(Intent().setComponent(ComponentName("com.samsung.android.lool", "com.samsung.android.sm.ui.battery.AppSleepListActivity")))
            }
            brand.contains("oppo") || brand.contains("oneplus") || brand.contains("realme") -> {
                intents.add(Intent().setComponent(ComponentName("com.coloros.safecenter", "com.coloros.safecenter.permission.startup.StartupAppListActivity")))
                intents.add(Intent().setComponent(ComponentName("com.coloros.safecenter", "com.coloros.safecenter.startupapp.StartupAppListActivity")))
                intents.add(Intent().setComponent(ComponentName("com.oppo.safe", "com.oppo.safe.permission.startup.StartupAppListActivity")))
                intents.add(Intent().setComponent(ComponentName("com.oplus.battery", "com.oplus.battery.AppListActivity")))
            }
            brand.contains("vivo") || brand.contains("iqoo") -> {
                intents.add(Intent().setComponent(ComponentName("com.vivo.permissionmanager", "com.vivo.permissionmanager.activity.BgStartUpManagerActivity")))
                intents.add(Intent().setComponent(ComponentName("com.iqoo.secure", "com.iqoo.secure.ui.phoneoptimize.BgStartUpManager")))
                intents.add(Intent().setComponent(ComponentName("com.vivo.permissionmanager", "com.vivo.permissionmanager.activity.PurviewTabActivity")))
            }
            brand.contains("huawei") || brand.contains("honor") -> {
                intents.add(Intent().setComponent(ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.optimize.process.ProtectActivity")))
                intents.add(Intent().setComponent(ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.appcontrol.activity.StartupAppControlActivity")))
            }
            brand.contains("transsion") || brand.contains("infinix") || brand.contains("tecno") -> {
                intents.add(Intent().setComponent(ComponentName("com.transsion.phonemaster", "com.cyin.himgr.autostart.AutoStartActivity")))
            }
        }

        // Generic fallback to Application Details Settings
        intents.add(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
            data = Uri.parse("package:${context.packageName}")
        })

        for (intent in intents) {
            try {
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                val matches = context.packageManager.queryIntentActivities(intent, PackageManager.MATCH_DEFAULT_ONLY)
                if (matches.isNotEmpty()) {
                    context.startActivity(intent)
                    return true
                }
            } catch (_: Exception) {}
        }

        return false
    }
}

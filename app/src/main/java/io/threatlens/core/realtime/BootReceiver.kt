package io.threatlens.core.realtime

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat

class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        if (action == Intent.ACTION_BOOT_COMPLETED || action == "android.intent.action.QUICKBOOT_POWERON") {
            val prefs = context.getSharedPreferences("threatlens_prefs", Context.MODE_PRIVATE)
            val isShieldEnabled = prefs.getBoolean("key_realtime_shield_enabled", true)
            if (isShieldEnabled) {
                val serviceIntent = Intent(context, RealtimeDownloadShieldService::class.java)
                ContextCompat.startForegroundService(context, serviceIntent)
            }
        }
    }
}

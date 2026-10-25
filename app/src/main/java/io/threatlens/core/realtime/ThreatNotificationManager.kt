package io.threatlens.core.realtime

import android.app.*
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.core.app.NotificationCompat
import io.threatlens.MainActivity
import io.threatlens.core.model.ThreatReport
import io.threatlens.core.model.ThreatSeverity

object ThreatNotificationManager {

    const val SHIELD_CHANNEL_ID = "threatlens_shield_status"
    const val THREAT_ALERT_CHANNEL_ID = "threatlens_threat_alerts"
    const val FOREGROUND_NOTIFICATION_ID = 2001

    fun createChannels(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = context.getSystemService(NotificationManager::class.java)

            // Silent status channel for foreground service
            val shieldChannel = NotificationChannel(
                SHIELD_CHANNEL_ID,
                "ThreatLens Shield Active",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows real-time download and install protection status"
                setShowBadge(false)
            }

            // High importance channel for malware heads-up popups
            val alertChannel = NotificationChannel(
                THREAT_ALERT_CHANNEL_ID,
                "Malware & Threat Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Instant notifications when malicious files are intercepted"
                enableVibration(true)
                setShowBadge(true)
            }

            manager.createNotificationChannel(shieldChannel)
            manager.createNotificationChannel(alertChannel)
        }
    }

    fun buildForegroundShieldNotification(context: Context): Notification {
        val launchIntent = Intent(context, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            context, 0, launchIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(context, SHIELD_CHANNEL_ID)
            .setContentTitle("ThreatLens Shield Active")
            .setContentText("Monitoring downloads with zero-idle power mode")
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    fun showThreatAlert(context: Context, report: ThreatReport) {
        val manager = context.getSystemService(NotificationManager::class.java)

        val launchIntent = Intent(context, MainActivity::class.java).apply {
            putExtra("THREAT_ID", report.id)
        }
        val pendingIntent = PendingIntent.getActivity(
            context, report.id.hashCode(), launchIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val isMalicious = report.severity == ThreatSeverity.MALICIOUS
        val title = if (isMalicious) "CRITICAL MALWARE INTERCEPTED" else "Suspicious File Detected"
        val subtitle = "${report.targetName} (${report.threatFamily})"
        val body = report.aiExplanation ?: "Threat score: ${report.finalScore}/100. Potential risk detected."

        val builder = NotificationCompat.Builder(context, THREAT_ALERT_CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(subtitle)
            .setStyle(NotificationCompat.BigTextStyle().bigText("$subtitle\n\n$body"))
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)

        manager.notify(report.id.hashCode(), builder.build())
    }
}

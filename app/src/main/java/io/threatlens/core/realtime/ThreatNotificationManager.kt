package io.threatlens.core.realtime

import android.app.*
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.net.Uri
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import io.threatlens.MainActivity
import io.threatlens.R
import io.threatlens.core.model.ThreatReport
import io.threatlens.core.model.ThreatSeverity
import java.io.File

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
            .setContentText("Monitoring downloads and installations in real-time")
            .setSmallIcon(R.drawable.ic_threatlens_logo)
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun resolveAppDisplayName(context: Context, report: ThreatReport): String {
        // 1. If report already has a valid human-readable appName (and not generic base.apk)
        val candidate = report.appName?.trim()
        if (!candidate.isNullOrBlank() && !candidate.equals("base.apk", ignoreCase = true)) {
            return candidate
        }

        // 2. Try resolving via packageName
        val pkg = report.packageName?.trim()
        if (!pkg.isNullOrBlank()) {
            try {
                val appInfo = context.packageManager.getApplicationInfo(pkg, 0)
                val label = context.packageManager.getApplicationLabel(appInfo).toString()
                if (label.isNotBlank() && !label.equals("base.apk", ignoreCase = true)) {
                    return label
                }
            } catch (_: Exception) {}
        }

        // 3. Try resolving via target APK file archive
        if (report.targetPath.isNotBlank()) {
            try {
                val file = File(report.targetPath)
                if (file.exists() && file.extension.equals("apk", ignoreCase = true)) {
                    val archiveInfo = context.packageManager.getPackageArchiveInfo(file.absolutePath, 0)
                    if (archiveInfo != null) {
                        archiveInfo.applicationInfo.sourceDir = file.absolutePath
                        archiveInfo.applicationInfo.publicSourceDir = file.absolutePath
                        val label = context.packageManager.getApplicationLabel(archiveInfo.applicationInfo).toString()
                        if (label.isNotBlank() && !label.equals("base.apk", ignoreCase = true)) {
                            return label
                        }
                    }
                }
            } catch (_: Exception) {}
        }

        // 4. Fallback: If targetName is base.apk, show packageName or friendly fallback
        if (report.targetName.equals("base.apk", ignoreCase = true)) {
            return if (!report.packageName.isNullOrBlank()) report.packageName else "Android Application"
        }

        return report.targetName
    }

    private fun loadAppIconBitmap(context: Context, report: ThreatReport): Bitmap? {
        try {
            var drawable: Drawable? = null

            // Try from packageName
            if (!report.packageName.isNullOrBlank()) {
                try {
                    drawable = context.packageManager.getApplicationIcon(report.packageName)
                } catch (_: Exception) {}
            }

            // Try from APK path
            if (drawable == null && report.targetPath.isNotBlank()) {
                val file = File(report.targetPath)
                if (file.exists() && file.extension.equals("apk", ignoreCase = true)) {
                    val archiveInfo = context.packageManager.getPackageArchiveInfo(file.absolutePath, 0)
                    if (archiveInfo != null) {
                        archiveInfo.applicationInfo.sourceDir = file.absolutePath
                        archiveInfo.applicationInfo.publicSourceDir = file.absolutePath
                        drawable = archiveInfo.applicationInfo.loadIcon(context.packageManager)
                    }
                }
            }

            val targetDrawable = drawable ?: return null
            if (targetDrawable is BitmapDrawable && targetDrawable.bitmap != null) {
                return targetDrawable.bitmap
            }

            val width = if (targetDrawable.intrinsicWidth > 0) targetDrawable.intrinsicWidth else 96
            val height = if (targetDrawable.intrinsicHeight > 0) targetDrawable.intrinsicHeight else 96
            val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
            val canvas = Canvas(bitmap)
            targetDrawable.setBounds(0, 0, canvas.width, canvas.height)
            targetDrawable.draw(canvas)
            return bitmap
        } catch (_: Exception) {
            return null
        }
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

        val displayName = resolveAppDisplayName(context, report)
        val isMalicious = report.severity == ThreatSeverity.MALICIOUS
        val title = if (isMalicious) "CRITICAL MALWARE: $displayName" else "Suspicious Threat: $displayName"
        val subtitle = "${report.threatFamily} (Score: ${report.finalScore}/100)"
        val body = report.aiExplanation ?: "Score: ${report.finalScore}/100. Potential security risk detected on device."

        val bigText = buildString {
            appendLine("Application: $displayName")
            if (!report.packageName.isNullOrBlank()) {
                appendLine("Package: ${report.packageName}")
            }
            if (!report.targetName.equals(displayName, ignoreCase = true)) {
                appendLine("Target: ${report.targetName}")
            }
            appendLine("Verdict: ${report.threatFamily} • Score ${report.finalScore}/100")
            appendLine()
            append(body)
        }

        val builder = NotificationCompat.Builder(context, THREAT_ALERT_CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(subtitle)
            .setStyle(NotificationCompat.BigTextStyle().bigText(bigText))
            .setSmallIcon(R.drawable.ic_threatlens_logo)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)

        // Attach dynamic app icon to notification
        val appBitmap = loadAppIconBitmap(context, report)
        if (appBitmap != null) {
            builder.setLargeIcon(appBitmap)
        }

        manager.notify(report.id.hashCode(), builder.build())
    }
}

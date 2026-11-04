package io.threatlens.core.realtime

import android.app.*
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import android.media.AudioAttributes
import android.net.Uri
import android.os.Build
import androidx.core.app.NotificationCompat
import io.threatlens.MainActivity
import io.threatlens.R
import io.threatlens.core.model.ThreatReport
import io.threatlens.core.model.ThreatSeverity
import java.io.File

object ThreatNotificationManager {

    const val SHIELD_CHANNEL_ID = "threatlens_shield_status"
    const val THREAT_ALERT_CHANNEL_ID = "threatlens_threat_alerts" // Maintained for backward compatibility
    const val CRITICAL_MALWARE_CHANNEL_ID = "threatlens_critical_malware"
    const val SUSPICIOUS_ALERT_CHANNEL_ID = "threatlens_suspicious_alerts"
    const val SAFE_SCAN_CHANNEL_ID = "threatlens_safe_results"
    const val FOREGROUND_NOTIFICATION_ID = 2001

    fun createChannels(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = context.getSystemService(NotificationManager::class.java)

            // 1. Silent status channel for foreground service
            val shieldChannel = NotificationChannel(
                SHIELD_CHANNEL_ID,
                "ThreatLens Shield Active",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows real-time download and install protection status"
                setShowBadge(false)
            }

            val audioAttrs = AudioAttributes.Builder()
                .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                .setUsage(AudioAttributes.USAGE_NOTIFICATION_EVENT)
                .build()

            // 2. Critical Threat Alert Channel: Cyber Tactical Siren + 3-burst emergency vibration
            val sirenResId = context.resources.getIdentifier("threat_alert_siren", "raw", context.packageName)
            val sirenUri = if (sirenResId != 0) {
                Uri.parse("android.resource://${context.packageName}/$sirenResId")
            } else {
                Uri.parse("android.resource://${context.packageName}/raw/threat_alert_siren")
            }

            val criticalChannel = NotificationChannel(
                CRITICAL_MALWARE_CHANNEL_ID,
                "Critical Threat Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "High-priority electronic siren alerts when critical malware is intercepted"
                setSound(sirenUri, audioAttrs)
                enableVibration(true)
                vibrationPattern = longArrayOf(0, 500, 200, 500, 200, 500)
                enableLights(true)
                lightColor = 0xFFFF1744.toInt()
                setShowBadge(true)
            }

            // 3. Suspicious & Caution Alert Channel: Amber Caution Pulse + two-tone prompt vibration
            val cautionResId = context.resources.getIdentifier("threat_caution_pulse", "raw", context.packageName)
            val cautionUri = if (cautionResId != 0) {
                Uri.parse("android.resource://${context.packageName}/$cautionResId")
            } else {
                Uri.parse("android.resource://${context.packageName}/raw/threat_caution_pulse")
            }

            val suspiciousChannel = NotificationChannel(
                SUSPICIOUS_ALERT_CHANNEL_ID,
                "Suspicious & Caution Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Two-tone caution alerts when suspicious apps or risky downloads are detected"
                setSound(cautionUri, audioAttrs)
                enableVibration(true)
                vibrationPattern = longArrayOf(0, 250, 150, 250)
                enableLights(true)
                lightColor = 0xFFFFB300.toInt()
                setShowBadge(true)
            }

            // 4. Safe Verification Channel: 100% SILENT (zero sound, zero vibration)
            val safeChannel = NotificationChannel(
                SAFE_SCAN_CHANNEL_ID,
                "Realtime Scan Verification",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Silent status verifications when downloads or installed apps are verified clean"
                setSound(null, null)
                enableVibration(false)
                vibrationPattern = longArrayOf(0)
                setShowBadge(false)
            }

            // 5. Legacy backward compatibility channel
            val legacyAlertChannel = NotificationChannel(
                THREAT_ALERT_CHANNEL_ID,
                "Malware & Threat Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Instant notifications when malicious files are intercepted"
                enableVibration(true)
                setShowBadge(true)
            }

            manager.createNotificationChannel(shieldChannel)
            manager.createNotificationChannel(criticalChannel)
            manager.createNotificationChannel(suspiciousChannel)
            manager.createNotificationChannel(safeChannel)
            manager.createNotificationChannel(legacyAlertChannel)
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
            .setSmallIcon(R.drawable.ic_notification_shield)
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    fun isAppInstallTarget(report: ThreatReport, isPackageInstall: Boolean? = null): Boolean {
        if (isPackageInstall != null) return isPackageInstall
        val path = report.targetPath.lowercase()
        return path.startsWith("/data/app") ||
               path.startsWith("/system/") ||
               path.startsWith("/data/priv-app") ||
               path.startsWith("/vendor/app") ||
               path.contains("/data/user/") ||
               report.targetName.equals("base.apk", ignoreCase = true)
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

    fun showThreatAlert(context: Context, report: ThreatReport, isPackageInstall: Boolean? = null) {
        val manager = context.getSystemService(NotificationManager::class.java)

        val launchIntent = Intent(context, MainActivity::class.java).apply {
            putExtra("THREAT_ID", report.id)
            putExtra("THREAT_SHA256", report.sha256)
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            context, report.id.hashCode(), launchIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val isApp = isAppInstallTarget(report, isPackageInstall)
        val isMalicious = report.severity == ThreatSeverity.MALICIOUS
        val displayName = resolveAppDisplayName(context, report)

        // Select channel, vector icon, and accent color
        val channelId = if (isMalicious) CRITICAL_MALWARE_CHANNEL_ID else SUSPICIOUS_ALERT_CHANNEL_ID
        val smallIconRes = if (isMalicious) R.drawable.ic_notification_danger else R.drawable.ic_notification_warning
        val accentColor = if (isMalicious) 0xFFFF1744.toInt() else 0xFFFFB300.toInt()

        val title = if (isApp) {
            if (isMalicious) "🚨 App Install Shield: Malware Detected" else "⚠️ App Install Shield: Suspicious App"
        } else {
            if (isMalicious) "🚨 Download Shield: Malware Intercepted" else "⚠️ Download Shield: Caution Advised"
        }

        val subtitle = if (isMalicious) {
            "$displayName • ${report.threatFamily} (${report.finalScore}/100)"
        } else {
            "$displayName • Caution Advised (${report.finalScore}/100)"
        }

        val body = report.aiExplanation ?: if (isMalicious) {
            "Hostile threat behaviors or known malicious signature detected."
        } else {
            "Score: ${report.finalScore}/100. Potential privacy or permission risk identified."
        }

        val bigText = buildString {
            if (isApp) {
                appendLine(if (isMalicious) "🚨 CRITICAL MALWARE IN INSTALLED APP" else "⚠️ SUSPICIOUS INSTALLED APP DETECTED")
                appendLine("Application: $displayName")
                if (!report.packageName.isNullOrBlank()) {
                    appendLine("Package: ${report.packageName}")
                }
            } else {
                appendLine(if (isMalicious) "🚨 CRITICAL MALWARE IN DOWNLOADED FILE" else "⚠️ SUSPICIOUS DOWNLOAD INTERCEPTED")
                appendLine("File: $displayName")
                appendLine("Path: ${report.targetPath}")
            }
            appendLine("Threat Assessment: ${report.threatFamily} • Score ${report.finalScore}/100")
            appendLine()
            append(body)
        }

        val builder = NotificationCompat.Builder(context, channelId)
            .setContentTitle(title)
            .setContentText(subtitle)
            .setStyle(NotificationCompat.BigTextStyle().bigText(bigText))
            .setSmallIcon(smallIconRes)
            .setColor(accentColor)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)

        // Add context action for installed malicious/suspicious apps: One-tap Uninstall
        if (isApp && !report.packageName.isNullOrBlank()) {
            val uninstallIntent = Intent(Intent.ACTION_DELETE).apply {
                data = Uri.parse("package:${report.packageName}")
            }
            val uninstallPending = PendingIntent.getActivity(
                context,
                report.id.hashCode() + 1,
                uninstallIntent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )
            builder.addAction(R.drawable.ic_notification_danger, "UNINSTALL APP", uninstallPending)
        }

        // Attach dynamic app icon to notification
        val appBitmap = loadAppIconBitmap(context, report)
        if (appBitmap != null) {
            builder.setLargeIcon(appBitmap)
        }

        manager.notify(report.id.hashCode(), builder.build())
    }

    fun showSafeScanNotification(context: Context, report: ThreatReport, isPackageInstall: Boolean? = null) {
        val manager = context.getSystemService(NotificationManager::class.java)

        val launchIntent = Intent(context, MainActivity::class.java).apply {
            putExtra("THREAT_ID", report.id)
            putExtra("THREAT_SHA256", report.sha256)
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            context, report.id.hashCode(), launchIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val isApp = isAppInstallTarget(report, isPackageInstall)
        val displayName = resolveAppDisplayName(context, report)

        val title = if (isApp) {
            "📦 App Install Shield: Verified Safe: $displayName"
        } else {
            "📥 Download Shield: Verified Safe: $displayName"
        }

        val subtitle = if (isApp) {
            "No threats detected • Verified safe to use (0/100)"
        } else {
            "No threats detected • Download verified safe (0/100)"
        }

        val rationale = report.scoreBreakdown?.rationale ?: "Multi-engine security inspection completed (Score: 0/100)"

        val bigText = buildString {
            if (isApp) {
                appendLine("Application: $displayName")
                if (!report.packageName.isNullOrBlank()) {
                    appendLine("Package: ${report.packageName}")
                }
                appendLine("Verdict: Verified Safe • Threat Score: 0/100")
                appendLine("Status: On-device static inspection and cloud intelligence passed. Safe to use.")
            } else {
                appendLine("Downloaded File: $displayName")
                appendLine("Path: ${report.targetPath}")
                appendLine("Verdict: Verified Safe • Threat Score: 0/100")
                appendLine("Status: $rationale")
            }
        }

        val builder = NotificationCompat.Builder(context, SAFE_SCAN_CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(subtitle)
            .setStyle(NotificationCompat.BigTextStyle().bigText(bigText))
            .setSmallIcon(R.drawable.ic_notification_safe)
            .setColor(0xFF00E676.toInt()) // Neon Emerald
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setSound(null)
            .setVibrate(null)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)

        val appBitmap = loadAppIconBitmap(context, report)
        if (appBitmap != null) {
            builder.setLargeIcon(appBitmap)
        }

        manager.notify(report.id.hashCode(), builder.build())
    }
}

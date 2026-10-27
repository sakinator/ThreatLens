package io.threatlens.core.realtime

import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.database.ContentObserver
import android.net.Uri
import android.os.*
import android.provider.MediaStore
import java.io.File

class RealtimeDownloadShieldService : Service() {

    private var downloadFolderObserver: FileObserver? = null
    private var mediaContentObserver: ContentObserver? = null

    override fun onCreate() {
        super.onCreate()
        ThreatNotificationManager.createChannels(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val notification = ThreatNotificationManager.buildForegroundShieldNotification(this)
        try {
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(
                    ThreatNotificationManager.FOREGROUND_NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                )
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(
                    ThreatNotificationManager.FOREGROUND_NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
                )
            } else {
                startForeground(ThreatNotificationManager.FOREGROUND_NOTIFICATION_ID, notification)
            }
        } catch (_: Exception) {
            startForeground(ThreatNotificationManager.FOREGROUND_NOTIFICATION_ID, notification)
        }

        startUltraLowPowerWatchers()
        io.threatlens.core.system.ShieldWatchdogJobService.scheduleWatchdog(applicationContext)
        return START_STICKY
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
        // Auto-resuscitate immediately if the app is cleared from Recent Apps
        try {
            val restartIntent = Intent(applicationContext, RealtimeDownloadShieldService::class.java).apply {
                setPackage(packageName)
            }
            val pendingIntent = android.app.PendingIntent.getService(
                applicationContext,
                1001,
                restartIntent,
                android.app.PendingIntent.FLAG_ONE_SHOT or android.app.PendingIntent.FLAG_IMMUTABLE
            )
            val alarmManager = getSystemService(android.content.Context.ALARM_SERVICE) as? android.app.AlarmManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                alarmManager?.setExactAndAllowWhileIdle(
                    android.app.AlarmManager.RTC_WAKEUP,
                    System.currentTimeMillis() + 1000L,
                    pendingIntent
                )
            } else {
                alarmManager?.set(
                    android.app.AlarmManager.RTC_WAKEUP,
                    System.currentTimeMillis() + 1000L,
                    pendingIntent
                )
            }
        } catch (_: Exception) {}
    }

    private fun startUltraLowPowerWatchers() {
        val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)

        // 1. Kernel inotify watcher: Fires ONLY on completed write (CLOSE_WRITE) or rename (MOVED_TO)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && downloadsDir.exists()) {
            downloadFolderObserver = object : FileObserver(downloadsDir, CLOSE_WRITE or MOVED_TO) {
                override fun onEvent(event: Int, path: String?) {
                    if (path.isNullOrBlank()) return
                    // Fast filter on thread before scheduling any work
                    val lower = path.lowercase()
                    if (lower.endsWith(".apk") || lower.endsWith(".dex") || lower.endsWith(".jar")) {
                        val targetFile = File(downloadsDir, path)
                        RealtimeScanCoordinator.scanFileAsync(applicationContext, targetFile)
                    }
                }
            }
            downloadFolderObserver?.startWatching()
        }

        // 2. MediaStore Downloads event listener for system browser download completions
        mediaContentObserver = object : ContentObserver(Handler(Looper.getMainLooper())) {
            override fun onChange(selfChange: Boolean, uri: Uri?) {
                super.onChange(selfChange, uri)
                if (uri != null) {
                    processMediaStoreUri(uri)
                }
            }
        }

        try {
            contentResolver.registerContentObserver(
                MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                true,
                mediaContentObserver!!
            )
        } catch (_: Exception) {}
    }

    private fun processMediaStoreUri(uri: Uri) {
        try {
            val projection = arrayOf(MediaStore.MediaColumns.DATA, MediaStore.MediaColumns.DISPLAY_NAME)
            contentResolver.query(uri, projection, null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val dataIndex = cursor.getColumnIndex(MediaStore.MediaColumns.DATA)
                    if (dataIndex != -1) {
                        val path = cursor.getString(dataIndex)
                        if (!path.isNullOrBlank()) {
                            val file = File(path)
                            RealtimeScanCoordinator.scanFileAsync(applicationContext, file)
                        }
                    }
                }
            }
        } catch (_: Exception) {}
    }

    override fun onDestroy() {
        downloadFolderObserver?.stopWatching()
        mediaContentObserver?.let { contentResolver.unregisterContentObserver(it) }
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}

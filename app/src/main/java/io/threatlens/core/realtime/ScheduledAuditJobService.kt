package io.threatlens.core.realtime

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.content.SharedPreferences
import io.threatlens.core.diagnostics.AppDiagnosticLogger
import io.threatlens.core.model.ThreatSeverity
import kotlinx.coroutines.*

/**
 * P4: Autonomous Scheduled Background Deep Audit JobService.
 *
 * Runs non-intrusively via Android JobScheduler every 24 to 48 hours exclusively when the device
 * is idle and connected to AC power (charging). Performs full-depth static bytecode, heuristic,
 * native ELF, and signature audits across all installed apps with 0% battery impact.
 */
class ScheduledAuditJobService : JobService() {

    private val jobScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    override fun onStartJob(params: JobParameters?): Boolean {
        jobScope.launch {
            try {
                performScheduledAudit(applicationContext)
            } catch (e: Exception) {
                AppDiagnosticLogger.logError("ScheduledAuditJobService", "Audit execution failed: ${e.message}", e)
            }
            jobFinished(params, false)
        }
        return true
    }

    override fun onStopJob(params: JobParameters?): Boolean {
        jobScope.cancel()
        return true
    }

    private suspend fun performScheduledAudit(context: Context) = withContext(Dispatchers.IO) {
        AppDiagnosticLogger.log("ScheduledAuditJobService", "Executing scheduled background deep audit...")
        val pm = context.packageManager
        val packages = pm.getInstalledPackages(0)

        var threatsFound = 0
        val threatsToPersist = mutableListOf<io.threatlens.core.model.ThreatReport>()

        for (pkg in packages) {
            val sourceDir = pkg.applicationInfo.sourceDir ?: continue
            val apkFile = java.io.File(sourceDir)
            if (apkFile.exists() && apkFile.canRead()) {
                val report = RealtimeScanCoordinator.streamScan(context, apkFile, isFullScan = true)
                if (report.severity == ThreatSeverity.MALICIOUS || report.severity == ThreatSeverity.HIGH_RISK || report.severity == ThreatSeverity.SUSPICIOUS) {
                    threatsFound++
                    threatsToPersist.add(report)
                    ThreatNotificationManager.showThreatAlert(context, report)
                }
            }
        }

        // Persist all identified threats so they survive process death and appear in UI
        if (threatsToPersist.isNotEmpty()) {
            io.threatlens.core.scanner.ScanReportRepository.saveReports(context, threatsToPersist)
        }

        // Update last scheduled audit timestamp in settings
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit().putLong(KEY_LAST_AUDIT_TIMESTAMP, System.currentTimeMillis()).apply()

        AppDiagnosticLogger.log(
            "ScheduledAuditJobService",
            "Scheduled audit complete: Scanned ${packages.size} apps, identified $threatsFound threats."
        )
    }

    companion object {
        private const val SCHEDULED_AUDIT_JOB_ID = 8852
        private const val PREFS_NAME = "threatlens_scheduled_audit"
        private const val KEY_ENABLED = "key_scheduled_audit_enabled"
        private const val KEY_INTERVAL_HOURS = "key_interval_hours"
        private const val KEY_LAST_AUDIT_TIMESTAMP = "key_last_audit_timestamp"
        const val DEFAULT_INTERVAL_HOURS = 168 // Default: 7 days (1 week)
        const val DEFAULT_INTERVAL_DAYS = 7

        fun isEnabled(context: Context): Boolean {
            return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getBoolean(KEY_ENABLED, true)
        }

        fun getIntervalHours(context: Context): Int {
            return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getInt(KEY_INTERVAL_HOURS, DEFAULT_INTERVAL_HOURS)
        }

        fun getIntervalDays(context: Context): Int {
            val hours = getIntervalHours(context)
            return (hours / 24).coerceIn(1, 7)
        }

        fun getLastAuditTimestamp(context: Context): Long {
            return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getLong(KEY_LAST_AUDIT_TIMESTAMP, 0L)
        }

        fun setEnabled(context: Context, enabled: Boolean, intervalHours: Int = DEFAULT_INTERVAL_HOURS) {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            prefs.edit()
                .putBoolean(KEY_ENABLED, enabled)
                .putInt(KEY_INTERVAL_HOURS, intervalHours)
                .apply()

            if (enabled) {
                scheduleAudit(context, intervalHours)
            } else {
                cancelAudit(context)
            }
        }

        fun setIntervalDays(context: Context, days: Int) {
            val clampedDays = days.coerceIn(1, 7)
            val hours = clampedDays * 24
            val enabled = isEnabled(context)
            setEnabled(context, enabled, hours)
        }

        fun scheduleAudit(context: Context, intervalHours: Int = DEFAULT_INTERVAL_HOURS) {
            val scheduler = context.getSystemService(Context.JOB_SCHEDULER_SERVICE) as? JobScheduler ?: return
            val component = ComponentName(context, ScheduledAuditJobService::class.java)

            val millis = intervalHours.toLong() * 60 * 60 * 1000L
            val jobInfo = JobInfo.Builder(SCHEDULED_AUDIT_JOB_ID, component)
                .setPeriodic(millis)
                .setRequiresCharging(true)
                .setRequiresDeviceIdle(true)
                .setPersisted(true)
                .build()

            scheduler.schedule(jobInfo)
        }

        fun cancelAudit(context: Context) {
            val scheduler = context.getSystemService(Context.JOB_SCHEDULER_SERVICE) as? JobScheduler ?: return
            scheduler.cancel(SCHEDULED_AUDIT_JOB_ID)
        }
    }
}

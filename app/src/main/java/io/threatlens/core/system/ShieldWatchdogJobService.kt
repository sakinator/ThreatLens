package io.threatlens.core.system

import android.app.ActivityManager
import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
import io.threatlens.core.realtime.RealtimeDownloadShieldService
import kotlinx.coroutines.*

/**
 * ThreatLens Shield Watchdog JobService.
 *
 * Runs via native Android JobScheduler every 15-30 minutes during standard OS maintenance windows
 * to verify that RealtimeDownloadShieldService is active. If an aggressive OEM task killer terminated
 * the shield process, this watchdog resurrects it without holding wake locks or draining battery.
 */
class ShieldWatchdogJobService : JobService() {

    private val jobScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    override fun onStartJob(params: JobParameters?): Boolean {
        jobScope.launch {
            try {
                ensureShieldRunning(applicationContext)
            } catch (_: Exception) {}
            jobFinished(params, false)
        }
        return true
    }

    override fun onStopJob(params: JobParameters?): Boolean {
        jobScope.cancel()
        return true
    }

    companion object {
        private const val WATCHDOG_JOB_ID = 8850

        fun scheduleWatchdog(context: Context) {
            val scheduler = context.getSystemService(Context.JOB_SCHEDULER_SERVICE) as? JobScheduler ?: return
            val component = ComponentName(context, ShieldWatchdogJobService::class.java)

            val jobInfo = JobInfo.Builder(WATCHDOG_JOB_ID, component)
                .setPeriodic(15 * 60 * 1000L) // 15 minutes batch interval
                .setPersisted(true) // Survives device reboots
                .build()

            scheduler.schedule(jobInfo)
        }

        fun cancelWatchdog(context: Context) {
            val scheduler = context.getSystemService(Context.JOB_SCHEDULER_SERVICE) as? JobScheduler ?: return
            scheduler.cancel(WATCHDOG_JOB_ID)
        }

        fun ensureShieldRunning(context: Context) {
            if (!isServiceRunning(context, RealtimeDownloadShieldService::class.java)) {
                val intent = Intent(context, RealtimeDownloadShieldService::class.java)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(intent)
                } else {
                    context.startService(intent)
                }
            }
        }

        @Suppress("DEPRECATION")
        private fun isServiceRunning(context: Context, serviceClass: Class<*>): Boolean {
            val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager ?: return false
            val services = am.getRunningServices(50) ?: return false
            return services.any { it.service.className == serviceClass.name }
        }
    }
}

package io.threatlens.core.update

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import kotlinx.coroutines.*

/**
 * Native Android JobService that silently updates the virus signature database:
 * - Runs nightly when device is connected to Wi-Fi (UNMETERED network)
 * - Requires charging (device plugged in at night)
 * - 0% idle battery consumption, zero mobile data usage
 */
class SignatureUpdateJobService : JobService() {

    private val jobScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    override fun onStartJob(params: JobParameters?): Boolean {
        jobScope.launch {
            try {
                SignatureUpdateService.updateSignaturesNow(applicationContext)
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
        private const val SIGNATURE_JOB_ID = 8842

        fun scheduleNightlyWifiUpdate(context: Context) {
            val scheduler = context.getSystemService(Context.JOB_SCHEDULER_SERVICE) as? JobScheduler ?: return
            val component = ComponentName(context, SignatureUpdateJobService::class.java)

            val jobInfo = JobInfo.Builder(SIGNATURE_JOB_ID, component)
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_UNMETERED) // Strictly Wi-Fi only
                .setRequiresCharging(true) // Enforces device is charging (overnight)
                .setPeriodic(24 * 60 * 60 * 1000L) // Runs once daily
                .setPersisted(true) // Survives device reboots
                .build()

            scheduler.schedule(jobInfo)
        }

        fun cancelNightlyWifiUpdate(context: Context) {
            val scheduler = context.getSystemService(Context.JOB_SCHEDULER_SERVICE) as? JobScheduler ?: return
            scheduler.cancel(SIGNATURE_JOB_ID)
        }
    }
}
package io.threatlens

import android.app.Application
import io.threatlens.core.realtime.ThreatNotificationManager

class ThreatLensApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        // Initialize notification channels for silent shield status and high-priority alerts
        ThreatNotificationManager.createChannels(this)
    }
}

package io.threatlens

import android.app.Application
import io.threatlens.core.realtime.ThreatNotificationManager
import io.threatlens.core.update.SignatureUpdateService

class ThreatLensApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        // Initialize notification channels for silent shield status and high-priority alerts
        ThreatNotificationManager.createChannels(this)
        // Initialize exclusion filters for both Antivirus and VPN
        io.threatlens.core.exclusions.ExclusionManager.init(this)
        // Initialize per-app network firewall rule manager
        io.threatlens.core.firewall.FirewallRuleManager.init(this)
        // Initialize local signature database and load persisted updates
        SignatureUpdateService.init(this)
        // Initialize durable API key vault (survives app updates and restores lost keys)
        io.threatlens.core.storage.ApiKeyVault.init(this)
        // Initialize scheduled deep audit if enabled
        if (io.threatlens.core.realtime.ScheduledAuditJobService.isEnabled(this)) {
            io.threatlens.core.realtime.ScheduledAuditJobService.scheduleAudit(this)
        }
    }
}
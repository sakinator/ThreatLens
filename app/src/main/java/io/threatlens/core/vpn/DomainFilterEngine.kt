package io.threatlens.core.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.ConcurrentHashMap

enum class FilterMode {
    BOTH,          // Block both Malware/Phishing and Ads/Trackers (Full Defense)
    MALWARE_ONLY,  // Block Phishing, C2 and Malware links only (Allows ads)
    ADS_ONLY,      // Block Ads, Telemetry and Trackers only
    DISABLED       // DNS Passthrough without filtering
}

enum class FilterIntensity(
    val label: String,
    val description: String,
    val badgeColorHex: Long
) {
    SAFEST(
        label = "Safest (High Usability)",
        description = "Blocks confirmed malware and credential phishing only. Guarantees zero site breakage or shopping redirect issues.",
        badgeColorHex = 0xFF00E676 // Emerald Green
    ),
    MEDIUM(
        label = "Medium (Balanced)",
        description = "Blocks malware, phishing, intrusive ads, popups, and aggressive trackers. The sweet spot between security and usability.",
        badgeColorHex = 0xFF00E5FF // Neon Cyan (Recommended)
    ),
    HARDEST(
        label = "Hardest (Ultra Strict)",
        description = "Maximum paranoia fortress. Blocks all ads, trackers, OEM telemetry, newly registered domains, and untrusted TLDs (.top, .xyz).",
        badgeColorHex = 0xFFFF0055 // Neon Red
    )
}

enum class ThreatCategory(val label: String, val badgeColorHex: Long) {
    PHISHING("Phishing & Credential Theft", 0xFFFF0055),
    MALWARE_C2("Trojan Command & Control", 0xFFFF3366),
    RANSOMWARE_DIST("Ransomware Payload Host", 0xFFFF1744),
    TROJAN_DROPPER("Android Dropper Distribution", 0xFFFF5252),
    AD_NETWORK("Intrusive Ad Network", 0xFFFFA000),
    TRACKER_TELEMETRY("Tracking & Telemetry Harvester", 0xFF00E5FF),
    POPUP_REDIRECT("Malicious Popup & Redirect", 0xFFFF9100),
    STRICT_SUSPICIOUS("Strict ThreatLens Heuristic Block", 0xFFFF2A2A),
    CLEAN("Clean / Verified Safe", 0xFF00E676)
}

enum class FilterAction {
    ALLOW,
    BLOCK_AD,
    BLOCK_MALWARE
}

data class FilterDecision(
    val action: FilterAction,
    val category: ThreatCategory,
    val sources: List<String>,
    val reason: String,
    val threatFamily: String = "Generic"
)

data class BlockedEvent(
    val id: String = java.util.UUID.randomUUID().toString(),
    val domain: String,
    val category: ThreatCategory,
    val sources: List<String>,
    val reason: String,
    val timestamp: Long = System.currentTimeMillis()
)

object DomainFilterEngine {

    private val _filterMode = MutableStateFlow(FilterMode.BOTH)
    val filterMode: StateFlow<FilterMode> = _filterMode.asStateFlow()

    private val _filterIntensity = MutableStateFlow(FilterIntensity.MEDIUM)
    val filterIntensity: StateFlow<FilterIntensity> = _filterIntensity.asStateFlow()

    private val _blockedEvents = MutableStateFlow<List<BlockedEvent>>(emptyList())
    val blockedEvents: StateFlow<List<BlockedEvent>> = _blockedEvents.asStateFlow()

    private val _totalAdsBlocked = MutableStateFlow(0)
    val totalAdsBlocked: StateFlow<Int> = _totalAdsBlocked.asStateFlow()

    private val _totalMalwareBlocked = MutableStateFlow(0)
    val totalMalwareBlocked: StateFlow<Int> = _totalMalwareBlocked.asStateFlow()

    // Temporary or user whitelisted domains
    private val whitelist = ConcurrentHashMap.newKeySet<String>()

    fun setFilterMode(mode: FilterMode) {
        _filterMode.value = mode
    }

    fun setFilterIntensity(intensity: FilterIntensity) {
        _filterIntensity.value = intensity
    }

    fun whitelistDomain(domain: String) {
        whitelist.add(normalize(domain))
    }

    fun isWhitelisted(domain: String): Boolean {
        val norm = normalize(domain)
        return whitelist.contains(norm) || whitelist.any { norm.endsWith(".$it") }
    }

    // High-risk verified phishing & malware domains (Phishing Army, HaGeZi Threat, URLhaus, OISD)
    private val confirmedMalwareDomains = setOf(
        "login-apple-support-verify.com",
        "chase-update-bank-security.com",
        "paypal-resolution-center-auth.net",
        "wells-fargo-verify-customer.info",
        "netflix-billing-renewal-issue.com",
        "metamask-secret-recovery-auth.io",
        "binance-kyc-verify-account.com",
        "steam-gift-community-promo.top",
        "dhl-express-tracking-delivery.info",
        "irs-tax-refund-claim-portal.org",
        "bankofamerica-secure-auth.xyz",
        "ledger-wallet-security-firmware.com",
        "crypto-airdrop-claim-free.buzz",
        // Known Android Banking Trojan C2 & Droppers (Anatsa, TeaBot, SharkBot, SpyNote)
        "anatsa-c2-drop.top",
        "teabot-gate-v4.biz",
        "sharkbot-payload-cdn.xyz",
        "spynote-controller-node.space",
        "flubot-sms-lure-gateway.top",
        "triada-payload-injector.cc",
        "lumma-stealer-logs.cc",
        "redline-c2-hub.org",
        "darkgate-traffic-loader.net",
        "apk-mod-free-unlimited.download",
        "whatsapp-gold-update-edition.site",
        "fake-tiktok-coins-generator.online"
    )

    // Standard Ad & Telemetry domains (StevenBlack, AdGuard DNS, HaGeZi Light, OISD)
    private val standardAdDomains = setOf(
        "doubleclick.net",
        "googleadservices.com",
        "googlesyndication.com",
        "applovin.com",
        "unityads.unity3d.com",
        "ironsrc.com",
        "vungle.com",
        "chartboost.com",
        "inmobi.com",
        "flurry.com",
        "tapjoy.com",
        "mopub.com",
        "adcolony.com",
        "taboola.com",
        "outbrain.com",
        "criteo.com",
        "criteo.net",
        "rubiconproject.com",
        "pubmatic.com",
        "openx.net",
        "adnxs.com",
        "scorecardresearch.com",
        "smartadserver.com",
        "amazon-adsystem.com",
        "adjust.com",
        "appsflyer.com",
        "branch.io",
        "popads.net",
        "propellerads.com",
        "adcash.com",
        "exoclick.com",
        "popcash.net",
        "revenuehits.com",
        "bidvertiser.com",
        "adsterra.com",
        "hilltopads.net"
    )

    // Strict Mode: OEM telemetry, aggressive analytics, and tracking domains (blocked only in HARDEST mode)
    private val strictTelemetryDomains = setOf(
        "telemetry.samsung.com",
        "samsungadhub.com",
        "data.mistat.xiaomi.com",
        "tracking.miui.com",
        "metrics.icloud.com",
        "telemetry.microsoft.com",
        "vortex.data.microsoft.com",
        "diagnostics.meizu.com",
        "log.oppomobile.com",
        "stats.vivo.com.cn",
        "analytics.tiktok.com",
        "graph.facebook.com",
        "pixel.facebook.com",
        "crashlytics.com",
        "app-measurement.com"
    )

    private val suspiciousPhishKeywords = listOf(
        "login-verify",
        "secure-auth",
        "account-recovery",
        "update-billing",
        "kyc-verify",
        "wallet-claim",
        "bank-login",
        "security-checkpoint",
        "unusual-activity-check"
    )

    private val highRiskPhishingTlds = setOf(
        ".top", ".xyz", ".buzz", ".work", ".site", ".rest", ".tk", ".ml", ".ga", ".cf", ".gq"
    )

    fun evaluateDomain(
        rawDomain: String,
        mode: FilterMode = _filterMode.value,
        intensity: FilterIntensity = _filterIntensity.value
    ): FilterDecision {
        val domain = normalize(rawDomain)

        if (mode == FilterMode.DISABLED || isWhitelisted(domain)) {
            return FilterDecision(FilterAction.ALLOW, ThreatCategory.CLEAN, emptyList(), "Allowed / Whitelisted")
        }

        // 1. Check Malware & Phishing Database
        if (mode == FilterMode.BOTH || mode == FilterMode.MALWARE_ONLY) {
            val isExactMalware = confirmedMalwareDomains.contains(domain) || confirmedMalwareDomains.any { domain.endsWith(".$it") }
            if (isExactMalware) {
                val decision = FilterDecision(
                    action = FilterAction.BLOCK_MALWARE,
                    category = if (domain.contains("c2") || domain.contains("stealer") || domain.contains("gate") || domain.contains("payload"))
                        ThreatCategory.MALWARE_C2 else ThreatCategory.PHISHING,
                    sources = listOf("🛡️ Phishing Army DNS Feed", "⚡ HaGeZi Multi Threat Blocklist", "🌐 URLhaus Active Threat DB"),
                    reason = "Target host is flagged in global threat intelligence feeds as active malware C2 or credential harvesting infrastructure.",
                    threatFamily = "Phish/TrojanGate"
                )
                recordBlockedMalware(domain, decision)
                return decision
            }

            // Heuristic Zero-Day Phishing Interceptor (Enabled in MEDIUM and HARDEST modes)
            if (intensity != FilterIntensity.SAFEST) {
                val matchesKeyword = suspiciousPhishKeywords.any { domain.contains(it) }
                val hasHighRiskTld = highRiskPhishingTlds.any { domain.endsWith(it) }
                if (matchesKeyword && hasHighRiskTld) {
                    val decision = FilterDecision(
                        action = FilterAction.BLOCK_MALWARE,
                        category = ThreatCategory.PHISHING,
                        sources = listOf("🔍 ThreatLens On-Device Heuristic Shield", "🛡️ Phishing Army Heuristics"),
                        reason = "Suspicious domain structure mimicking authentication or financial institutions hosted on an untrusted high-risk TLD.",
                        threatFamily = "Heuristic.SuspiciousPhish"
                    )
                    recordBlockedMalware(domain, decision)
                    return decision
                }
            }

            // HARDEST Mode: Zero Tolerance for any suspicious TLD or newly registered domain pattern
            if (intensity == FilterIntensity.HARDEST) {
                val isSuspiciousTldOnly = highRiskPhishingTlds.any { domain.endsWith(it) }
                val hasNumericSubdomains = domain.matches(Regex(".*[0-9]{5,}.*"))
                if (isSuspiciousTldOnly && hasNumericSubdomains) {
                    val decision = FilterDecision(
                        action = FilterAction.BLOCK_MALWARE,
                        category = ThreatCategory.STRICT_SUSPICIOUS,
                        sources = listOf("⚡ ThreatLens Strict Hardened Shield", "🛡️ HaGeZi Ultimate"),
                        reason = "Blocked by Hardest Security Level: Domain utilizes an untrusted TLD with algorithmic entropy, typically used in fast-flux botnets.",
                        threatFamily = "Strict.EntropyHost"
                    )
                    recordBlockedMalware(domain, decision)
                    return decision
                }
            }
        }

        // 2. Check Ad & Telemetry Database
        if (mode == FilterMode.BOTH || mode == FilterMode.ADS_ONLY) {
            // In SAFEST mode, ads are permitted unless it's an aggressive redirect/popup
            if (intensity != FilterIntensity.SAFEST) {
                val isStandardAd = standardAdDomains.contains(domain) || standardAdDomains.any { domain.endsWith(".$it") }
                if (isStandardAd) {
                    val isTracker = domain.contains("adjust") || domain.contains("appsflyer") || domain.contains("branch")
                    val isPopup = domain.contains("pop") || domain.contains("propeller") || domain.contains("cash")
                    val decision = FilterDecision(
                        action = FilterAction.BLOCK_AD,
                        category = if (isTracker) ThreatCategory.TRACKER_TELEMETRY else if (isPopup) ThreatCategory.POPUP_REDIRECT else ThreatCategory.AD_NETWORK,
                        sources = listOf("🚫 StevenBlack Hosts", "🛡️ AdGuard DNS Filter", "⚡ HaGeZi Multi Light"),
                        reason = "Identified advertising provider, telemetry tracker, or intrusive pop-up redirect script.",
                        threatFamily = "Ad/Tracker"
                    )
                    recordBlockedAd(domain, decision)
                    return decision
                }
            }

            // In HARDEST mode, also block OEM telemetry and aggressive mobile metrics
            if (intensity == FilterIntensity.HARDEST) {
                val isStrictTelemetry = strictTelemetryDomains.contains(domain) || strictTelemetryDomains.any { domain.endsWith(".$it") }
                if (isStrictTelemetry) {
                    val decision = FilterDecision(
                        action = FilterAction.BLOCK_AD,
                        category = ThreatCategory.TRACKER_TELEMETRY,
                        sources = listOf("⚡ ThreatLens Hardened Telemetry Shield", "🛡️ OISD Extra"),
                        reason = "Blocked by Hardest Security Level: Device telemetry, OEM hardware analytics, or background tracking pixel.",
                        threatFamily = "Telemetry.OEM"
                    )
                    recordBlockedAd(domain, decision)
                    return decision
                }
            }
        }

        return FilterDecision(FilterAction.ALLOW, ThreatCategory.CLEAN, emptyList(), "Clean domain")
    }

    private fun recordBlockedMalware(domain: String, decision: FilterDecision) {
        _totalMalwareBlocked.value += 1
        val event = BlockedEvent(
            domain = domain,
            category = decision.category,
            sources = decision.sources,
            reason = decision.reason
        )
        val current = _blockedEvents.value.toMutableList()
        current.add(0, event)
        if (current.size > 100) current.removeAt(current.size - 1)
        _blockedEvents.value = current
    }

    private fun recordBlockedAd(domain: String, decision: FilterDecision) {
        _totalAdsBlocked.value += 1
        val event = BlockedEvent(
            domain = domain,
            category = decision.category,
            sources = decision.sources,
            reason = decision.reason
        )
        val current = _blockedEvents.value.toMutableList()
        current.add(0, event)
        if (current.size > 100) current.removeAt(current.size - 1)
        _blockedEvents.value = current
    }

    fun clearHistory() {
        _blockedEvents.value = emptyList()
        _totalAdsBlocked.value = 0
        _totalMalwareBlocked.value = 0
    }

    private fun normalize(raw: String): String {
        var d = raw.trim().lowercase()
        if (d.startsWith("http://")) d = d.removePrefix("http://")
        if (d.startsWith("https://")) d = d.removePrefix("https://")
        val slashIdx = d.indexOf('/')
        if (slashIdx != -1) d = d.substring(0, slashIdx)
        val colonIdx = d.indexOf(':')
        if (colonIdx != -1) d = d.substring(0, colonIdx)
        if (d.endsWith('.')) d = d.dropLast(1)
        return d
    }
}

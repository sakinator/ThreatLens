package io.threatlens

import io.threatlens.core.vpn.*
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class DomainFilterRegressionTest {

    @Before
    fun setup() {
        DomainFilterEngine.clearHistory()
        DomainFilterEngine.setFilterMode(FilterMode.BOTH)
        DomainFilterEngine.setFilterIntensity(FilterIntensity.MEDIUM)
    }

    @Test
    fun testConfirmedMalwareBlockedInMedium() {
        val decision = DomainFilterEngine.evaluateDomain(
            "anatsa-c2-drop.top",
            FilterMode.BOTH,
            FilterIntensity.MEDIUM
        )
        assertEquals(FilterAction.BLOCK_MALWARE, decision.action)
        assertTrue(decision.sources.isNotEmpty())
    }

    @Test
    fun testConfirmedAdsBlockedInMedium() {
        val decision = DomainFilterEngine.evaluateDomain(
            "doubleclick.net",
            FilterMode.BOTH,
            FilterIntensity.MEDIUM
        )
        assertEquals(FilterAction.BLOCK_AD, decision.action)
    }

    @Test
    fun testSafestModeAllowsAds() {
        // In SAFEST mode, ads are permitted so that users experience zero breakage on regular browsing
        val decision = DomainFilterEngine.evaluateDomain(
            "doubleclick.net",
            FilterMode.BOTH,
            FilterIntensity.SAFEST
        )
        assertEquals(FilterAction.ALLOW, decision.action)

        // But verified malware must still be blocked!
        val malwareDecision = DomainFilterEngine.evaluateDomain(
            "chase-update-bank-security.com",
            FilterMode.BOTH,
            FilterIntensity.SAFEST
        )
        assertEquals(FilterAction.BLOCK_MALWARE, malwareDecision.action)
    }

    @Test
    fun testHardestModeBlocksTelemetryAndEntropy() {
        val telemetryDecision = DomainFilterEngine.evaluateDomain(
            "telemetry.samsung.com",
            FilterMode.BOTH,
            FilterIntensity.HARDEST
        )
        assertEquals(FilterAction.BLOCK_AD, telemetryDecision.action)

        val entropyDecision = DomainFilterEngine.evaluateDomain(
            "suspicious-auth-98324.top",
            FilterMode.BOTH,
            FilterIntensity.HARDEST
        )
        assertEquals(FilterAction.BLOCK_MALWARE, entropyDecision.action)
    }

    @Test
    fun testWhitelistOverride() {
        DomainFilterEngine.whitelistDomain("anatsa-c2-drop.top")
        val decision = DomainFilterEngine.evaluateDomain(
            "anatsa-c2-drop.top",
            FilterMode.BOTH,
            FilterIntensity.HARDEST
        )
        assertEquals(FilterAction.ALLOW, decision.action)
    }

    @Test
    fun testDnsProvidersRegistryHasValidEntries() {
        val providers = DnsProviders.ALL_PROVIDERS
        assertTrue(providers.size >= 8)
        providers.forEach { provider ->
            assertTrue(provider.primaryIp.isNotBlank())
            assertTrue(provider.name.isNotBlank())
            assertTrue(provider.features.isNotEmpty())
        }
    }
}

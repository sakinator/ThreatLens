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
        DomainFilterEngine.setFilterIntensity(FilterIntensity.BALANCED)
    }

    @Test
    fun testConfirmedMalwareBlockedInBalanced() {
        val decision = DomainFilterEngine.evaluateDomain(
            "anatsa-c2-drop.top",
            FilterMode.BOTH,
            FilterIntensity.BALANCED
        )
        assertEquals(FilterAction.BLOCK_MALWARE, decision.action)
        assertTrue(decision.sources.isNotEmpty())
    }

    @Test
    fun testConfirmedAdsBlockedInBalanced() {
        val decision = DomainFilterEngine.evaluateDomain(
            "doubleclick.net",
            FilterMode.BOTH,
            FilterIntensity.BALANCED
        )
        assertEquals(FilterAction.BLOCK_AD, decision.action)
    }

    @Test
    fun testEssentialShieldAllowsAdsForZeroBreakage() {
        // In ESSENTIAL mode, ads are permitted so that users experience zero breakage on regular browsing
        val decision = DomainFilterEngine.evaluateDomain(
            "doubleclick.net",
            FilterMode.BOTH,
            FilterIntensity.ESSENTIAL
        )
        assertEquals(FilterAction.ALLOW, decision.action)

        // But verified malware must still be blocked!
        val malwareDecision = DomainFilterEngine.evaluateDomain(
            "chase-update-bank-security.com",
            FilterMode.BOTH,
            FilterIntensity.ESSENTIAL
        )
        assertEquals(FilterAction.BLOCK_MALWARE, malwareDecision.action)
    }

    @Test
    fun testZeroTrustFortressBlocksTelemetryAndEntropy() {
        val telemetryDecision = DomainFilterEngine.evaluateDomain(
            "telemetry.samsung.com",
            FilterMode.BOTH,
            FilterIntensity.ZERO_TRUST
        )
        assertEquals(FilterAction.BLOCK_AD, telemetryDecision.action)

        val entropyDecision = DomainFilterEngine.evaluateDomain(
            "suspicious-auth-98324.top",
            FilterMode.BOTH,
            FilterIntensity.ZERO_TRUST
        )
        assertEquals(FilterAction.BLOCK_MALWARE, entropyDecision.action)
    }

    @Test
    fun testWhitelistOverride() {
        DomainFilterEngine.whitelistDomain("anatsa-c2-drop.top")
        val decision = DomainFilterEngine.evaluateDomain(
            "anatsa-c2-drop.top",
            FilterMode.BOTH,
            FilterIntensity.ZERO_TRUST
        )
        assertEquals(FilterAction.ALLOW, decision.action)
    }

    @Test
    fun testIntensitySuggestedDnsMapping() {
        assertEquals("cloudflare_sec", FilterIntensity.ESSENTIAL.suggestedDnsId)
        assertEquals("adguard", FilterIntensity.BALANCED.suggestedDnsId)
        assertEquals("mullvad", FilterIntensity.ZERO_TRUST.suggestedDnsId)

        // Verify that suggested DNS IDs resolve to real providers
        val essentialDns = DnsProviders.getById(FilterIntensity.ESSENTIAL.suggestedDnsId)
        val balancedDns = DnsProviders.getById(FilterIntensity.BALANCED.suggestedDnsId)
        val zeroTrustDns = DnsProviders.getById(FilterIntensity.ZERO_TRUST.suggestedDnsId)

        assertEquals("Cloudflare 1.1.1.2", essentialDns.name)
        assertEquals("AdGuard DNS", balancedDns.name)
        assertEquals("Mullvad DNS", zeroTrustDns.name)
    }

    @Test
    fun testDnsProvidersRegistryHasValidEntries() {
        val providers = DnsProviders.ALL_PROVIDERS
        assertTrue(providers.size >= 8)
        providers.forEach { provider ->
            assertTrue(provider.primaryIp.isNotBlank())
            assertTrue(provider.name.isNotBlank())
            assertTrue(provider.features.isNotEmpty())
            assertTrue(!provider.recommendationBadge.isNullOrBlank())
        }
    }
}

package io.threatlens.core.vpn

import androidx.compose.ui.graphics.Color

data class DnsProvider(
    val id: String,
    val name: String,
    val brandTag: String,
    val primaryIp: String,
    val secondaryIp: String,
    val description: String,
    val features: List<String>,
    val primaryColor: Color,
    val accentColor: Color,
    val website: String,
    val recommendationBadge: String? = null
)

object DnsProviders {
    val ADGUARD = DnsProvider(
        id = "adguard",
        name = "AdGuard DNS",
        brandTag = "AG",
        primaryIp = "94.140.14.14",
        secondaryIp = "94.140.15.15",
        description = "World-leading privacy and ad-blocking resolver. Blocks ads, tracking domains, and malicious phishing sites.",
        features = listOf("Ad Blocking", "Tracker Shield", "Phishing Filter", "No Logs"),
        primaryColor = Color(0xFF23A867), // Official AdGuard Emerald
        accentColor = Color(0xFF68D391),
        website = "https://adguard-dns.io",
        recommendationBadge = "RECOMMENDED DEFAULT (BALANCED)"
    )

    val CLOUDFLARE_SECURITY = DnsProvider(
        id = "cloudflare_sec",
        name = "Cloudflare 1.1.1.2",
        brandTag = "CF",
        primaryIp = "1.1.1.2",
        secondaryIp = "1.0.0.2",
        description = "Cloudflare 1.1.1.1 with automated malware and malicious link blocking powered by Cloudflare Threat Intel.",
        features = listOf("Malware Defense", "Ultra Low Latency", "Global Anycast", "Zero Logs"),
        primaryColor = Color(0xFFF6821F), // Official Cloudflare Orange
        accentColor = Color(0xFFFFA94D),
        website = "https://1.1.1.1",
        recommendationBadge = "SUGGESTED FOR ESSENTIAL SHIELD"
    )

    val CLOUDFLARE_STANDARD = DnsProvider(
        id = "cloudflare",
        name = "Cloudflare 1.1.1.1",
        brandTag = "1.1",
        primaryIp = "1.1.1.1",
        secondaryIp = "1.0.0.1",
        description = "The Internet's fastest privacy-first DNS directory. Resolves queries at lightning speed with zero logging.",
        features = listOf("World's Fastest", "Strict Privacy", "Anycast CDN", "DNSSEC"),
        primaryColor = Color(0xFFF6821F),
        accentColor = Color(0xFFFFA94D),
        website = "https://1.1.1.1",
        recommendationBadge = "FASTEST RAW RESOLUTION"
    )

    val QUAD9 = DnsProvider(
        id = "quad9",
        name = "Quad9 Security",
        brandTag = "Q9",
        primaryIp = "9.9.9.9",
        secondaryIp = "149.112.112.112",
        description = "Swiss non-profit foundation combining 18+ global threat intelligence feeds to block malware, phishing, and botnets.",
        features = listOf("18+ Threat Feeds", "Swiss Privacy Laws", "Phishing Blocker", "GDPR Compliant"),
        primaryColor = Color(0xFF0A4D8C), // Official Quad9 Navy
        accentColor = Color(0xFF38BDF8),
        website = "https://quad9.net",
        recommendationBadge = "BEST SWISS THREAT INTEL"
    )

    val CONTROL_D = DnsProvider(
        id = "controld",
        name = "Control D",
        brandTag = "CD",
        primaryIp = "76.76.2.1",
        secondaryIp = "76.76.10.1",
        description = "Modern secure DNS provider with AI-driven threat categorization, malware blocking, and tracking prevention.",
        features = listOf("AI Threat Engine", "Malware Blocker", "Ad Filter", "Telemetry Shield"),
        primaryColor = Color(0xFF19B394), // Control D Teal
        accentColor = Color(0xFF2DD4BF),
        website = "https://controld.com",
        recommendationBadge = "AI-POWERED DEFENSE"
    )

    val NEXTDNS = DnsProvider(
        id = "nextdns",
        name = "NextDNS",
        brandTag = "NX",
        primaryIp = "45.90.28.0",
        secondaryIp = "45.90.30.0",
        description = "Next-generation cloud firewall protecting against cyber threats, native tracking, and intrusive advertising.",
        features = listOf("Cloud Firewall", "Tracker Blocker", "Phishing Guard", "DNS-over-HTTPS"),
        primaryColor = Color(0xFF1084FF), // NextDNS Blue
        accentColor = Color(0xFF60A5FA),
        website = "https://nextdns.io",
        recommendationBadge = "CLOUD FIREWALL SHIELD"
    )

    val MULLVAD = DnsProvider(
        id = "mullvad",
        name = "Mullvad DNS",
        brandTag = "MV",
        primaryIp = "194.242.2.4",
        secondaryIp = "194.242.2.5",
        description = "High-security Swedish privacy resolver. Strictly no logs, audited infrastructure, and ad/tracker blocking.",
        features = listOf("Swedish Privacy", "Strict Zero Logs", "Ad & Tracker Shield", "Audited"),
        primaryColor = Color(0xFFE5B324), // Mullvad Yellow
        accentColor = Color(0xFFFDE047),
        website = "https://mullvad.net",
        recommendationBadge = "SUGGESTED FOR ZERO-TRUST FORTRESS"
    )

    val GOOGLE = DnsProvider(
        id = "google",
        name = "Google Public DNS",
        brandTag = "G",
        primaryIp = "8.8.8.8",
        secondaryIp = "8.8.4.4",
        description = "Global anycast DNS infrastructure with worldwide low-latency resolution and robust DDoS mitigation.",
        features = listOf("Global Anycast", "High Reliability", "DDoS Hardened", "DNSSEC Validation"),
        primaryColor = Color(0xFF4285F4), // Google Blue
        accentColor = Color(0xFF8AB4F8),
        website = "https://developers.google.com/speed/public-dns",
        recommendationBadge = "GLOBAL ANYCAST RELIABILITY"
    )

    val ALL_PROVIDERS: List<DnsProvider> = listOf(
        ADGUARD,
        CLOUDFLARE_SECURITY,
        CLOUDFLARE_STANDARD,
        QUAD9,
        CONTROL_D,
        NEXTDNS,
        MULLVAD,
        GOOGLE
    )

    fun getById(id: String): DnsProvider {
        return ALL_PROVIDERS.firstOrNull { it.id.equals(id, ignoreCase = true) } ?: ADGUARD
    }
}

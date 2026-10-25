package io.threatlens.core.vpn

import androidx.compose.ui.graphics.Color

enum class DnsCategory(val label: String) {
    RECOMMENDED("⭐ Recommended"),
    SECURITY("🛡️ Threat & Malware Defense"),
    AD_BLOCKING("🚫 Ad & Tracker Blocking"),
    PRIVACY("🔒 Zero-Log Privacy"),
    FAMILY("👨‍👩‍👧 Family & Content Safety"),
    PERFORMANCE("⚡ High-Speed Anycast")
}

data class DnsProvider(
    val id: String,
    val name: String,
    val brandTag: String,
    val primaryIp: String,
    val secondaryIp: String,
    val description: String,
    val category: DnsCategory,
    val features: List<String>,
    val primaryColor: Color,
    val accentColor: Color,
    val website: String,
    val recommendationBadge: String? = null,
    val dohUrl: String? = null
)

object DnsProviders {

    // 1. ADGUARD DNS (Default Ad & Tracker Blocking)
    val ADGUARD = DnsProvider(
        id = "adguard",
        name = "AdGuard DNS",
        brandTag = "AG",
        primaryIp = "94.140.14.14",
        secondaryIp = "94.140.15.15",
        description = "World-leading privacy and ad-blocking resolver. Blocks ads, tracking domains, and malicious phishing sites.",
        category = DnsCategory.AD_BLOCKING,
        features = listOf("Ad Blocking", "Tracker Shield", "Phishing Filter", "No Logs"),
        primaryColor = Color(0xFF23A867), // Official AdGuard Emerald
        accentColor = Color(0xFF68D391),
        website = "https://adguard-dns.io",
        recommendationBadge = "RECOMMENDED DEFAULT (BALANCED)",
        dohUrl = "https://dns.adguard-dns.com/dns-query"
    )

    // 2. CLOUDFLARE 1.1.1.2 (Security / Malware Blocking)
    val CLOUDFLARE_SECURITY = DnsProvider(
        id = "cloudflare_sec",
        name = "Cloudflare 1.1.1.2",
        brandTag = "CF",
        primaryIp = "1.1.1.2",
        secondaryIp = "1.0.0.2",
        description = "Cloudflare 1.1.1.1 with automated malware and malicious link blocking powered by Cloudflare Threat Intel.",
        category = DnsCategory.SECURITY,
        features = listOf("Malware Defense", "Ultra Low Latency", "Global Anycast", "Zero Logs"),
        primaryColor = Color(0xFFF6821F), // Official Cloudflare Orange
        accentColor = Color(0xFFFFA94D),
        website = "https://1.1.1.1",
        recommendationBadge = "SUGGESTED FOR ESSENTIAL SHIELD",
        dohUrl = "https://security.cloudflare-dns.com/dns-query"
    )

    // 3. CLOUDFLARE 1.1.1.1 (Standard Raw Speed)
    val CLOUDFLARE_STANDARD = DnsProvider(
        id = "cloudflare",
        name = "Cloudflare 1.1.1.1",
        brandTag = "1.1",
        primaryIp = "1.1.1.1",
        secondaryIp = "1.0.0.1",
        description = "The Internet's fastest privacy-first DNS directory. Resolves queries at lightning speed with zero logging.",
        category = DnsCategory.PERFORMANCE,
        features = listOf("World's Fastest", "Strict Privacy", "Anycast CDN", "DNSSEC"),
        primaryColor = Color(0xFFF6821F),
        accentColor = Color(0xFFFFA94D),
        website = "https://1.1.1.1",
        recommendationBadge = "FASTEST RAW RESOLUTION",
        dohUrl = "https://cloudflare-dns.com/dns-query"
    )

    // 4. CLOUDFLARE 1.1.1.3 (Family & Adult Filter)
    val CLOUDFLARE_FAMILY = DnsProvider(
        id = "cloudflare_fam",
        name = "Cloudflare Family",
        brandTag = "1.3",
        primaryIp = "1.1.1.3",
        secondaryIp = "1.0.0.3",
        description = "Cloudflare resolver configured to block malware, phishing, and explicit adult websites automatically.",
        category = DnsCategory.FAMILY,
        features = listOf("Malware Filter", "Adult Site Blocker", "SafeSearch", "Anycast"),
        primaryColor = Color(0xFFF6821F),
        accentColor = Color(0xFF38BDF8),
        website = "https://1.1.1.1/family",
        recommendationBadge = "FAMILY & ADULT CONTENT SHIELD",
        dohUrl = "https://family.cloudflare-dns.com/dns-query"
    )

    // 5. QUAD9 SECURITY (Swiss Threat Intel)
    val QUAD9 = DnsProvider(
        id = "quad9",
        name = "Quad9 Security",
        brandTag = "Q9",
        primaryIp = "9.9.9.9",
        secondaryIp = "149.112.112.112",
        description = "Swiss non-profit foundation combining 18+ global threat intelligence feeds to block malware, phishing, and botnets.",
        category = DnsCategory.SECURITY,
        features = listOf("18+ Threat Feeds", "Swiss Privacy Laws", "Phishing Blocker", "GDPR Compliant"),
        primaryColor = Color(0xFF0A4D8C), // Official Quad9 Navy
        accentColor = Color(0xFF38BDF8),
        website = "https://quad9.net",
        recommendationBadge = "BEST SWISS THREAT INTEL",
        dohUrl = "https://dns.quad9.net/dns-query"
    )

    // 6. CONTROL D (AI Threat Filter)
    val CONTROL_D = DnsProvider(
        id = "controld",
        name = "Control D",
        brandTag = "CD",
        primaryIp = "76.76.2.1",
        secondaryIp = "76.76.10.1",
        description = "Modern secure DNS provider with AI-driven threat categorization, malware blocking, and tracking prevention.",
        category = DnsCategory.SECURITY,
        features = listOf("AI Threat Engine", "Malware Blocker", "Ad Filter", "Telemetry Shield"),
        primaryColor = Color(0xFF19B394), // Control D Teal
        accentColor = Color(0xFF2DD4BF),
        website = "https://controld.com",
        recommendationBadge = "AI-POWERED DEFENSE",
        dohUrl = "https://freedns.controld.com/p1"
    )

    // 7. NEXTDNS (Cloud Firewall)
    val NEXTDNS = DnsProvider(
        id = "nextdns",
        name = "NextDNS",
        brandTag = "NX",
        primaryIp = "45.90.28.0",
        secondaryIp = "45.90.30.0",
        description = "Next-generation cloud firewall protecting against cyber threats, native tracking, and intrusive advertising.",
        category = DnsCategory.AD_BLOCKING,
        features = listOf("Cloud Firewall", "Tracker Blocker", "Phishing Guard", "DNS-over-HTTPS"),
        primaryColor = Color(0xFF1084FF), // NextDNS Blue
        accentColor = Color(0xFF60A5FA),
        website = "https://nextdns.io",
        recommendationBadge = "CLOUD FIREWALL SHIELD",
        dohUrl = "https://dns.nextdns.io/dns-query"
    )

    // 8. MULLVAD DNS (Swedish Zero-Log Privacy)
    val MULLVAD = DnsProvider(
        id = "mullvad",
        name = "Mullvad DNS",
        brandTag = "MV",
        primaryIp = "194.242.2.4",
        secondaryIp = "194.242.2.5",
        description = "High-security Swedish privacy resolver. Strictly no logs, audited infrastructure, and ad/tracker blocking.",
        category = DnsCategory.PRIVACY,
        features = listOf("Swedish Privacy", "Strict Zero Logs", "Ad & Tracker Shield", "Audited"),
        primaryColor = Color(0xFFE5B324), // Mullvad Yellow
        accentColor = Color(0xFFFDE047),
        website = "https://mullvad.net",
        recommendationBadge = "SUGGESTED FOR ZERO-TRUST FORTRESS",
        dohUrl = "https://dns.mullvad.net/dns-query"
    )

    // 9. CISCO OPENDNS (Enterprise Phishing & Botnet Shield)
    val OPENDNS = DnsProvider(
        id = "opendns",
        name = "Cisco OpenDNS",
        brandTag = "OD",
        primaryIp = "208.67.222.222",
        secondaryIp = "208.67.220.220",
        description = "Cisco Umbrella's reliable global DNS blocking phishing websites, malware distributors, and rogue botnets.",
        category = DnsCategory.SECURITY,
        features = listOf("Cisco Umbrella Intel", "Phishing Shield", "Botnet Protection", "High Uptime"),
        primaryColor = Color(0xFF049FD9), // Cisco Blue
        accentColor = Color(0xFF67D8EF),
        website = "https://www.opendns.com",
        recommendationBadge = "CISCO UMBRELLA THREAT DEFENSE",
        dohUrl = "https://doh.opendns.com/dns-query"
    )

    // 10. RETHINKDNS (Open-Source Android Project)
    val RETHINK_DNS = DnsProvider(
        id = "rethinkdns",
        name = "RethinkDNS",
        brandTag = "RD",
        primaryIp = "104.28.2.1",
        secondaryIp = "104.28.3.1",
        description = "Open-source privacy and censorship-resistant DNS resolver backed by the Mozilla Foundation and freedom projects.",
        category = DnsCategory.PRIVACY,
        features = listOf("Open Source", "Anti-Censorship", "Cryptographic Validation", "Zero Telemetry"),
        primaryColor = Color(0xFF7C3AED), // Rethink Purple
        accentColor = Color(0xFFA78BFA),
        website = "https://rethinkdns.com",
        recommendationBadge = "OPEN-SOURCE PRIVACY CHAMPION",
        dohUrl = "https://max.rethinkdns.com/dns-query"
    )

    // 11. CLEANBROWSING SECURITY (Security & Phishing Filter)
    val CLEANBROWSING = DnsProvider(
        id = "cleanbrowsing",
        name = "CleanBrowsing",
        brandTag = "CB",
        primaryIp = "185.228.168.9",
        secondaryIp = "185.228.169.9",
        description = "Security-focused Anycast resolver that blocks phishing, malware, ransomware, and malicious redirect scripts.",
        category = DnsCategory.SECURITY,
        features = listOf("Malware Sinkhole", "Ransomware Defense", "Anti-Phishing", "DNSSEC"),
        primaryColor = Color(0xFF2563EB), // CleanBrowsing Blue
        accentColor = Color(0xFF93C5FD),
        website = "https://cleanbrowsing.org",
        recommendationBadge = "DEDICATED SECURITY SINKHOLE",
        dohUrl = "https://doh.cleanbrowsing.org/doh/security-filter/"
    )

    // 12. DNS.SB (Non-Profit Zero-Log European Anycast)
    val DNS_SB = DnsProvider(
        id = "dnssb",
        name = "DNS.SB",
        brandTag = "SB",
        primaryIp = "185.222.222.222",
        secondaryIp = "45.11.45.11",
        description = "European non-profit DNS network with zero logging, DNSSEC enforcement, and no commercial tracking.",
        category = DnsCategory.PRIVACY,
        features = listOf("European Privacy", "Zero-Log Policy", "DNSSEC Verified", "Non-Profit"),
        primaryColor = Color(0xFF059669), // SB Forest Green
        accentColor = Color(0xFF34D399),
        website = "https://dns.sb",
        recommendationBadge = "EU INDEPENDENT NON-PROFIT",
        dohUrl = "https://doh.dns.sb/dns-query"
    )

    // 13. COMODO SECURE DNS (Enterprise Threat Sinkhole)
    val COMODO = DnsProvider(
        id = "comodo",
        name = "Comodo Secure",
        brandTag = "CM",
        primaryIp = "8.26.56.26",
        secondaryIp = "8.20.247.20",
        description = "Comodo CyberSecurity Anycast DNS with multi-layer threat filtering against malware and spyware.",
        category = DnsCategory.SECURITY,
        features = listOf("Comodo Valkyrie Intel", "Spyware Blocker", "DDoS Hardened", "Anycast Routing"),
        primaryColor = Color(0xFFDC2626), // Comodo Red
        accentColor = Color(0xFFF87171),
        website = "https://www.comodo.com/secure-dns",
        recommendationBadge = "ENTERPRISE THREAT INTELLIGENCE",
        dohUrl = null
    )

    // 14. LIBREDNS (German Privacy Activist DNS)
    val LIBREDNS = DnsProvider(
        id = "libredns",
        name = "LibreDNS",
        brandTag = "LD",
        primaryIp = "116.202.176.26",
        secondaryIp = "116.202.176.26",
        description = "German non-profit public DNS service emphasizing digital autonomy, zero tracking, and freedom.",
        category = DnsCategory.PRIVACY,
        features = listOf("Digital Rights Activism", "No User Profiling", "GDPR Native", "Censorship-Resistant"),
        primaryColor = Color(0xFFD97706), // Libre Amber
        accentColor = Color(0xFFFBBF24),
        website = "https://libredns.gr",
        recommendationBadge = "PRIVACY ACTIVIST RESOLVER",
        dohUrl = "https://doh.libredns.gr/dns-query"
    )

    // 15. GOOGLE PUBLIC DNS (Global Anycast)
    val GOOGLE = DnsProvider(
        id = "google",
        name = "Google Public DNS",
        brandTag = "G",
        primaryIp = "8.8.8.8",
        secondaryIp = "8.8.4.4",
        description = "Global anycast DNS infrastructure with worldwide low-latency resolution and robust DDoS mitigation.",
        category = DnsCategory.PERFORMANCE,
        features = listOf("Global Anycast", "High Reliability", "DDoS Hardened", "DNSSEC Validation"),
        primaryColor = Color(0xFF4285F4), // Google Blue
        accentColor = Color(0xFF8AB4F8),
        website = "https://developers.google.com/speed/public-dns",
        recommendationBadge = "GLOBAL ANYCAST RELIABILITY",
        dohUrl = "https://dns.google/dns-query"
    )

    val ALL_PROVIDERS: List<DnsProvider> = listOf(
        ADGUARD,
        CLOUDFLARE_SECURITY,
        CLOUDFLARE_STANDARD,
        CLOUDFLARE_FAMILY,
        QUAD9,
        CONTROL_D,
        NEXTDNS,
        MULLVAD,
        OPENDNS,
        RETHINK_DNS,
        CLEANBROWSING,
        DNS_SB,
        COMODO,
        LIBREDNS,
        GOOGLE
    )

    fun getById(id: String): DnsProvider {
        return ALL_PROVIDERS.firstOrNull { it.id.equals(id, ignoreCase = true) } ?: ADGUARD
    }
}

package io.threatlens.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.threatlens.ui.theme.*

data class EngineBrand(
    val name: String,
    val primaryColor: Color,
    val accentColor: Color,
    val icon: ImageVector,
    val initials: String
)

object EngineRegistry {
    // CLOUD SCANNERS
    val VIRUSTOTAL = EngineBrand(
        name = "VirusTotal",
        primaryColor = Color(0xFF0058FF),
        accentColor = Color(0xFF00E5FF),
        icon = Icons.Default.AllInclusive,
        initials = "VT"
    )

    val HYBRID_ANALYSIS = EngineBrand(
        name = "Hybrid Analysis",
        primaryColor = Color(0xFF0284C7),
        accentColor = Color(0xFF38BDF8),
        icon = Icons.Default.RemoveRedEye,
        initials = "HA"
    )

    val KASPERSKY = EngineBrand(
        name = "Kaspersky OpenTIP",
        primaryColor = Color(0xFF00A88E),
        accentColor = Color(0xFF00E676),
        icon = Icons.Default.Shield,
        initials = "K"
    )

    val METADEFENDER = EngineBrand(
        name = "MetaDefender",
        primaryColor = Color(0xFFEA580C),
        accentColor = Color(0xFF3B82F6),
        icon = Icons.Default.Hub,
        initials = "MD"
    )

    val MALWARE_BAZAAR = EngineBrand(
        name = "MalwareBazaar",
        primaryColor = Color(0xFFEAB308),
        accentColor = Color(0xFFCA8A04),
        icon = Icons.Default.BugReport,
        initials = "MB"
    )

    val FILESCAN = EngineBrand(
        name = "Filescan.io",
        primaryColor = Color(0xFF9333EA),
        accentColor = Color(0xFFA855F7),
        icon = Icons.Default.Radar,
        initials = "FS"
    )

    val ALIENVAULT_OTX = EngineBrand(
        name = "AlienVault OTX",
        primaryColor = Color(0xFF0284C7),
        accentColor = Color(0xFF38BDF8),
        icon = Icons.Default.Public,
        initials = "OTX"
    )

    val CIRCL_LU = EngineBrand(
        name = "CIRCL Hashlookup",
        primaryColor = Color(0xFF0D9488),
        accentColor = Color(0xFF14B8A6),
        icon = Icons.Default.GppGood,
        initials = "CRC"
    )

    val THREATLENS_LOCAL = EngineBrand(
        name = "ThreatLens Local Engine",
        primaryColor = Color(0xFF00E5FF),
        accentColor = Color(0xFF0066FF),
        icon = Icons.Default.Shield,
        initials = "TL"
    )

    // AI THREAT EXPLAINERS
    val OPENAI_CHATGPT = EngineBrand(
        name = "ChatGPT (OpenAI)",
        primaryColor = Color(0xFF10A37F), // Official OpenAI Teal
        accentColor = Color(0xFF19C37D),
        icon = Icons.Default.Psychology,
        initials = "GPT"
    )

    val ANTHROPIC_CLAUDE = EngineBrand(
        name = "Claude (Anthropic)",
        primaryColor = Color(0xFFCC785C), // Official Anthropic Terracotta
        accentColor = Color(0xFFE08D79),
        icon = Icons.Default.WbSunny,
        initials = "CLA"
    )

    val GEMINI_AI = EngineBrand(
        name = "Google Gemini",
        primaryColor = Color(0xFF4285F4),
        accentColor = Color(0xFF9B72CF),
        icon = Icons.Default.AutoAwesome,
        initials = "✦"
    )

    val GROQ_AI = EngineBrand(
        name = "Groq Cloud",
        primaryColor = Color(0xFFF97316),
        accentColor = Color(0xFFFB923C),
        icon = Icons.Default.Bolt,
        initials = "⚡"
    )

    fun getBrand(name: String): EngineBrand {
        val lower = name.lowercase()
        return when {
            lower.contains("chatgpt") || lower.contains("openai") || lower.contains("gpt") -> OPENAI_CHATGPT
            lower.contains("claude") || lower.contains("anthropic") -> ANTHROPIC_CLAUDE
            lower.contains("virustotal") || lower.contains("vt") -> VIRUSTOTAL
            lower.contains("hybrid") -> HYBRID_ANALYSIS
            lower.contains("kaspersky") -> KASPERSKY
            lower.contains("metadefender") -> METADEFENDER
            lower.contains("bazaar") -> MALWARE_BAZAAR
            lower.contains("filescan") -> FILESCAN
            lower.contains("alienvault") || lower.contains("otx") -> ALIENVAULT_OTX
            lower.contains("circl") || lower.contains("hashlookup") -> CIRCL_LU
            lower.contains("threatlens") || lower.contains("local") -> THREATLENS_LOCAL
            lower.contains("gemini") -> GEMINI_AI
            lower.contains("groq") -> GROQ_AI
            else -> EngineBrand(name, NeonCyan, CyberAmber, Icons.Default.Security, "AV")
        }
    }
}

@Composable
fun EngineLogoIcon(
    engineName: String,
    modifier: Modifier = Modifier.size(24.dp)
) {
    val brand = EngineRegistry.getBrand(engineName)
    Box(
        modifier = modifier
            .background(
                Brush.linearGradient(listOf(brand.primaryColor, brand.accentColor)),
                CircleShape
            )
            .border(1.dp, Color.White.copy(alpha = 0.25f), CircleShape),
        contentAlignment = Alignment.Center
    ) {
        Icon(
            imageVector = brand.icon,
            contentDescription = brand.name,
            tint = Color.White,
            modifier = Modifier.size(13.dp)
        )
    }
}

@Composable
fun EngineStatusBadge(
    engineName: String,
    detailText: String? = null,
    isFlagged: Boolean = false,
    isPending: Boolean = false,
    modifier: Modifier = Modifier
) {
    val brand = EngineRegistry.getBrand(engineName)
    val borderColor = when {
        isPending -> CyberCardBorder
        isFlagged -> NeonCrimson
        else -> NeonEmerald
    }

    Surface(
        modifier = modifier,
        color = CyberCardSurface,
        shape = RoundedCornerShape(10.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, borderColor.copy(alpha = 0.7f))
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            EngineLogoIcon(engineName = engineName, modifier = Modifier.size(20.dp))
            Spacer(modifier = Modifier.width(8.dp))
            Column {
                Text(
                    text = brand.name,
                    color = TextPrimary,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold
                )
                if (isPending) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(8.dp),
                            strokeWidth = 1.2.dp,
                            color = NeonCyan
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(
                            text = "Awaiting response...",
                            color = TextMuted,
                            fontSize = 10.sp
                        )
                    }
                } else if (!detailText.isNullOrBlank()) {
                    Text(
                        text = detailText,
                        color = if (isFlagged) NeonCrimson else NeonEmerald,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Medium
                    )
                }
            }
        }
    }
}

data class VendorBrand(
    val name: String,
    val color: Color,
    val initials: String,
    val icon: ImageVector = Icons.Default.Shield
)

object SubEngineRegistry {
    private val VENDORS = listOf(
        VendorBrand("Kaspersky", Color(0xFF00A88E), "K"),
        VendorBrand("Microsoft", Color(0xFF00A4EF), "MS"),
        VendorBrand("WindowsDefender", Color(0xFF00A4EF), "MS"),
        VendorBrand("Defender", Color(0xFF00A4EF), "MS"),
        VendorBrand("Avast", Color(0xFFFF7800), "AV"),
        VendorBrand("AVG", Color(0xFFFF7800), "AVG"),
        VendorBrand("Bitdefender", Color(0xFFED1C24), "BD"),
        VendorBrand("ESET", Color(0xFF00838F), "ESET"),
        VendorBrand("ESET-NOD32", Color(0xFF00838F), "ESET"),
        VendorBrand("Sophos", Color(0xFF0058A3), "SPH"),
        VendorBrand("Google", Color(0xFF4285F4), "G"),
        VendorBrand("PlayProtect", Color(0xFF4285F4), "G"),
        VendorBrand("Symantec", Color(0xFFEDB111), "SYM"),
        VendorBrand("Broadcom", Color(0xFFEDB111), "SYM"),
        VendorBrand("TrendMicro", Color(0xFFD81B60), "TM"),
        VendorBrand("McAfee", Color(0xFFC01818), "MC"),
        VendorBrand("Fortinet", Color(0xFFDA291C), "FT"),
        VendorBrand("ClamAV", Color(0xFF1E88E5), "CLAM"),
        VendorBrand("AhnLab", Color(0xFF005BAC), "AHN"),
        VendorBrand("F-Secure", Color(0xFF0072CE), "FS"),
        VendorBrand("Malwarebytes", Color(0xFF0073D1), "MB"),
        VendorBrand("SentinelOne", Color(0xFF4E2A84), "S1"),
        VendorBrand("CrowdStrike", Color(0xFFE2231A), "CS"),
        VendorBrand("DrWeb", Color(0xFF43A047), "DRW"),
        VendorBrand("QuickHeal", Color(0xFFFF6F00), "QH"),
        VendorBrand("Tencent", Color(0xFF12B7F5), "TC"),
        VendorBrand("Yandex", Color(0xFFFF0000), "YA"),
        VendorBrand("WithSecure", Color(0xFF0072CE), "WS"),
        VendorBrand("Avira", Color(0xFFD32F2F), "AVR"),
        VendorBrand("Ikarus", Color(0xFF388E3C), "IKR")
    )

    fun getVendorBrand(name: String): VendorBrand {
        val clean = name.trim().lowercase()
        return VENDORS.firstOrNull { clean.contains(it.name.lowercase()) }
            ?: VendorBrand(
                name = name.trim(),
                color = Color(0xFF64748B),
                initials = name.trim().take(3).uppercase()
            )
    }
}

@Composable
fun VendorFindingBadge(
    item: String,
    isMalicious: Boolean = true,
    modifier: Modifier = Modifier
) {
    val colonIndex = item.indexOf(':')
    if (colonIndex > 0) {
        val vendorName = item.substring(0, colonIndex).trim()
        val findingText = item.substring(colonIndex + 1).trim()
        val vendor = SubEngineRegistry.getVendorBrand(vendorName)

        Surface(
            modifier = modifier.fillMaxWidth(),
            color = CyberDarkSurface,
            shape = RoundedCornerShape(6.dp),
            border = androidx.compose.foundation.BorderStroke(1.dp, vendor.color.copy(alpha = 0.4f))
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Sub-engine logo badge
                Box(
                    modifier = Modifier
                        .size(22.dp)
                        .background(vendor.color.copy(alpha = 0.2f), CircleShape)
                        .border(1.dp, vendor.color, CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    if (vendor.initials.length <= 2) {
                        Text(
                            text = vendor.initials,
                            color = vendor.color,
                            fontSize = 9.sp,
                            fontWeight = FontWeight.Bold
                        )
                    } else {
                        Icon(
                            imageVector = vendor.icon,
                            contentDescription = vendorName,
                            tint = vendor.color,
                            modifier = Modifier.size(12.dp)
                        )
                    }
                }
                Spacer(modifier = Modifier.width(8.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = vendorName,
                        color = Color.White,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = findingText,
                        color = if (isMalicious) NeonCrimson else CyberAmber,
                        fontSize = 10.sp,
                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                        maxLines = 2,
                        overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
                    )
                }
            }
        }
    } else {
        // Non-vendor line (e.g. general intelligence finding)
        Row(
            modifier = modifier.fillMaxWidth().padding(vertical = 2.dp),
            verticalAlignment = Alignment.Top
        ) {
            Text(
                text = "• ",
                color = if (isMalicious) NeonCrimson else NeonEmerald,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold
            )
            Text(
                text = item,
                color = TextPrimary,
                fontSize = 11.sp,
                fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                lineHeight = 15.sp
            )
        }
    }
}

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

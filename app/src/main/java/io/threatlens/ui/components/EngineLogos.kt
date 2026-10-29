package io.threatlens.ui.components

import androidx.compose.foundation.Canvas
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
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.threatlens.ui.theme.*

data class EngineBrand(
    val name: String,
    val brandKey: String,
    val primaryColor: Color,
    val accentColor: Color,
    val icon: ImageVector,
    val initials: String
)

object EngineRegistry {
    // CLOUD SCANNERS
    val VIRUSTOTAL = EngineBrand(
        name = "VirusTotal",
        brandKey = "VirusTotal",
        primaryColor = Color(0xFF0058FF),
        accentColor = Color(0xFF00E5FF),
        icon = Icons.Default.AllInclusive,
        initials = "VT"
    )

    val HYBRID_ANALYSIS = EngineBrand(
        name = "Hybrid Analysis",
        brandKey = "HybridAnalysis",
        primaryColor = Color(0xFF0284C7),
        accentColor = Color(0xFF38BDF8),
        icon = Icons.Default.RemoveRedEye,
        initials = "HA"
    )

    val KASPERSKY = EngineBrand(
        name = "Kaspersky OpenTIP",
        brandKey = "Kaspersky",
        primaryColor = Color(0xFF00A88E),
        accentColor = Color(0xFF00E676),
        icon = Icons.Default.Shield,
        initials = "K"
    )

    val METADEFENDER = EngineBrand(
        name = "MetaDefender",
        brandKey = "MetaDefender",
        primaryColor = Color(0xFFEA580C),
        accentColor = Color(0xFF3B82F6),
        icon = Icons.Default.Hub,
        initials = "MD"
    )

    val MALWARE_BAZAAR = EngineBrand(
        name = "MalwareBazaar",
        brandKey = "MalwareBazaar",
        primaryColor = Color(0xFFEAB308),
        accentColor = Color(0xFFCA8A04),
        icon = Icons.Default.BugReport,
        initials = "MB"
    )

    val FILESCAN = EngineBrand(
        name = "Filescan.io",
        brandKey = "Filescan",
        primaryColor = Color(0xFF9333EA),
        accentColor = Color(0xFFA855F7),
        icon = Icons.Default.Radar,
        initials = "FS"
    )

    val ALIENVAULT_OTX = EngineBrand(
        name = "AlienVault OTX",
        brandKey = "AlienVault",
        primaryColor = Color(0xFF0284C7),
        accentColor = Color(0xFF38BDF8),
        icon = Icons.Default.Public,
        initials = "OTX"
    )

    val CIRCL_LU = EngineBrand(
        name = "CIRCL Hashlookup",
        brandKey = "CIRCL",
        primaryColor = Color(0xFF0D9488),
        accentColor = Color(0xFF14B8A6),
        icon = Icons.Default.GppGood,
        initials = "CRC"
    )

    // LOCAL SCANNING ENGINES
    val THREATLENS_LOCAL = EngineBrand(
        name = "ThreatLens Behavioral Heuristics",
        brandKey = "ThreatLensLocal",
        primaryColor = Color(0xFF00E5FF),
        accentColor = Color(0xFF0066FF),
        icon = Icons.Default.Shield,
        initials = "TL"
    )

    val CLAMAV = EngineBrand(
        name = "ClamAV Open Source Engine",
        brandKey = "ClamAV",
        primaryColor = Color(0xFFE65100),
        accentColor = Color(0xFFF59E0B),
        icon = Icons.Default.Security,
        initials = "CLAM"
    )

    val YARA = EngineBrand(
        name = "YARA Mobile Threat Rules",
        brandKey = "YARA",
        primaryColor = Color(0xFFDC2626),
        accentColor = Color(0xFFEF4444),
        icon = Icons.Default.Radar,
        initials = "YARA"
    )

    val CERT_SHIELD = EngineBrand(
        name = "ThreatLens Certificate & Repack Shield",
        brandKey = "ThreatLensCert",
        primaryColor = Color(0xFF7C3AED),
        accentColor = Color(0xFF8B5CF6),
        icon = Icons.Default.VerifiedUser,
        initials = "CERT"
    )

    val PACKER_SHIELD = EngineBrand(
        name = "ThreatLens Anti-Analysis & Packer Shield",
        brandKey = "ThreatLensPacker",
        primaryColor = Color(0xFF059669),
        accentColor = Color(0xFF10B981),
        icon = Icons.Default.Layers,
        initials = "PACK"
    )

    val SIGNATURE_DB = EngineBrand(
        name = "ThreatLens Offline Signature DB",
        brandKey = "ThreatLensSigDb",
        primaryColor = Color(0xFF2563EB),
        accentColor = Color(0xFF3B82F6),
        icon = Icons.Default.Storage,
        initials = "SIG"
    )

    // AI THREAT EXPLAINERS
    val OPENAI_CHATGPT = EngineBrand(
        name = "ChatGPT (OpenAI)",
        brandKey = "ChatGPT",
        primaryColor = Color(0xFF10A37F),
        accentColor = Color(0xFF19C37D),
        icon = Icons.Default.Psychology,
        initials = "GPT"
    )

    val ANTHROPIC_CLAUDE = EngineBrand(
        name = "Claude (Anthropic)",
        brandKey = "Claude",
        primaryColor = Color(0xFFCC785C),
        accentColor = Color(0xFFE08D79),
        icon = Icons.Default.WbSunny,
        initials = "CLA"
    )

    val GEMINI_AI = EngineBrand(
        name = "Google Gemini",
        brandKey = "Gemini",
        primaryColor = Color(0xFF4285F4),
        accentColor = Color(0xFF9B72CF),
        icon = Icons.Default.AutoAwesome,
        initials = "✦"
    )

    val GROQ_AI = EngineBrand(
        name = "Groq Cloud",
        brandKey = "Groq",
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
            lower.contains("gemini") -> GEMINI_AI
            lower.contains("groq") -> GROQ_AI
            lower.contains("virustotal") || lower.contains("vt") -> VIRUSTOTAL
            lower.contains("hybrid") -> HYBRID_ANALYSIS
            lower.contains("kaspersky") -> KASPERSKY
            lower.contains("metadefender") -> METADEFENDER
            lower.contains("bazaar") -> MALWARE_BAZAAR
            lower.contains("filescan") -> FILESCAN
            lower.contains("alienvault") || lower.contains("otx") -> ALIENVAULT_OTX
            lower.contains("circl") || lower.contains("hashlookup") -> CIRCL_LU
            lower.contains("clamav") -> CLAMAV
            lower.contains("yara") -> YARA
            lower.contains("cert") || lower.contains("repack") -> CERT_SHIELD
            lower.contains("packer") || lower.contains("entropy") -> PACKER_SHIELD
            lower.contains("signature db") || lower.contains("offline signature") -> SIGNATURE_DB
            lower.contains("threatlens") || lower.contains("local") || lower.contains("behavioral") -> THREATLENS_LOCAL
            else -> EngineBrand(name, "Generic", NeonCyan, CyberAmber, Icons.Default.Security, "AV")
        }
    }
}

// ---------------------------------------------------------------------------
// AUTHENTIC BRAND LOGOS (VECTOR CANVAS EMBLEMS)
// ---------------------------------------------------------------------------

@Composable
fun VirusTotalLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        // Blue shield/rounded container
        drawRoundRect(
            color = Color(0xFF0058FF),
            cornerRadius = CornerRadius(w * 0.28f, h * 0.28f)
        )
        // Original VirusTotal geometric loop (stylized V and T polygon ribbon)
        val path = Path().apply {
            moveTo(w * 0.26f, h * 0.30f)
            lineTo(w * 0.46f, h * 0.70f)
            lineTo(w * 0.62f, h * 0.38f)
            lineTo(w * 0.74f, h * 0.38f)
            lineTo(w * 0.50f, h * 0.78f)
            lineTo(w * 0.38f, h * 0.78f)
            lineTo(w * 0.16f, h * 0.30f)
            close()
        }
        drawPath(path, Color.White)

        // Top horizontal T-bar
        val barPath = Path().apply {
            moveTo(w * 0.52f, h * 0.30f)
            lineTo(w * 0.84f, h * 0.30f)
            lineTo(w * 0.80f, h * 0.40f)
            lineTo(w * 0.48f, h * 0.40f)
            close()
        }
        drawPath(barPath, Color(0xFF00E5FF))
    }
}

@Composable
fun NortonLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        // Iconic Norton Golden Yellow Circle
        drawCircle(
            color = Color(0xFFFDB813),
            radius = w * 0.48f,
            center = Offset(w * 0.5f, h * 0.5f)
        )
        // Authentic black Norton checkmark with hook
        val check = Path().apply {
            moveTo(w * 0.25f, h * 0.52f)
            lineTo(w * 0.44f, h * 0.74f)
            lineTo(w * 0.78f, h * 0.28f)
        }
        drawPath(
            path = check,
            color = Color(0xFF1E1E1E),
            style = Stroke(width = w * 0.14f, cap = StrokeCap.Round)
        )
    }
}

@Composable
fun BitdefenderLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        // Bitdefender Iconic Red Background
        drawRoundRect(
            color = Color(0xFFED1C24),
            cornerRadius = CornerRadius(w * 0.26f, h * 0.26f)
        )
        // White Bitdefender Flame / Stylized Dragon B
        val flame = Path().apply {
            moveTo(w * 0.28f, h * 0.24f)
            lineTo(w * 0.56f, h * 0.24f)
            cubicTo(w * 0.76f, h * 0.24f, w * 0.78f, h * 0.46f, w * 0.60f, h * 0.50f)
            cubicTo(w * 0.82f, h * 0.54f, w * 0.78f, h * 0.76f, w * 0.54f, h * 0.76f)
            lineTo(w * 0.28f, h * 0.76f)
            close()
        }
        drawPath(flame, Color.White)

        // Flame cut-outs inside
        drawCircle(Color(0xFFED1C24), radius = w * 0.08f, center = Offset(w * 0.46f, h * 0.38f))
        drawCircle(Color(0xFFED1C24), radius = w * 0.09f, center = Offset(w * 0.46f, h * 0.62f))
    }
}

@Composable
fun MicrosoftDefenderLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        // Dark blue shield backdrop
        drawRoundRect(
            color = Color(0xFF0F172A),
            cornerRadius = CornerRadius(w * 0.24f, h * 0.24f)
        )
        // 4 Official Microsoft colored squares
        val gap = w * 0.06f
        val sq = w * 0.22f
        val left = w * 0.24f
        val top = h * 0.24f

        // Red (Top-left)
        drawRect(Color(0xFFF25022), topLeft = Offset(left, top), size = Size(sq, sq))
        // Green (Top-right)
        drawRect(Color(0xFF7FBA00), topLeft = Offset(left + sq + gap, top), size = Size(sq, sq))
        // Blue (Bottom-left)
        drawRect(Color(0xFF00A4EF), topLeft = Offset(left, top + sq + gap), size = Size(sq, sq))
        // Yellow (Bottom-right)
        drawRect(Color(0xFFFFB900), topLeft = Offset(left + sq + gap, top + sq + gap), size = Size(sq, sq))
    }
}

@Composable
fun KasperskyLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        // Kaspersky Emerald Green
        drawRoundRect(
            color = Color(0xFF00A88E),
            cornerRadius = CornerRadius(w * 0.26f, h * 0.26f)
        )
        // Sharp Geometric Kaspersky 'K'
        val path = Path().apply {
            // Left vertical pillar
            moveTo(w * 0.28f, h * 0.24f)
            lineTo(w * 0.40f, h * 0.24f)
            lineTo(w * 0.40f, h * 0.76f)
            lineTo(w * 0.28f, h * 0.76f)
            close()
            // Upper diagonal arm
            moveTo(w * 0.44f, h * 0.54f)
            lineTo(w * 0.66f, h * 0.24f)
            lineTo(w * 0.78f, h * 0.24f)
            lineTo(w * 0.52f, h * 0.58f)
            close()
            // Lower diagonal arm
            moveTo(w * 0.50f, h * 0.52f)
            lineTo(w * 0.78f, h * 0.76f)
            lineTo(w * 0.65f, h * 0.76f)
            lineTo(w * 0.42f, h * 0.57f)
            close()
        }
        drawPath(path, Color.White)
    }
}

@Composable
fun AvastLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        // Avast Orange
        drawRoundRect(
            color = Color(0xFFFF7800),
            cornerRadius = CornerRadius(w * 0.35f, h * 0.35f)
        )
        // White lowercase 'a' emblem
        val path = Path().apply {
            moveTo(w * 0.64f, h * 0.36f)
            lineTo(w * 0.64f, h * 0.70f)
            lineTo(w * 0.52f, h * 0.70f)
            lineTo(w * 0.52f, h * 0.62f)
            cubicTo(w * 0.46f, h * 0.72f, w * 0.32f, h * 0.72f, w * 0.30f, h * 0.56f)
            cubicTo(w * 0.28f, h * 0.42f, w * 0.42f, h * 0.38f, w * 0.60f, h * 0.38f)
            close()
        }
        drawPath(path, Color.White)
        drawCircle(Color(0xFFFF7800), radius = w * 0.08f, center = Offset(w * 0.45f, h * 0.53f))
    }
}

@Composable
fun EsetLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        // ESET Cyan / Teal
        drawRoundRect(
            color = Color(0xFF00838F),
            cornerRadius = CornerRadius(w * 0.28f, h * 0.28f)
        )
        // Stylized white 'e' / cyborg shield eye
        val path = Path().apply {
            moveTo(w * 0.26f, h * 0.50f)
            lineTo(w * 0.74f, h * 0.50f)
            cubicTo(w * 0.74f, h * 0.32f, w * 0.62f, h * 0.26f, w * 0.50f, h * 0.26f)
            cubicTo(w * 0.34f, h * 0.26f, w * 0.26f, h * 0.38f, w * 0.26f, h * 0.50f)
            cubicTo(w * 0.26f, h * 0.66f, w * 0.36f, h * 0.74f, w * 0.52f, h * 0.74f)
            cubicTo(w * 0.64f, h * 0.74f, w * 0.70f, h * 0.68f, w * 0.72f, h * 0.64f)
        }
        drawPath(path, Color.White, style = Stroke(width = w * 0.11f, cap = StrokeCap.Round))
    }
}

@Composable
fun McAfeeLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        // McAfee Crimson Red Shield
        val shield = Path().apply {
            moveTo(w * 0.50f, h * 0.14f)
            lineTo(w * 0.86f, h * 0.26f)
            lineTo(w * 0.86f, h * 0.56f)
            cubicTo(w * 0.86f, h * 0.78f, w * 0.50f, h * 0.90f, w * 0.50f, h * 0.90f)
            cubicTo(w * 0.50f, h * 0.90f, w * 0.14f, h * 0.78f, w * 0.14f, h * 0.56f)
            lineTo(w * 0.14f, h * 0.26f)
            close()
        }
        drawPath(shield, Color(0xFFC01818))

        // White McAfee stylized angular 'M'
        val mPath = Path().apply {
            moveTo(w * 0.28f, h * 0.68f)
            lineTo(w * 0.28f, h * 0.36f)
            lineTo(w * 0.50f, h * 0.54f)
            lineTo(w * 0.72f, h * 0.36f)
            lineTo(w * 0.72f, h * 0.68f)
        }
        drawPath(mPath, Color.White, style = Stroke(width = w * 0.11f, cap = StrokeCap.Round))
    }
}

@Composable
fun SophosLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawRoundRect(
            color = Color(0xFF0058A3),
            cornerRadius = CornerRadius(w * 0.26f, h * 0.26f)
        )
        // Bold white 'S'
        val sPath = Path().apply {
            moveTo(w * 0.68f, h * 0.36f)
            cubicTo(w * 0.60f, h * 0.26f, w * 0.36f, h * 0.26f, w * 0.36f, h * 0.40f)
            cubicTo(w * 0.36f, h * 0.52f, w * 0.64f, h * 0.52f, w * 0.64f, h * 0.64f)
            cubicTo(w * 0.64f, h * 0.76f, w * 0.40f, h * 0.76f, w * 0.32f, h * 0.66f)
        }
        drawPath(sPath, Color.White, style = Stroke(width = w * 0.13f, cap = StrokeCap.Round))
    }
}

@Composable
fun GoogleProtectLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        // Google Play Protect 4-color Shield
        val shield = Path().apply {
            moveTo(w * 0.50f, h * 0.12f)
            lineTo(w * 0.86f, h * 0.24f)
            lineTo(w * 0.86f, h * 0.54f)
            cubicTo(w * 0.86f, h * 0.76f, w * 0.50f, h * 0.88f, w * 0.50f, h * 0.88f)
            cubicTo(w * 0.50f, h * 0.88f, w * 0.14f, h * 0.76f, w * 0.14f, h * 0.54f)
            lineTo(w * 0.14f, h * 0.24f)
            close()
        }
        drawPath(shield, Color(0xFF4285F4))

        // Inner checkmark
        val check = Path().apply {
            moveTo(w * 0.32f, h * 0.50f)
            lineTo(w * 0.46f, h * 0.64f)
            lineTo(w * 0.68f, h * 0.36f)
        }
        drawPath(check, Color(0xFF34A853), style = Stroke(width = w * 0.12f, cap = StrokeCap.Round))
    }
}

@Composable
fun TrendMicroLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawCircle(Color(0xFFD71920), radius = w * 0.48f, center = Offset(w * 0.5f, h * 0.5f))
        // White dynamic crescent / swoop
        val arc = Path().apply {
            moveTo(w * 0.70f, h * 0.30f)
            cubicTo(w * 0.32f, h * 0.24f, w * 0.24f, h * 0.62f, w * 0.48f, h * 0.76f)
            cubicTo(w * 0.72f, h * 0.84f, w * 0.80f, h * 0.62f, w * 0.76f, h * 0.50f)
        }
        drawPath(arc, Color.White, style = Stroke(width = w * 0.12f, cap = StrokeCap.Round))
    }
}

@Composable
fun MalwarebytesLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawRoundRect(Color(0xFF0073D1), cornerRadius = CornerRadius(w * 0.26f, h * 0.26f))
        // Sharp white 'M'
        val path = Path().apply {
            moveTo(w * 0.26f, h * 0.72f)
            lineTo(w * 0.26f, h * 0.28f)
            lineTo(w * 0.50f, h * 0.52f)
            lineTo(w * 0.74f, h * 0.28f)
            lineTo(w * 0.74f, h * 0.72f)
        }
        drawPath(path, Color.White, style = Stroke(width = w * 0.12f, cap = StrokeCap.Round))
    }
}

@Composable
fun ClamAvLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawRoundRect(Color(0xFFE65100), cornerRadius = CornerRadius(w * 0.28f, h * 0.28f))
        // Clam shell radiating fan
        val shell = Path().apply {
            moveTo(w * 0.50f, h * 0.76f)
            lineTo(w * 0.24f, h * 0.38f)
            cubicTo(w * 0.34f, h * 0.24f, w * 0.66f, h * 0.24f, w * 0.76f, h * 0.38f)
            close()
        }
        drawPath(shell, Color.White)
        drawLine(Color(0xFFE65100), start = Offset(w * 0.50f, h * 0.76f), end = Offset(w * 0.50f, h * 0.26f), strokeWidth = w * 0.05f)
        drawLine(Color(0xFFE65100), start = Offset(w * 0.50f, h * 0.76f), end = Offset(w * 0.36f, h * 0.30f), strokeWidth = w * 0.04f)
        drawLine(Color(0xFFE65100), start = Offset(w * 0.50f, h * 0.76f), end = Offset(w * 0.64f, h * 0.30f), strokeWidth = w * 0.04f)
    }
}

@Composable
fun DrWebLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawCircle(Color(0xFF43A047), radius = w * 0.48f, center = Offset(w * 0.5f, h * 0.5f))
        // Spider body + legs
        drawCircle(Color.White, radius = w * 0.16f, center = Offset(w * 0.5f, h * 0.54f))
        drawCircle(Color.White, radius = w * 0.10f, center = Offset(w * 0.5f, h * 0.34f))
        // Legs
        drawLine(Color.White, start = Offset(w * 0.38f, h * 0.46f), end = Offset(w * 0.18f, h * 0.32f), strokeWidth = w * 0.05f, cap = StrokeCap.Round)
        drawLine(Color.White, start = Offset(w * 0.62f, h * 0.46f), end = Offset(w * 0.82f, h * 0.32f), strokeWidth = w * 0.05f, cap = StrokeCap.Round)
        drawLine(Color.White, start = Offset(w * 0.38f, h * 0.58f), end = Offset(w * 0.18f, h * 0.68f), strokeWidth = w * 0.05f, cap = StrokeCap.Round)
        drawLine(Color.White, start = Offset(w * 0.62f, h * 0.58f), end = Offset(w * 0.82f, h * 0.68f), strokeWidth = w * 0.05f, cap = StrokeCap.Round)
    }
}

@Composable
fun QuickHealLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawRoundRect(Color(0xFFFF6F00), cornerRadius = CornerRadius(w * 0.28f, h * 0.28f))
        // White 'Q' loop and slash
        drawCircle(Color.White, radius = w * 0.22f, center = Offset(w * 0.5f, h * 0.46f), style = Stroke(width = w * 0.09f))
        drawLine(Color.White, start = Offset(w * 0.54f, h * 0.54f), end = Offset(w * 0.74f, h * 0.74f), strokeWidth = w * 0.09f, cap = StrokeCap.Round)
    }
}

@Composable
fun AhnLabLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawRoundRect(Color(0xFF005BAC), cornerRadius = CornerRadius(w * 0.26f, h * 0.26f))
        // V3 mark
        val vPath = Path().apply {
            moveTo(w * 0.24f, h * 0.32f)
            lineTo(w * 0.44f, h * 0.72f)
            lineTo(w * 0.54f, h * 0.32f)
        }
        drawPath(vPath, Color.White, style = Stroke(width = w * 0.08f, cap = StrokeCap.Round))
        // 3 curves
        val three = Path().apply {
            moveTo(w * 0.62f, h * 0.34f)
            cubicTo(w * 0.78f, h * 0.34f, w * 0.78f, h * 0.50f, w * 0.64f, h * 0.52f)
            cubicTo(w * 0.80f, h * 0.54f, w * 0.80f, h * 0.70f, w * 0.62f, h * 0.70f)
        }
        drawPath(three, Color.White, style = Stroke(width = w * 0.08f, cap = StrokeCap.Round))
    }
}

@Composable
fun AviraLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawCircle(Color(0xFFD32F2F), radius = w * 0.48f, center = Offset(w * 0.5f, h * 0.5f))
        // Open white umbrella
        val dome = Path().apply {
            moveTo(w * 0.20f, h * 0.48f)
            cubicTo(w * 0.22f, h * 0.24f, w * 0.78f, h * 0.24f, w * 0.80f, h * 0.48f)
            close()
        }
        drawPath(dome, Color.White)
        drawLine(Color.White, start = Offset(w * 0.50f, h * 0.40f), end = Offset(w * 0.50f, h * 0.72f), strokeWidth = w * 0.06f, cap = StrokeCap.Round)
        val hook = Path().apply {
            moveTo(w * 0.50f, h * 0.72f)
            cubicTo(w * 0.50f, h * 0.80f, w * 0.40f, h * 0.80f, w * 0.40f, h * 0.74f)
        }
        drawPath(hook, Color.White, style = Stroke(width = w * 0.06f, cap = StrokeCap.Round))
    }
}

// ---------------------------------------------------------------------------
// CLOUD SCANNERS BRAND LOGOS
// ---------------------------------------------------------------------------

@Composable
fun HybridAnalysisLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawRoundRect(Color(0xFF0F172A), cornerRadius = CornerRadius(w * 0.26f, h * 0.26f))
        // Falcon cyber eye with cyan iris
        val eye = Path().apply {
            moveTo(w * 0.16f, h * 0.50f)
            cubicTo(w * 0.32f, h * 0.28f, w * 0.68f, h * 0.28f, w * 0.84f, h * 0.50f)
            cubicTo(w * 0.68f, h * 0.72f, w * 0.32f, h * 0.72f, w * 0.16f, h * 0.50f)
            close()
        }
        drawPath(eye, Color(0xFF0284C7), style = Stroke(width = w * 0.08f))
        drawCircle(Color(0xFF38BDF8), radius = w * 0.14f, center = Offset(w * 0.50f, h * 0.50f))
        drawCircle(Color.White, radius = w * 0.06f, center = Offset(w * 0.48f, h * 0.48f))
    }
}

@Composable
fun MetaDefenderLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawRoundRect(Color(0xFF1E293B), cornerRadius = CornerRadius(w * 0.26f, h * 0.26f))
        // OPSWAT interconnected nodes (Orange + Blue)
        val p1 = Offset(w * 0.50f, h * 0.24f)
        val p2 = Offset(w * 0.24f, h * 0.70f)
        val p3 = Offset(w * 0.76f, h * 0.70f)
        drawLine(Color.White.copy(alpha = 0.5f), p1, p2, strokeWidth = w * 0.05f)
        drawLine(Color.White.copy(alpha = 0.5f), p2, p3, strokeWidth = w * 0.05f)
        drawLine(Color.White.copy(alpha = 0.5f), p3, p1, strokeWidth = w * 0.05f)
        drawCircle(Color(0xFFEA580C), radius = w * 0.12f, center = p1)
        drawCircle(Color(0xFF3B82F6), radius = w * 0.12f, center = p2)
        drawCircle(Color(0xFF10B981), radius = w * 0.12f, center = p3)
    }
}

@Composable
fun AlienVaultLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawRoundRect(Color(0xFF0B192C), cornerRadius = CornerRadius(w * 0.26f, h * 0.26f))
        // Orbital globe with cyan pulse ring
        drawCircle(Color(0xFF0284C7), radius = w * 0.28f, center = Offset(w * 0.50f, h * 0.50f))
        val ring = Path().apply {
            moveTo(w * 0.14f, h * 0.60f)
            cubicTo(w * 0.24f, h * 0.32f, w * 0.76f, h * 0.32f, w * 0.86f, h * 0.40f)
        }
        drawPath(ring, Color(0xFF38BDF8), style = Stroke(width = w * 0.07f, cap = StrokeCap.Round))
    }
}

@Composable
fun CirclLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawCircle(Color(0xFF0D9488), radius = w * 0.48f, center = Offset(w * 0.5f, h * 0.5f))
        // White CERT rosette shield
        val shield = Path().apply {
            moveTo(w * 0.50f, h * 0.20f)
            lineTo(w * 0.78f, h * 0.32f)
            lineTo(w * 0.78f, h * 0.56f)
            cubicTo(w * 0.78f, h * 0.74f, w * 0.50f, h * 0.84f, w * 0.50f, h * 0.84f)
            cubicTo(w * 0.50f, h * 0.84f, w * 0.22f, h * 0.74f, w * 0.22f, h * 0.56f)
            lineTo(w * 0.22f, h * 0.32f)
            close()
        }
        drawPath(shield, Color.White, style = Stroke(width = w * 0.07f))
        drawCircle(Color.White, radius = w * 0.09f, center = Offset(w * 0.50f, h * 0.50f))
    }
}

@Composable
fun MalwareBazaarLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawRoundRect(Color(0xFFEAB308), cornerRadius = CornerRadius(w * 0.26f, h * 0.26f))
        // Threat radar bug silhouette
        drawCircle(Color(0xFF1E293B), radius = w * 0.16f, center = Offset(w * 0.50f, h * 0.54f))
        drawCircle(Color(0xFF1E293B), radius = w * 0.10f, center = Offset(w * 0.50f, h * 0.34f))
        drawLine(Color(0xFF1E293B), Offset(w * 0.34f, h * 0.46f), Offset(w * 0.16f, h * 0.38f), strokeWidth = w * 0.06f, cap = StrokeCap.Round)
        drawLine(Color(0xFF1E293B), Offset(w * 0.66f, h * 0.46f), Offset(w * 0.84f, h * 0.38f), strokeWidth = w * 0.06f, cap = StrokeCap.Round)
        drawLine(Color(0xFF1E293B), Offset(w * 0.34f, h * 0.60f), Offset(w * 0.18f, h * 0.68f), strokeWidth = w * 0.06f, cap = StrokeCap.Round)
        drawLine(Color(0xFF1E293B), Offset(w * 0.66f, h * 0.60f), Offset(w * 0.82f, h * 0.68f), strokeWidth = w * 0.06f, cap = StrokeCap.Round)
    }
}

@Composable
fun FilescanLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawRoundRect(Color(0xFF9333EA), cornerRadius = CornerRadius(w * 0.26f, h * 0.26f))
        // Multi-layer radar beams
        drawCircle(Color.White.copy(alpha = 0.3f), radius = w * 0.32f, center = Offset(w * 0.50f, h * 0.50f), style = Stroke(width = w * 0.05f))
        drawCircle(Color.White.copy(alpha = 0.6f), radius = w * 0.20f, center = Offset(w * 0.50f, h * 0.50f), style = Stroke(width = w * 0.05f))
        drawCircle(Color(0xFFA855F7), radius = w * 0.08f, center = Offset(w * 0.50f, h * 0.50f))
    }
}

// ---------------------------------------------------------------------------
// LOCAL SCANNING ENGINES BRAND LOGOS
// ---------------------------------------------------------------------------

@Composable
fun ThreatLensLocalLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawRoundRect(Color(0xFF031926), cornerRadius = CornerRadius(w * 0.26f, h * 0.26f))
        drawRoundRect(Color(0xFF00E5FF).copy(alpha = 0.6f), cornerRadius = CornerRadius(w * 0.26f, h * 0.26f), style = Stroke(width = w * 0.06f))
        // Target radar crosshair
        drawCircle(Color(0xFF00E5FF), radius = w * 0.22f, center = Offset(w * 0.50f, h * 0.50f), style = Stroke(width = w * 0.05f))
        drawLine(Color(0xFF00E5FF), Offset(w * 0.50f, h * 0.20f), Offset(w * 0.50f, h * 0.80f), strokeWidth = w * 0.05f)
        drawLine(Color(0xFF00E5FF), Offset(w * 0.20f, h * 0.50f), Offset(w * 0.80f, h * 0.50f), strokeWidth = w * 0.05f)
        drawCircle(Color(0xFF00E5FF), radius = w * 0.07f, center = Offset(w * 0.50f, h * 0.50f))
    }
}

@Composable
fun ThreatLensPackerLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawRoundRect(Color(0xFF06281E), cornerRadius = CornerRadius(w * 0.26f, h * 0.26f))
        drawRoundRect(Color(0xFF10B981).copy(alpha = 0.6f), cornerRadius = CornerRadius(w * 0.26f, h * 0.26f), style = Stroke(width = w * 0.06f))
        // Unpacker cube
        val topFace = Path().apply {
            moveTo(w * 0.50f, h * 0.22f)
            lineTo(w * 0.74f, h * 0.36f)
            lineTo(w * 0.50f, h * 0.50f)
            lineTo(w * 0.26f, h * 0.36f)
            close()
        }
        drawPath(topFace, Color(0xFF10B981))
        val leftFace = Path().apply {
            moveTo(w * 0.26f, h * 0.36f)
            lineTo(w * 0.50f, h * 0.50f)
            lineTo(w * 0.50f, h * 0.76f)
            lineTo(w * 0.26f, h * 0.62f)
            close()
        }
        drawPath(leftFace, Color(0xFF059669))
        val rightFace = Path().apply {
            moveTo(w * 0.50f, h * 0.50f)
            lineTo(w * 0.74f, h * 0.36f)
            lineTo(w * 0.74f, h * 0.62f)
            lineTo(w * 0.50f, h * 0.76f)
            close()
        }
        drawPath(rightFace, Color(0xFF047857))
    }
}

@Composable
fun ThreatLensCertLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawRoundRect(Color(0xFF1E1035), cornerRadius = CornerRadius(w * 0.26f, h * 0.26f))
        drawRoundRect(Color(0xFF8B5CF6).copy(alpha = 0.6f), cornerRadius = CornerRadius(w * 0.26f, h * 0.26f), style = Stroke(width = w * 0.06f))
        // Certificate seal with verified checkmark
        drawCircle(Color(0xFF7C3AED), radius = w * 0.26f, center = Offset(w * 0.50f, h * 0.44f))
        val check = Path().apply {
            moveTo(w * 0.38f, h * 0.44f)
            lineTo(w * 0.46f, h * 0.52f)
            lineTo(w * 0.62f, h * 0.36f)
        }
        drawPath(check, Color.White, style = Stroke(width = w * 0.07f, cap = StrokeCap.Round))
        // Ribbon tails
        val ribbon = Path().apply {
            moveTo(w * 0.40f, h * 0.64f)
            lineTo(w * 0.34f, h * 0.82f)
            lineTo(w * 0.44f, h * 0.76f)
            lineTo(w * 0.50f, h * 0.82f)
            lineTo(w * 0.56f, h * 0.76f)
            lineTo(w * 0.66f, h * 0.82f)
            lineTo(w * 0.60f, h * 0.64f)
        }
        drawPath(ribbon, Color(0xFF8B5CF6))
    }
}

@Composable
fun ThreatLensSigDbLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawRoundRect(Color(0xFF0A1931), cornerRadius = CornerRadius(w * 0.26f, h * 0.26f))
        drawRoundRect(Color(0xFF3B82F6).copy(alpha = 0.6f), cornerRadius = CornerRadius(w * 0.26f, h * 0.26f), style = Stroke(width = w * 0.06f))
        // Database cylinder layers
        val cy1 = Path().apply {
            moveTo(w * 0.26f, h * 0.30f)
            cubicTo(w * 0.26f, h * 0.22f, w * 0.74f, h * 0.22f, w * 0.74f, h * 0.30f)
            cubicTo(w * 0.74f, h * 0.38f, w * 0.26f, h * 0.38f, w * 0.26f, h * 0.30f)
        }
        drawPath(cy1, Color(0xFF3B82F6))
        val cy2 = Path().apply {
            moveTo(w * 0.26f, h * 0.48f)
            cubicTo(w * 0.26f, h * 0.56f, w * 0.74f, h * 0.56f, w * 0.74f, h * 0.48f)
        }
        drawPath(cy2, Color(0xFF3B82F6), style = Stroke(width = w * 0.06f, cap = StrokeCap.Round))
        val cy3 = Path().apply {
            moveTo(w * 0.26f, h * 0.66f)
            cubicTo(w * 0.26f, h * 0.74f, w * 0.74f, h * 0.74f, w * 0.74f, h * 0.66f)
        }
        drawPath(cy3, Color(0xFF3B82F6), style = Stroke(width = w * 0.06f, cap = StrokeCap.Round))
    }
}

@Composable
fun YaraLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawRoundRect(Color(0xFF280B0B), cornerRadius = CornerRadius(w * 0.26f, h * 0.26f))
        drawRoundRect(Color(0xFFEF4444).copy(alpha = 0.6f), cornerRadius = CornerRadius(w * 0.26f, h * 0.26f), style = Stroke(width = w * 0.06f))
        // YARA signature scanner crosshair
        drawCircle(Color(0xFFDC2626), radius = w * 0.22f, center = Offset(w * 0.50f, h * 0.50f), style = Stroke(width = w * 0.05f))
        drawLine(Color(0xFFEF4444), Offset(w * 0.50f, h * 0.18f), Offset(w * 0.50f, h * 0.82f), strokeWidth = w * 0.05f)
        drawLine(Color(0xFFEF4444), Offset(w * 0.18f, h * 0.50f), Offset(w * 0.82f, h * 0.50f), strokeWidth = w * 0.05f)
    }
}

// ---------------------------------------------------------------------------
// BRAND LOGO DISPATCHER
// ---------------------------------------------------------------------------

@Composable
fun BrandLogoBadge(
    brandKey: String,
    modifier: Modifier = Modifier.size(22.dp)
) {
    when (brandKey) {
        "VirusTotal" -> VirusTotalLogo(modifier)
        "Norton", "Symantec" -> NortonLogo(modifier)
        "Bitdefender" -> BitdefenderLogo(modifier)
        "Microsoft", "WindowsDefender" -> MicrosoftDefenderLogo(modifier)
        "Kaspersky" -> KasperskyLogo(modifier)
        "Avast" -> AvastLogo(modifier)
        "ESET" -> EsetLogo(modifier)
        "McAfee" -> McAfeeLogo(modifier)
        "Sophos" -> SophosLogo(modifier)
        "Google" -> GoogleProtectLogo(modifier)
        "TrendMicro" -> TrendMicroLogo(modifier)
        "Malwarebytes" -> MalwarebytesLogo(modifier)
        "ClamAV" -> ClamAvLogo(modifier)
        "DrWeb" -> DrWebLogo(modifier)
        "QuickHeal" -> QuickHealLogo(modifier)
        "AhnLab" -> AhnLabLogo(modifier)
        "Avira" -> AviraLogo(modifier)
        "HybridAnalysis" -> HybridAnalysisLogo(modifier)
        "MetaDefender" -> MetaDefenderLogo(modifier)
        "AlienVault" -> AlienVaultLogo(modifier)
        "CIRCL" -> CirclLogo(modifier)
        "MalwareBazaar" -> MalwareBazaarLogo(modifier)
        "Filescan" -> FilescanLogo(modifier)
        "ThreatLensLocal" -> ThreatLensLocalLogo(modifier)
        "ThreatLensPacker" -> ThreatLensPackerLogo(modifier)
        "ThreatLensCert" -> ThreatLensCertLogo(modifier)
        "ThreatLensSigDb" -> ThreatLensSigDbLogo(modifier)
        "YARA" -> YaraLogo(modifier)
        else -> {
            // High-quality generic fallback
            val brand = EngineRegistry.getBrand(brandKey)
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
                    contentDescription = brandKey,
                    tint = Color.White,
                    modifier = Modifier.size(13.dp)
                )
            }
        }
    }
}

@Composable
fun EngineLogoIcon(
    engineName: String,
    modifier: Modifier = Modifier.size(24.dp)
) {
    val brand = EngineRegistry.getBrand(engineName)
    BrandLogoBadge(brandKey = brand.brandKey, modifier = modifier)
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

// ---------------------------------------------------------------------------
// SUB-ENGINE / COMMERCIAL VENDOR REGISTRY (VIRUSTOTAL & METADEFENDER)
// ---------------------------------------------------------------------------

data class VendorBrand(
    val name: String,
    val brandKey: String,
    val color: Color,
    val initials: String,
    val icon: ImageVector = Icons.Default.Shield
)

object SubEngineRegistry {
    // Comprehensive commercial AV vendor database (ordered so longer specific matches precede substrings)
    private val VENDORS = listOf(
        VendorBrand("BitDefenderFalx", "Bitdefender", Color(0xFFED1C24), "BD"),
        VendorBrand("BitDefenderTheta", "Bitdefender", Color(0xFFED1C24), "BD"),
        VendorBrand("Bitdefender", "Bitdefender", Color(0xFFED1C24), "BD"),
        VendorBrand("SymantecMobileInsight", "Norton", Color(0xFFFDB813), "SYM"),
        VendorBrand("Symantec", "Norton", Color(0xFFFDB813), "SYM"),
        VendorBrand("Norton", "Norton", Color(0xFFFDB813), "NRT"),
        VendorBrand("Broadcom", "Norton", Color(0xFFFDB813), "SYM"),
        VendorBrand("WindowsDefender", "Microsoft", Color(0xFF00A4EF), "MS"),
        VendorBrand("Defender", "Microsoft", Color(0xFF00A4EF), "MS"),
        VendorBrand("Microsoft", "Microsoft", Color(0xFF00A4EF), "MS"),
        VendorBrand("Kaspersky", "Kaspersky", Color(0xFF00A88E), "K"),
        VendorBrand("Avast-Mobile", "Avast", Color(0xFFFF7800), "AV"),
        VendorBrand("Avast", "Avast", Color(0xFFFF7800), "AV"),
        VendorBrand("AVG", "Avast", Color(0xFFFF7800), "AVG"),
        VendorBrand("ESET-NOD32", "ESET", Color(0xFF00838F), "ESET"),
        VendorBrand("ESET", "ESET", Color(0xFF00838F), "ESET"),
        VendorBrand("Sophos", "Sophos", Color(0xFF0058A3), "SPH"),
        VendorBrand("Google", "Google", Color(0xFF4285F4), "G"),
        VendorBrand("PlayProtect", "Google", Color(0xFF4285F4), "G"),
        VendorBrand("TrendMicro-HouseCall", "TrendMicro", Color(0xFFD71920), "TM"),
        VendorBrand("TrendMicro", "TrendMicro", Color(0xFFD71920), "TM"),
        VendorBrand("McAfee-GW-Edition", "McAfee", Color(0xFFC01818), "MC"),
        VendorBrand("McAfee", "McAfee", Color(0xFFC01818), "MC"),
        VendorBrand("Fortinet", "Fortinet", Color(0xFFDA291C), "FT"),
        VendorBrand("ClamAV", "ClamAV", Color(0xFFE65100), "CLAM"),
        VendorBrand("AhnLab-V3", "AhnLab", Color(0xFF005BAC), "AHN"),
        VendorBrand("AhnLab", "AhnLab", Color(0xFF005BAC), "AHN"),
        VendorBrand("F-Secure", "F-Secure", Color(0xFF0072CE), "FS"),
        VendorBrand("Malwarebytes", "Malwarebytes", Color(0xFF0073D1), "MB"),
        VendorBrand("SentinelOne", "SentinelOne", Color(0xFF4E2A84), "S1"),
        VendorBrand("CrowdStrike", "CrowdStrike", Color(0xFFE2231A), "CS"),
        VendorBrand("DrWeb", "DrWeb", Color(0xFF43A047), "DRW"),
        VendorBrand("CAT-QuickHeal", "QuickHeal", Color(0xFFFF6F00), "QH"),
        VendorBrand("QuickHeal", "QuickHeal", Color(0xFFFF6F00), "QH"),
        VendorBrand("Tencent", "Tencent", Color(0xFF12B7F5), "TC"),
        VendorBrand("Yandex", "Yandex", Color(0xFFFF0000), "YA"),
        VendorBrand("WithSecure", "WithSecure", Color(0xFF0072CE), "WS"),
        VendorBrand("Avira", "Avira", Color(0xFFD32F2F), "AVR"),
        VendorBrand("Ikarus", "Ikarus", Color(0xFF388E3C), "IKR"),
        VendorBrand("ZoneAlarm", "ZoneAlarm", Color(0xFFB71C1C), "ZA"),
        VendorBrand("PaloAlto", "PaloAlto", Color(0xFFFA582D), "PA"),
        VendorBrand("GData", "GData", Color(0xFFD50000), "GD"),
        VendorBrand("Emsisoft", "Emsisoft", Color(0xFF0091EA), "EMS"),
        VendorBrand("CR-Reason", "CR-Reason", Color(0xFF212121), "CR"),
        VendorBrand("Cynet", "Cynet", Color(0xFF00C853), "CYN"),
        VendorBrand("K7AntiVirus", "K7", Color(0xFF00897B), "K7"),
        VendorBrand("K7GW", "K7", Color(0xFF00897B), "K7"),
        VendorBrand("ALYac", "ALYac", Color(0xFF00ACC1), "AL"),
        VendorBrand("Antiy-AVL", "Antiy", Color(0xFF5E35B1), "ANT"),
        VendorBrand("Arcabit", "Arcabit", Color(0xFF3949AB), "ARC"),
        VendorBrand("Baidu", "Baidu", Color(0xFF2979FF), "BDU"),
        VendorBrand("Bkav", "Bkav", Color(0xFFFF6D00), "BK"),
        VendorBrand("CMC", "CMC", Color(0xFF43A047), "CMC"),
        VendorBrand("Comodo", "Comodo", Color(0xFFE53935), "CMD"),
        VendorBrand("Jiangmin", "Jiangmin", Color(0xFF00897B), "JM"),
        VendorBrand("Kingsoft", "Kingsoft", Color(0xFF00ACC1), "KS"),
        VendorBrand("MaxSecure", "MaxSecure", Color(0xFF6D4C41), "MAX"),
        VendorBrand("NANO-Antivirus", "NANO", Color(0xFF546E7A), "NANO"),
        VendorBrand("SUPERAntiSpyware", "SUPERAntiSpyware", Color(0xFF7CB342), "SAS"),
        VendorBrand("Tachyon", "Tachyon", Color(0xFF1E88E5), "TY"),
        VendorBrand("TotalDefense", "TotalDefense", Color(0xFF303F9F), "TD"),
        VendorBrand("Trapmine", "Trapmine", Color(0xFF5D4037), "TM"),
        VendorBrand("Trustlook", "Trustlook", Color(0xFF00B0FF), "TL"),
        VendorBrand("VIPRE", "VIPRE", Color(0xFF00796B), "VIP"),
        VendorBrand("ViRobot", "ViRobot", Color(0xFF0288D1), "VR"),
        VendorBrand("Zillya", "Zillya", Color(0xFF7CB342), "ZIL"),
        VendorBrand("Zoner", "Zoner", Color(0xFF689F38), "ZON")
    )

    fun getVendorBrand(name: String): VendorBrand {
        val clean = name.trim().lowercase()
        // Priority 1: Exact or direct prefix alias matches
        when {
            clean.contains("bitdefender") -> return VendorBrand(name, "Bitdefender", Color(0xFFED1C24), "BD")
            clean.contains("norton") || clean.contains("symantec") || clean.contains("broadcom") ->
                return VendorBrand(name, "Norton", Color(0xFFFDB813), "SYM")
            clean.contains("windowsdefender") || clean.contains("microsoft") ->
                return VendorBrand(name, "Microsoft", Color(0xFF00A4EF), "MS")
            clean.contains("kaspersky") -> return VendorBrand(name, "Kaspersky", Color(0xFF00A88E), "K")
            clean.contains("avast") -> return VendorBrand(name, "Avast", Color(0xFFFF7800), "AV")
            clean.contains("avg") -> return VendorBrand(name, "Avast", Color(0xFFFF7800), "AVG")
            clean.contains("eset") || clean.contains("nod32") -> return VendorBrand(name, "ESET", Color(0xFF00838F), "ESET")
            clean.contains("sophos") -> return VendorBrand(name, "Sophos", Color(0xFF0058A3), "SPH")
            clean.contains("google") || clean.contains("playprotect") -> return VendorBrand(name, "Google", Color(0xFF4285F4), "G")
            clean.contains("trendmicro") || clean.contains("housecall") -> return VendorBrand(name, "TrendMicro", Color(0xFFD71920), "TM")
            clean.contains("mcafee") -> return VendorBrand(name, "McAfee", Color(0xFFC01818), "MC")
            clean.contains("malwarebytes") -> return VendorBrand(name, "Malwarebytes", Color(0xFF0073D1), "MB")
            clean.contains("clamav") -> return VendorBrand(name, "ClamAV", Color(0xFFE65100), "CLAM")
            clean.contains("drweb") -> return VendorBrand(name, "DrWeb", Color(0xFF43A047), "DRW")
            clean.contains("quickheal") || clean.contains("cat-quickheal") -> return VendorBrand(name, "QuickHeal", Color(0xFFFF6F00), "QH")
            clean.contains("ahnlab") || clean.contains("v3") -> return VendorBrand(name, "AhnLab", Color(0xFF005BAC), "AHN")
            clean.contains("avira") -> return VendorBrand(name, "Avira", Color(0xFFD32F2F), "AVR")
            clean.contains("sentinel") -> return VendorBrand(name, "SentinelOne", Color(0xFF4E2A84), "S1")
            clean.contains("crowdstrike") || clean.contains("falcon") -> return VendorBrand(name, "CrowdStrike", Color(0xFFE2231A), "CS")
            clean.contains("fortinet") || clean.contains("forti") -> return VendorBrand(name, "Fortinet", Color(0xFFDA291C), "FT")
            clean.contains("f-secure") || clean.contains("fsecure") -> return VendorBrand(name, "F-Secure", Color(0xFF0072CE), "FS")
            clean.contains("withsecure") -> return VendorBrand(name, "WithSecure", Color(0xFF0072CE), "WS")
            clean.contains("tencent") -> return VendorBrand(name, "Tencent", Color(0xFF12B7F5), "TC")
            clean.contains("yandex") -> return VendorBrand(name, "Yandex", Color(0xFFFF0000), "YA")
            clean.contains("ikarus") -> return VendorBrand(name, "Ikarus", Color(0xFF388E3C), "IKR")
        }

        // Priority 2: Match against registered vendors sorted by longest name descending
        val matched = VENDORS.firstOrNull { clean.contains(it.name.lowercase()) }
        if (matched != null) return matched

        return VendorBrand(
            name = name.trim(),
            brandKey = "Generic",
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
            shape = RoundedCornerShape(8.dp),
            border = androidx.compose.foundation.BorderStroke(1.dp, vendor.color.copy(alpha = 0.45f))
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Authentic Brand Logo Badge
                BrandLogoBadge(
                    brandKey = vendor.brandKey,
                    modifier = Modifier.size(24.dp)
                )
                Spacer(modifier = Modifier.width(10.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = vendorName,
                        color = Color.White,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(modifier = Modifier.height(1.dp))
                    Text(
                        text = findingText,
                        color = if (isMalicious) NeonCrimson else CyberAmber,
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
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
                fontFamily = FontFamily.Monospace,
                lineHeight = 15.sp
            )
        }
    }
}

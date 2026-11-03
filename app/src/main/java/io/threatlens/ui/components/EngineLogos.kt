package io.threatlens.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.ui.draw.clip
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import io.threatlens.R
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
            lower.contains("alin") -> EngineBrand("Predictive Alin AI", "Alin", Color(0xFF6C5CE7), Color(0xFFA29BFE), Icons.Default.Psychology, "AI")
            lower.contains("vulnerability") -> EngineBrand("Vulnerability Assessment", "Vulnerability", Color(0xFFFF7675), Color(0xFFD63031), Icons.Default.Warning, "CVE")
            lower.contains("cdr") -> EngineBrand("Deep CDR", "DeepCDR", Color(0xFF00CEC9), Color(0xFF0984E3), Icons.Default.CleaningServices, "CDR")
            lower.contains("sandbox") -> EngineBrand("Adaptive Sandbox", "Sandbox", Color(0xFF0284C7), Color(0xFF38BDF8), Icons.Default.ViewInAr, "SBX")
            lower.contains("dlp") -> EngineBrand("Proactive DLP", "ProactiveDlp", Color(0xFF0369A1), Color(0xFF38BDF8), Icons.Default.Lock, "DLP")
            lower.contains("content inspector") || lower.contains("ai content") -> EngineBrand("AI Content Inspector", "AiContentInspector", Color(0xFF7C3AED), Color(0xFFA78BFA), Icons.Default.Policy, "AIC")
            lower.contains("country") || lower.contains("origin") -> EngineBrand("Country of Origin", "CountryOfOrigin", Color(0xFF4F46E5), Color(0xFF818CF8), Icons.Default.Public, "COO")
            lower.contains("metascan") || lower.contains("metadefender") -> METADEFENDER
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
fun OfficialVendorLogo(
    drawableRes: Int,
    contentDescription: String,
    modifier: Modifier = Modifier
) {
    Image(
        painter = painterResource(id = drawableRes),
        contentDescription = contentDescription,
        modifier = modifier.clip(RoundedCornerShape(4.dp)),
        contentScale = ContentScale.Fit
    )
}

@Composable
fun VirusTotalLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_virustotal, "VirusTotal", modifier)
}


@Composable
fun NortonLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_norton, "Norton", modifier)
}


@Composable
fun BitdefenderLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_bitdefender, "Bitdefender", modifier)
}


@Composable
fun MicrosoftDefenderLogo(modifier: Modifier = Modifier.size(24.dp)) {
    // Official Microsoft Defender 4-color square brand palette: Red (0xFFF25022), Green (0xFF7FBA00), Blue (0xFF00A4EF), Yellow (0xFFFFB900)
    OfficialVendorLogo(R.drawable.ic_vendor_microsoft, "Microsoft", modifier)
}


@Composable
fun KasperskyLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_kaspersky, "Kaspersky", modifier)
}


@Composable
fun AvastLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_avast, "Avast", modifier)
}


@Composable
fun EsetLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_eset, "ESET", modifier)
}


@Composable
fun McAfeeLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_mcafee, "McAfee", modifier)
}


@Composable
fun SophosLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_sophos, "Sophos", modifier)
}


@Composable
fun GoogleProtectLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_google, "Google Play Protect", modifier)
}


@Composable
fun TrendMicroLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_trendmicro, "Trend Micro", modifier)
}


@Composable
fun MalwarebytesLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_malwarebytes, "Malwarebytes", modifier)
}


@Composable
fun ClamAvLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_clamav, "ClamAV", modifier)
}


@Composable
fun DrWebLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_drweb, "Dr.Web", modifier)
}


@Composable
fun QuickHealLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_quickheal, "Quick Heal", modifier)
}


@Composable
fun AhnLabLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_ahnlab, "AhnLab", modifier)
}


@Composable
fun AviraLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_avira, "Avira", modifier)
}


// ---------------------------------------------------------------------------
// CLOUD SCANNERS BRAND LOGOS
// ---------------------------------------------------------------------------

@Composable
fun HybridAnalysisLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_hybridanalysis, "Hybrid Analysis", modifier)
}


@Composable
fun MetaDefenderLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_metadefender, "MetaDefender", modifier)
}


@Composable
fun AlienVaultLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_alienvault, "AlienVault", modifier)
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
fun FilescanLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_filescan, "Filescan", modifier)
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

@Composable
fun AlinAiLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawCircle(Color(0xFF6C5CE7), radius = w * 0.48f, center = Offset(w * 0.5f, h * 0.5f))
        val c = Offset(w * 0.5f, h * 0.5f)
        val p1 = Offset(w * 0.30f, h * 0.35f)
        val p2 = Offset(w * 0.70f, h * 0.35f)
        val p3 = Offset(w * 0.35f, h * 0.70f)
        val p4 = Offset(w * 0.65f, h * 0.70f)
        val stroke = w * 0.04f
        drawLine(Color.White.copy(alpha = 0.7f), c, p1, strokeWidth = stroke)
        drawLine(Color.White.copy(alpha = 0.7f), c, p2, strokeWidth = stroke)
        drawLine(Color.White.copy(alpha = 0.7f), c, p3, strokeWidth = stroke)
        drawLine(Color.White.copy(alpha = 0.7f), c, p4, strokeWidth = stroke)
        drawLine(Color.White.copy(alpha = 0.5f), p1, p2, strokeWidth = stroke)
        drawLine(Color.White.copy(alpha = 0.5f), p3, p4, strokeWidth = stroke)
        val rSmall = w * 0.07f
        drawCircle(Color.White, radius = w * 0.09f, center = c)
        drawCircle(Color(0xFFA29BFE), radius = rSmall, center = p1)
        drawCircle(Color(0xFFA29BFE), radius = rSmall, center = p2)
        drawCircle(Color(0xFFA29BFE), radius = rSmall, center = p3)
        drawCircle(Color(0xFFA29BFE), radius = rSmall, center = p4)
    }
}

@Composable
fun VulnerabilityLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawRoundRect(Color(0xFFDC2626), cornerRadius = CornerRadius(w * 0.26f, h * 0.26f))
        val path = Path().apply {
            moveTo(w * 0.50f, h * 0.20f)
            lineTo(w * 0.78f, h * 0.32f)
            lineTo(w * 0.78f, h * 0.58f)
            cubicTo(w * 0.78f, h * 0.74f, w * 0.50f, h * 0.84f, w * 0.50f, h * 0.84f)
            cubicTo(w * 0.50f, h * 0.84f, w * 0.22f, h * 0.74f, w * 0.22f, h * 0.58f)
            lineTo(w * 0.22f, h * 0.32f)
            close()
        }
        drawPath(path, Color.White, style = Stroke(width = w * 0.07f, cap = StrokeCap.Round))
        drawLine(Color.White, Offset(w * 0.50f, h * 0.36f), Offset(w * 0.50f, h * 0.54f), strokeWidth = w * 0.08f, cap = StrokeCap.Round)
        drawCircle(Color.White, radius = w * 0.045f, center = Offset(w * 0.50f, h * 0.66f))
    }
}

@Composable
fun DeepCdrLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawCircle(Color(0xFF0D9488), radius = w * 0.48f, center = Offset(w * 0.5f, h * 0.5f))
        val check = Path().apply {
            moveTo(w * 0.28f, h * 0.52f)
            lineTo(w * 0.44f, h * 0.68f)
            lineTo(w * 0.72f, h * 0.34f)
        }
        drawPath(check, Color.White, style = Stroke(width = w * 0.08f, cap = StrokeCap.Round))
    }
}

@Composable
fun AdaptiveSandboxLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawRoundRect(Color(0xFF0284C7), cornerRadius = CornerRadius(w * 0.26f, h * 0.26f))
        val path = Path().apply {
            moveTo(w * 0.50f, h * 0.22f)
            lineTo(w * 0.78f, h * 0.38f)
            lineTo(w * 0.78f, h * 0.68f)
            lineTo(w * 0.50f, h * 0.84f)
            lineTo(w * 0.22f, h * 0.68f)
            lineTo(w * 0.22f, h * 0.38f)
            close()
        }
        drawPath(path, Color.White, style = Stroke(width = w * 0.06f, cap = StrokeCap.Round))
        drawLine(Color.White, Offset(w * 0.50f, h * 0.52f), Offset(w * 0.50f, h * 0.84f), strokeWidth = w * 0.05f)
        drawLine(Color.White, Offset(w * 0.50f, h * 0.52f), Offset(w * 0.78f, h * 0.38f), strokeWidth = w * 0.05f)
        drawLine(Color.White, Offset(w * 0.50f, h * 0.52f), Offset(w * 0.22f, h * 0.38f), strokeWidth = w * 0.05f)
    }
}

@Composable
fun CountryOfOriginLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawCircle(Color(0xFF4F46E5), radius = w * 0.48f, center = Offset(w * 0.5f, h * 0.5f))
        drawCircle(Color.White, radius = w * 0.34f, center = Offset(w * 0.5f, h * 0.5f), style = Stroke(width = w * 0.05f))
        drawLine(Color.White, Offset(w * 0.16f, h * 0.50f), Offset(w * 0.84f, h * 0.50f), strokeWidth = w * 0.04f)
        val arc = Path().apply {
            moveTo(w * 0.50f, h * 0.16f)
            cubicTo(w * 0.32f, h * 0.28f, w * 0.32f, h * 0.72f, w * 0.50f, h * 0.84f)
            cubicTo(w * 0.68f, h * 0.72f, w * 0.68f, h * 0.28f, w * 0.50f, h * 0.16f)
        }
        drawPath(arc, Color.White, style = Stroke(width = w * 0.04f))
    }
}

@Composable
fun ProactiveDlpLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawRoundRect(Color(0xFF0369A1), cornerRadius = CornerRadius(w * 0.26f, h * 0.26f))
        val doc = Path().apply {
            moveTo(w * 0.28f, h * 0.22f)
            lineTo(w * 0.58f, h * 0.22f)
            lineTo(w * 0.72f, h * 0.36f)
            lineTo(w * 0.72f, h * 0.78f)
            lineTo(w * 0.28f, h * 0.78f)
            close()
        }
        drawPath(doc, Color.White.copy(alpha = 0.25f))
        drawPath(doc, Color.White, style = Stroke(width = w * 0.06f))
        drawRoundRect(Color(0xFF38BDF8), topLeft = Offset(w * 0.38f, h * 0.48f), size = Size(w * 0.24f, h * 0.22f), cornerRadius = CornerRadius(w * 0.04f, h * 0.04f))
        val shackle = Path().apply {
            moveTo(w * 0.43f, h * 0.48f)
            lineTo(w * 0.43f, h * 0.40f)
            cubicTo(w * 0.43f, h * 0.34f, w * 0.57f, h * 0.34f, w * 0.57f, h * 0.40f)
            lineTo(w * 0.57f, h * 0.48f)
        }
        drawPath(shackle, Color.White, style = Stroke(width = w * 0.05f))
    }
}

@Composable
fun AiContentInspectorLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawRoundRect(Color(0xFF7C3AED), cornerRadius = CornerRadius(w * 0.26f, h * 0.26f))
        val sparkle = Path().apply {
            moveTo(w * 0.50f, h * 0.22f)
            cubicTo(w * 0.50f, h * 0.42f, w * 0.58f, h * 0.50f, w * 0.78f, h * 0.50f)
            cubicTo(w * 0.58f, h * 0.50f, w * 0.50f, h * 0.58f, w * 0.50f, h * 0.78f)
            cubicTo(w * 0.50f, h * 0.58f, w * 0.42f, h * 0.50f, w * 0.22f, h * 0.50f)
            cubicTo(w * 0.42f, h * 0.50f, w * 0.50f, h * 0.42f, w * 0.50f, h * 0.22f)
            close()
        }
        drawPath(sparkle, Color.White)
        drawCircle(Color(0xFFA78BFA), radius = w * 0.08f, center = Offset(w * 0.50f, h * 0.50f))
    }
}

// ---------------------------------------------------------------------------
// BRAND LOGO DISPATCHER & SQUARE-FIT VENDOR EMBLEMS
// ---------------------------------------------------------------------------

@Composable
fun TrustlookLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_trustlook, "Trustlook", modifier)
}


@Composable
fun TrellixLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_trellix, "Trellix", modifier)
}


@Composable
fun RisingLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_rising, "Rising", modifier)
}


@Composable
fun KingsoftLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_kingsoft, "Kingsoft", modifier)
}


@Composable
fun BkavLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_bkav, "Bkav", modifier)
}


@Composable
fun EmsisoftLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_emsisoft, "Emsisoft", modifier)
}


@Composable
fun IkarusLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_ikarus, "Ikarus", modifier)
}


@Composable
fun K7Logo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_k7, "K7", modifier)
}


@Composable
fun AntiyLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_antiy, "Antiy", modifier)
}


@Composable
fun CmcLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_cmc, "CMC", modifier)
}


@Composable
fun FilseclabLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawRoundRect(Color(0xFF3949AB), cornerRadius = CornerRadius(w * 0.24f, h * 0.24f))
        // File document with security shield
        val doc = Path().apply {
            moveTo(w * 0.28f, h * 0.22f)
            lineTo(w * 0.56f, h * 0.22f)
            lineTo(w * 0.72f, h * 0.38f)
            lineTo(w * 0.72f, h * 0.78f)
            lineTo(w * 0.28f, h * 0.78f)
            close()
        }
        drawPath(doc, Color.White, style = Stroke(width = w * 0.07f))
        drawCircle(Color(0xFFFFCA28), radius = w * 0.10f, center = Offset(w * 0.50f, h * 0.54f))
    }
}

@Composable
fun HuorongLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_huorong, "Huorong", modifier)
}


@Composable
fun WebrootLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_webroot, "Webroot", modifier)
}


@Composable
fun XcitiumLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_xcitium, "Xcitium", modifier)
}


@Composable
fun ZillyaLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_zillya, "Zillya", modifier)
}


@Composable
fun LionicLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_lionic, "Lionic", modifier)
}


@Composable
fun NanoLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_nano, "NANO", modifier)
}


@Composable
fun TachyonLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_tachyon, "Tachyon", modifier)
}


@Composable
fun RocketCyberLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_rocketcyber, "RocketCyber", modifier)
}


@Composable
fun VaristLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_varist, "Varist", modifier)
}


@Composable
fun VirusBlokAdaLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawRoundRect(Color(0xFFC2185B), cornerRadius = CornerRadius(w * 0.24f, h * 0.24f))
        // Triple barrier shield
        val barrier = Path().apply {
            moveTo(w * 0.24f, h * 0.32f)
            lineTo(w * 0.76f, h * 0.32f)
            moveTo(w * 0.24f, h * 0.50f)
            lineTo(w * 0.76f, h * 0.50f)
            moveTo(w * 0.24f, h * 0.68f)
            lineTo(w * 0.76f, h * 0.68f)
        }
        drawPath(barrier, Color.White, style = Stroke(width = w * 0.08f, cap = StrokeCap.Round))
    }
}

@Composable
fun XvirusLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_xvirus, "Xvirus", modifier)
}


@Composable
fun SystweakLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawRoundRect(Color(0xFF00ACC1), cornerRadius = CornerRadius(w * 0.24f, h * 0.24f))
        // System tune-up gear emblem
        drawCircle(Color.White, radius = w * 0.24f, center = Offset(w * 0.50f, h * 0.50f), style = Stroke(width = w * 0.08f))
        drawCircle(Color.White, radius = w * 0.10f, center = Offset(w * 0.50f, h * 0.50f))
    }
}

@Composable
fun VirItLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_virit, "Vir.IT", modifier)
}


@Composable
fun ScrutinyLogo(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        drawRoundRect(Color(0xFF546E7A), cornerRadius = CornerRadius(w * 0.24f, h * 0.24f))
        drawCircle(Color.White, radius = w * 0.22f, center = Offset(w * 0.46f, h * 0.46f), style = Stroke(width = w * 0.08f))
        drawLine(Color.White, Offset(w * 0.62f, h * 0.62f), Offset(w * 0.78f, h * 0.78f), strokeWidth = w * 0.09f, cap = StrokeCap.Round)
    }
}

@Composable
fun AuroraLogo(modifier: Modifier = Modifier.size(24.dp)) {
    OfficialVendorLogo(R.drawable.ic_vendor_aurora, "Aurora", modifier)
}


fun getOfficialVendorDrawable(name: String): Int? {
    val clean = name.trim().lowercase()
        .replace("-", "")
        .replace(".", "")
        .replace("!", "")
        .replace("_", "")
        .replace(" ", "")

    return when {
        clean.contains("virustotal") || clean == "vt" -> R.drawable.ic_vendor_virustotal
        clean.contains("metadefender") || clean.contains("metascan") || clean.contains("opswat") -> R.drawable.ic_vendor_metadefender
        clean.contains("hybridanalysis") || clean.contains("hybrid") -> R.drawable.ic_vendor_hybridanalysis
        clean.contains("filescan") -> R.drawable.ic_vendor_filescan
        clean.contains("alienvault") || clean.contains("otx") -> R.drawable.ic_vendor_alienvault
        clean.contains("bitdefender") || clean.contains("falx") || clean.contains("theta") -> R.drawable.ic_vendor_bitdefender
        clean.contains("norton") || clean.contains("symantec") || clean.contains("broadcom") -> R.drawable.ic_vendor_norton
        clean.contains("microsoft") || clean.contains("windowsdefender") || clean.contains("defender") -> R.drawable.ic_vendor_microsoft
        clean.contains("kaspersky") || clean.contains("opentip") -> R.drawable.ic_vendor_kaspersky
        clean.contains("avast") -> R.drawable.ic_vendor_avast
        clean.contains("avg") -> R.drawable.ic_vendor_avg
        clean.contains("eset") || clean.contains("nod32") -> R.drawable.ic_vendor_eset
        clean.contains("mcafee") -> R.drawable.ic_vendor_mcafee
        clean.contains("sophos") || clean.contains("hitmanpro") -> R.drawable.ic_vendor_sophos
        clean.contains("google") || clean.contains("playprotect") -> R.drawable.ic_vendor_google
        clean.contains("trendmicro") || clean.contains("housecall") -> R.drawable.ic_vendor_trendmicro
        clean.contains("malwarebytes") || clean.contains("mbam") -> R.drawable.ic_vendor_malwarebytes
        clean.contains("clamav") || clean.contains("talos") -> R.drawable.ic_vendor_clamav
        clean.contains("drweb") -> R.drawable.ic_vendor_drweb
        clean.contains("quickheal") || clean.contains("catquickheal") -> R.drawable.ic_vendor_quickheal
        clean.contains("ahnlab") || clean.contains("v3") -> R.drawable.ic_vendor_ahnlab
        clean.contains("avira") -> R.drawable.ic_vendor_avira
        clean.contains("trustlook") -> R.drawable.ic_vendor_trustlook
        clean.contains("trellix") -> R.drawable.ic_vendor_trellix
        clean.contains("rising") || clean.contains("ruixing") -> R.drawable.ic_vendor_rising
        clean.contains("kingsoft") || clean.contains("duba") || clean.contains("cheetah") -> R.drawable.ic_vendor_kingsoft
        clean.contains("bkav") -> R.drawable.ic_vendor_bkav
        clean.contains("emsisoft") -> R.drawable.ic_vendor_emsisoft
        clean.contains("ikarus") -> R.drawable.ic_vendor_ikarus
        clean.contains("k7") -> R.drawable.ic_vendor_k7
        clean.contains("antiy") || clean.contains("avl") -> R.drawable.ic_vendor_antiy
        clean.contains("cmc") -> R.drawable.ic_vendor_cmc
        clean.contains("huorong") -> R.drawable.ic_vendor_huorong
        clean.contains("webroot") -> R.drawable.ic_vendor_webroot
        clean.contains("xcitium") || clean.contains("comodo") -> R.drawable.ic_vendor_xcitium
        clean.contains("zillya") -> R.drawable.ic_vendor_zillya
        clean.contains("lionic") -> R.drawable.ic_vendor_lionic
        clean.contains("nano") -> R.drawable.ic_vendor_nano
        clean.contains("tachyon") || clean.contains("inca") -> R.drawable.ic_vendor_tachyon
        clean.contains("rocketcyber") -> R.drawable.ic_vendor_rocketcyber
        clean.contains("varist") -> R.drawable.ic_vendor_varist
        clean.contains("xvirus") -> R.drawable.ic_vendor_xvirus
        clean.contains("virit") || clean.contains("tgsoft") -> R.drawable.ic_vendor_virit
        clean.contains("aurora") || clean.contains("secureage") -> R.drawable.ic_vendor_aurora
        clean.contains("crowdstrike") || clean.contains("falcon") -> R.drawable.ic_vendor_crowdstrike
        clean.contains("sentinel") -> R.drawable.ic_vendor_sentinelone
        clean.contains("fortinet") || clean.contains("forti") -> R.drawable.ic_vendor_fortinet
        clean.contains("fsecure") -> R.drawable.ic_vendor_fsecure
        clean.contains("withsecure") -> R.drawable.ic_vendor_withsecure
        clean.contains("gdata") -> R.drawable.ic_vendor_gdata
        clean.contains("paloalto") || clean.contains("wildfire") -> R.drawable.ic_vendor_paloalto
        clean.contains("zonealarm") -> R.drawable.ic_vendor_zonealarm
        clean.contains("zoner") -> R.drawable.ic_vendor_zoner
        clean.contains("totaldefense") -> R.drawable.ic_vendor_totaldefense
        clean.contains("tencent") || clean.contains("qq") -> R.drawable.ic_vendor_tencent
        clean.contains("yandex") -> R.drawable.ic_vendor_yandex
        clean.contains("alyac") -> R.drawable.ic_vendor_alyac
        clean.contains("arcabit") -> R.drawable.ic_vendor_arcabit
        clean.contains("superantispyware") -> R.drawable.ic_vendor_superantispyware
        clean.contains("vipre") -> R.drawable.ic_vendor_vipre
        clean.contains("cynet") -> R.drawable.ic_vendor_cynet
        else -> null
    }
}

@Composable
fun BrandLogoBadge(
    brandKey: String,
    modifier: Modifier = Modifier.size(22.dp)
) {
    val drawableRes = getOfficialVendorDrawable(brandKey)

    if (drawableRes != null) {
        OfficialVendorLogo(drawableRes, brandKey, modifier)
    } else {
        when (brandKey) {
            "ThreatLensLocal" -> ThreatLensLocalLogo(modifier)
            "ThreatLensPacker" -> ThreatLensPackerLogo(modifier)
            "ThreatLensCert" -> ThreatLensCertLogo(modifier)
            "ThreatLensSigDb" -> ThreatLensSigDbLogo(modifier)
            "YARA" -> YaraLogo(modifier)
            "Alin", "Alin AI", "Predictive Alin AI" -> AlinAiLogo(modifier)
            "Vulnerability", "Vulnerability Assessment" -> VulnerabilityLogo(modifier)
            "DeepCDR", "CDR", "Deep CDR" -> DeepCdrLogo(modifier)
            "Sandbox", "Adaptive Sandbox" -> AdaptiveSandboxLogo(modifier)
            "ProactiveDlp", "DLP", "Proactive DLP" -> ProactiveDlpLogo(modifier)
            "AiContentInspector", "AIC", "AI Content Inspector" -> AiContentInspectorLogo(modifier)
            "CountryOfOrigin", "Country of Origin" -> CountryOfOriginLogo(modifier)
            else -> {
                val vendor = SubEngineRegistry.getVendorBrand(brandKey)
                val fallbackDrawable = getOfficialVendorDrawable(vendor.name)
                if (fallbackDrawable != null) {
                    OfficialVendorLogo(fallbackDrawable, vendor.name, modifier)
                } else {
                    Canvas(modifier = modifier) {
                        val w = size.width
                        val h = size.height
                        drawRoundRect(
                            color = vendor.color,
                            cornerRadius = CornerRadius(w * 0.24f, h * 0.24f)
                        )
                        val shield = Path().apply {
                            moveTo(w * 0.50f, h * 0.22f)
                            lineTo(w * 0.74f, h * 0.34f)
                            lineTo(w * 0.74f, h * 0.58f)
                            cubicTo(w * 0.74f, h * 0.74f, w * 0.50f, h * 0.84f, w * 0.50f, h * 0.84f)
                            cubicTo(w * 0.50f, h * 0.84f, w * 0.26f, h * 0.74f, w * 0.26f, h * 0.58f)
                            lineTo(w * 0.26f, h * 0.34f)
                            close()
                        }
                        drawPath(shield, Color.White, style = Stroke(width = w * 0.08f))
                    }
                }
            }
        }
    }
}

@Composable
fun EngineLogoIcon(
    engineName: String,
    modifier: Modifier = Modifier.size(24.dp)
) {
    val directDrawable = getOfficialVendorDrawable(engineName)
    if (directDrawable != null) {
        OfficialVendorLogo(directDrawable, engineName, modifier)
    } else {
        val brand = EngineRegistry.getBrand(engineName)
        BrandLogoBadge(brandKey = brand.brandKey, modifier = modifier)
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
        VendorBrand("Zoner", "Zoner", Color(0xFF689F38), "ZON"),
        VendorBrand("Rising", "Rising", Color(0xFFFFB300), "RSG"),
        VendorBrand("Lionic", "Lionic", Color(0xFF1E88E5), "LNC"),
        VendorBrand("AlienVault", "AlienVault", Color(0xFF66BB6A), "OTX"),
        VendorBrand("Trellix", "Trellix", Color(0xFFE53935), "TLX"),
        VendorBrand("Huorong", "Huorong", Color(0xFFFF9800), "HR"),
        VendorBrand("Webroot", "Webroot", Color(0xFF7CB342), "WBR"),
        VendorBrand("Xcitium", "Xcitium", Color(0xFFD32F2F), "XCT"),
        VendorBrand("RocketCyber", "RocketCyber", Color(0xFF0288D1), "RC"),
        VendorBrand("Varist", "Varist", Color(0xFF00897B), "VAR"),
        VendorBrand("Xvirus", "Xvirus", Color(0xFFE53935), "XV"),
        VendorBrand("Vir.IT", "VirIT", Color(0xFF1976D2), "VIR"),
        VendorBrand("VirIT", "VirIT", Color(0xFF1976D2), "VIR"),
        VendorBrand("Aurora", "Aurora", Color(0xFF3949AB), "AUR"),
        VendorBrand("SecureAge", "Aurora", Color(0xFF3949AB), "AUR")
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
            clean.contains("alin") -> return VendorBrand(name, "Alin", Color(0xFF6C5CE7), "ALIN")
            clean.contains("metascan") -> return VendorBrand(name, "MetaDefender", Color(0xFF0072CE), "META")
            clean.contains("vulnerability") -> return VendorBrand(name, "Vulnerability", Color(0xFFFF7675), "VULN")
            clean.contains("cdr") -> return VendorBrand(name, "DeepCDR", Color(0xFF00CEC9), "CDR")
            clean.contains("sandbox") -> return VendorBrand(name, "Sandbox", Color(0xFF0284C7), "SBX")
            clean.contains("dlp") -> return VendorBrand(name, "ProactiveDlp", Color(0xFF0369A1), "DLP")
            clean.contains("content inspector") || clean.contains("ai content") -> return VendorBrand(name, "AiContentInspector", Color(0xFF7C3AED), "AIC")
            clean.contains("country") || clean.contains("origin") -> return VendorBrand(name, "CountryOfOrigin", Color(0xFF4F46E5), "COO")
            clean.contains("sentinel") -> return VendorBrand(name, "SentinelOne", Color(0xFF4E2A84), "S1")
            clean.contains("crowdstrike") || clean.contains("falcon") -> return VendorBrand(name, "CrowdStrike", Color(0xFFE2231A), "CS")
            clean.contains("fortinet") || clean.contains("forti") -> return VendorBrand(name, "Fortinet", Color(0xFFDA291C), "FT")
            clean.contains("f-secure") || clean.contains("fsecure") -> return VendorBrand(name, "F-Secure", Color(0xFF0072CE), "FS")
            clean.contains("withsecure") -> return VendorBrand(name, "WithSecure", Color(0xFF0072CE), "WS")
            clean.contains("tencent") -> return VendorBrand(name, "Tencent", Color(0xFF12B7F5), "TC")
            clean.contains("yandex") -> return VendorBrand(name, "Yandex", Color(0xFFFF0000), "YA")
            clean.contains("ikarus") -> return VendorBrand(name, "Ikarus", Color(0xFF388E3C), "IKR")
            clean.contains("rising") || clean.contains("ruixing") -> return VendorBrand(name, "Rising", Color(0xFFFFB300), "RSG")
            clean.contains("lionic") -> return VendorBrand(name, "Lionic", Color(0xFF1E88E5), "LNC")
            clean.contains("k7") -> return VendorBrand(name, "K7", Color(0xFF00897B), "K7")
            clean.contains("alienvault") || clean.contains("otx") -> return VendorBrand(name, "AlienVault", Color(0xFF66BB6A), "OTX")
            clean.contains("trellix") -> return VendorBrand(name, "Trellix", Color(0xFFE53935), "TLX")
            clean.contains("antiy") -> return VendorBrand(name, "Antiy", Color(0xFF5E35B1), "ANT")
            clean.contains("huorong") -> return VendorBrand(name, "Huorong", Color(0xFFFF9800), "HR")
            clean.contains("webroot") -> return VendorBrand(name, "Webroot", Color(0xFF7CB342), "WBR")
            clean.contains("xcitium") || clean.contains("comodo") -> return VendorBrand(name, "Xcitium", Color(0xFFD32F2F), "XCT")
            clean.contains("zillya") -> return VendorBrand(name, "Zillya", Color(0xFF7CB342), "ZIL")
            clean.contains("tachyon") -> return VendorBrand(name, "Tachyon", Color(0xFF1E88E5), "TY")
            clean.contains("nano") -> return VendorBrand(name, "NANO", Color(0xFF546E7A), "NANO")
            clean.contains("rocketcyber") -> return VendorBrand(name, "RocketCyber", Color(0xFF0288D1), "RC")
            clean.contains("varist") -> return VendorBrand(name, "Varist", Color(0xFF00897B), "VAR")
            clean.contains("xvirus") -> return VendorBrand(name, "Xvirus", Color(0xFFE53935), "XV")
            clean.contains("virit") || clean.contains("vir.it") -> return VendorBrand(name, "VirIT", Color(0xFF1976D2), "VIR")
            clean.contains("aurora") || clean.contains("secureage") -> return VendorBrand(name, "Aurora", Color(0xFF3949AB), "AUR")
            clean.contains("gdata") || clean.contains("g-data") -> return VendorBrand(name, "GData", Color(0xFFD50000), "GD")
            clean.contains("bkav") -> return VendorBrand(name, "Bkav", Color(0xFFFF6D00), "BK")
            clean.contains("kingsoft") || clean.contains("duba") -> return VendorBrand(name, "Kingsoft", Color(0xFF00ACC1), "KS")
            clean.contains("trustlook") -> return VendorBrand(name, "Trustlook", Color(0xFF00B0FF), "TL")
            clean.contains("emsisoft") -> return VendorBrand(name, "Emsisoft", Color(0xFF0091EA), "EMS")
            clean.contains("cmc") -> return VendorBrand(name, "CMC", Color(0xFF43A047), "CMC")
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
        val isItemClean = findingText.contains("clean", ignoreCase = true) ||
                          findingText.contains("no threat", ignoreCase = true) ||
                          findingText.contains("verified safe", ignoreCase = true) ||
                          findingText.contains("0/", ignoreCase = true) ||
                          findingText.contains("no vulnerabilities", ignoreCase = true) ||
                          findingText.contains("0 known", ignoreCase = true) ||
                          findingText.contains("allowed", ignoreCase = true) ||
                          findingText.contains("no restricted", ignoreCase = true)

        val findingColor = when {
            isItemClean -> NeonEmerald
            isMalicious -> NeonCrimson
            else -> CyberAmber
        }

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
                // Authentic Brand Logo Badge (Exact Official Vector Logo Matching)
                val directLogo = getOfficialVendorDrawable(vendorName) ?: getOfficialVendorDrawable(vendor.brandKey)
                if (directLogo != null) {
                    OfficialVendorLogo(
                        drawableRes = directLogo,
                        contentDescription = vendorName,
                        modifier = Modifier.size(24.dp)
                    )
                } else {
                    BrandLogoBadge(
                        brandKey = vendor.brandKey,
                        modifier = Modifier.size(24.dp)
                    )
                }
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
                        color = findingColor,
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
        val isItemClean = item.contains("clean", ignoreCase = true) ||
                          item.contains("safe", ignoreCase = true) ||
                          item.contains("0 known", ignoreCase = true) ||
                          item.contains("no threat", ignoreCase = true) ||
                          item.contains("no vulnerabilities", ignoreCase = true) ||
                          item.contains("no restricted", ignoreCase = true) ||
                          item.contains("0/", ignoreCase = true) ||
                          !isMalicious

        Row(
            modifier = modifier.fillMaxWidth().padding(vertical = 2.dp),
            verticalAlignment = Alignment.Top
        ) {
            Text(
                text = "• ",
                color = if (isItemClean) NeonEmerald else NeonCrimson,
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

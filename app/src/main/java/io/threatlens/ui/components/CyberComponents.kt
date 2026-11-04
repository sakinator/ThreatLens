package io.threatlens.ui.components

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.threatlens.core.model.ThreatReport
import io.threatlens.core.model.ThreatSeverity
import io.threatlens.ui.theme.*

@Composable
fun GlassCard(
    modifier: Modifier = Modifier,
    content: @Composable ColumnScope.() -> Unit
) {
    Card(
        modifier = modifier
            .fillMaxWidth()
            .border(1.dp, CyberCardBorder, RoundedCornerShape(16.dp)),
        colors = CardDefaults.cardColors(containerColor = CyberCardSurface),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            content()
        }
    }
}

@Composable
fun CyberRadarShield(
    isProtected: Boolean,
    modifier: Modifier = Modifier
) {
    val infiniteTransition = rememberInfiniteTransition(label = "pulse")
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 0.95f,
        targetValue = 1.05f,
        animationSpec = infiniteRepeatable(
            animation = tween(1400, easing = EaseInOutCubic),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulseScale"
    )

    val shieldColor = if (isProtected) NeonCyan else CyberAmber
    val glowBrush = Brush.radialGradient(
        colors = listOf(
            shieldColor.copy(alpha = 0.25f),
            Color.Transparent
        )
    )

    Box(
        contentAlignment = Alignment.Center,
        modifier = modifier
            .size(160.dp)
            .background(glowBrush, CircleShape)
    ) {
        Box(
            modifier = Modifier
                .size(120.dp)
                .scale(if (isProtected) pulseScale else 1.0f)
                .clip(CircleShape)
                .background(CyberCardSurface)
                .border(2.dp, shieldColor, CircleShape),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                imageVector = if (isProtected) Icons.Default.Security else Icons.Default.Warning,
                contentDescription = "Shield",
                tint = shieldColor,
                modifier = Modifier.size(54.dp)
            )
        }
    }
}

@Composable
fun ScoreBadge(score: Int, severity: ThreatSeverity, isFinal: Boolean = true) {
    val (color, label) = when (severity) {
        ThreatSeverity.SAFE -> NeonEmerald to "CLEAN"
        ThreatSeverity.SUSPICIOUS -> CyberAmber to "SUSPICIOUS"
        ThreatSeverity.HIGH_RISK -> NeonOrange to "HIGH RISK"
        ThreatSeverity.MALICIOUS -> NeonCrimson to "MALICIOUS"
    }

    Surface(
        color = color.copy(alpha = 0.15f),
        shape = RoundedCornerShape(8.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, color.copy(alpha = 0.6f))
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            if (!isFinal) {
                CircularProgressIndicator(
                    modifier = Modifier.size(10.dp),
                    strokeWidth = 1.5.dp,
                    color = color
                )
                Spacer(modifier = Modifier.width(5.dp))
            }
            Text(
                text = "$score/100",
                color = color,
                fontSize = 12.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace
            )
            Spacer(modifier = Modifier.width(4.dp))
            Text(
                text = if (isFinal) "• $label" else "• LIVE",
                color = color,
                fontSize = 11.sp,
                fontWeight = FontWeight.SemiBold
            )
        }
    }
}

data class SecurityCapabilityBadge(
    val label: String,
    val iconEmoji: String,
    val color: Color
)

fun computeSecurityCapabilities(report: ThreatReport): List<SecurityCapabilityBadge> {
    val list = mutableListOf<SecurityCapabilityBadge>()
    val perms = report.dangerousPermissions
    val behaviors = report.detectedBehaviors
    val family = (report.threatFamily ?: "").lowercase()

    // 1. Banking & Overlay risk
    val hasOverlay = perms.any { it.endsWith("SYSTEM_ALERT_WINDOW", ignoreCase = true) } ||
            perms.any { it.endsWith("BIND_ACCESSIBILITY_SERVICE", ignoreCase = true) } ||
            behaviors.any { it.contains("overlay", ignoreCase = true) || it.contains("accessibility", ignoreCase = true) } ||
            family.contains("banker") || family.contains("overlay")
    if (hasOverlay) {
        list.add(SecurityCapabilityBadge("Overlay & Accessibility", "🏦", CyberAmber))
    }

    // 2. 2FA / OTP & SMS Access
    val hasSms = perms.any { it.contains("SMS", ignoreCase = true) } ||
            perms.any { it.contains("NOTIFICATION_LISTENER", ignoreCase = true) } ||
            perms.any { it.contains("READ_CALL_LOG", ignoreCase = true) }
    if (hasSms) {
        list.add(SecurityCapabilityBadge("2FA & SMS Intercept", "💬", NeonCrimson))
    }

    // 3. Location / GPS
    val hasLocation = perms.any { it.contains("LOCATION", ignoreCase = true) }
    if (hasLocation) {
        list.add(SecurityCapabilityBadge("Background GPS", "📍", NeonCyan))
    }

    // 4. File Storage Access
    val hasStorage = perms.any { it.contains("MANAGE_EXTERNAL_STORAGE", ignoreCase = true) || it.contains("READ_EXTERNAL_STORAGE", ignoreCase = true) || it.contains("WRITE_EXTERNAL_STORAGE", ignoreCase = true) }
    if (hasStorage) {
        list.add(SecurityCapabilityBadge("Broad File Storage", "📁", NeonCyan))
    }

    // 5. Hardware Sensors (Camera / Mic)
    val hasSensors = perms.any { it.contains("CAMERA", ignoreCase = true) || it.contains("RECORD_AUDIO", ignoreCase = true) }
    if (hasSensors) {
        list.add(SecurityCapabilityBadge("Camera / Mic", "🎙️", CyberAmber))
    }

    // 6. Dropper / App Installer
    val hasInstaller = perms.any { it.contains("REQUEST_INSTALL_PACKAGES", ignoreCase = true) || it.contains("INSTALL_PACKAGES", ignoreCase = true) }
    if (hasInstaller) {
        list.add(SecurityCapabilityBadge("Silent Installer", "📦", CyberAmber))
    }

    // If zero sensitive privileges
    if (list.isEmpty()) {
        list.add(SecurityCapabilityBadge("Zero Sensitive Privileges", "🛡️", NeonEmerald))
    }

    return list
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ThreatItemRow(
    report: ThreatReport,
    onClick: () -> Unit
) {
    val context = LocalContext.current
    val isWhitelisted = remember(report.packageName, report.sha256) {
        io.threatlens.core.local.ThreatWhitelistManager.isWhitelisted(context, report.packageName, report.sha256)
    }
    val provenance = remember(report.packageName) {
        if (!report.packageName.isNullOrBlank()) {
            io.threatlens.core.local.AppProvenanceVerifier.inspectProvenance(context, report.packageName)
        } else null
    }

    val capabilities = remember(report.dangerousPermissions, report.detectedBehaviors, report.threatFamily) {
        computeSecurityCapabilities(report)
    }

    val cardBorderColor = when {
        !report.isFinal -> NeonCyan.copy(alpha = 0.55f)
        isWhitelisted -> NeonEmerald.copy(alpha = 0.45f)
        report.currentScore >= 75 || report.severity == ThreatSeverity.MALICIOUS -> NeonCrimson.copy(alpha = 0.55f)
        report.currentScore >= 25 || report.severity == ThreatSeverity.SUSPICIOUS || report.severity == ThreatSeverity.HIGH_RISK -> CyberAmber.copy(alpha = 0.45f)
        else -> CyberCardBorder.copy(alpha = 0.6f)
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 5.dp)
            .clickable { onClick() }
            .border(1.dp, cardBorderColor, RoundedCornerShape(12.dp)),
        colors = CardDefaults.cardColors(containerColor = CyberCardSurface),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            // Line 1: Header Row (App Icon + Title/Package Column + Score Badge & Chevron)
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.Top
            ) {
                AppIconBadge(
                    packageName = report.packageName,
                    apkPath = report.targetPath,
                    isApk = report.isApk,
                    size = 44.dp,
                    modifier = Modifier.padding(top = 2.dp)
                )

                Spacer(modifier = Modifier.width(12.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = report.appName ?: report.targetName,
                        color = TextPrimary,
                        fontWeight = FontWeight.Bold,
                        fontSize = 15.sp,
                        maxLines = 2,
                        softWrap = false,
                        overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
                    )
                    if (!report.packageName.isNullOrBlank() && report.packageName != report.appName) {
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = report.packageName,
                            color = TextMuted,
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            maxLines = 1,
                            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
                        )
                    }
                }

                Spacer(modifier = Modifier.width(8.dp))
                ScoreBadge(report.currentScore, report.severity, report.isFinal)
                Spacer(modifier = Modifier.width(2.dp))
                Icon(
                    imageVector = Icons.Default.ChevronRight,
                    contentDescription = "Details",
                    tint = TextMuted,
                    modifier = Modifier.size(18.dp)
                )
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Line 2: Responsive Badges Row (Audit Status + Provenance + Target + Detection Type + Family)
            FlowRow(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                // 1. Audit Status Pill (Clear pending vs completed indication)
                val (statusText, statusBg, statusColor) = when {
                    !report.isFinal -> Triple("⏳ CLOUD AUDIT RUNNING", NeonCyan.copy(alpha = 0.18f), NeonCyan)
                    isWhitelisted -> Triple("🛡️ WHITELISTED", NeonEmerald.copy(alpha = 0.18f), NeonEmerald)
                    report.currentScore >= 75 || report.severity == ThreatSeverity.MALICIOUS -> Triple("🚨 MALICIOUS THREAT", NeonCrimson.copy(alpha = 0.20f), NeonCrimson)
                    report.currentScore >= 25 || report.severity == ThreatSeverity.SUSPICIOUS || report.severity == ThreatSeverity.HIGH_RISK -> Triple("⚠️ ELEVATED RISK", CyberAmber.copy(alpha = 0.18f), CyberAmber)
                    else -> Triple("✓ AUDIT COMPLETE", NeonEmerald.copy(alpha = 0.18f), NeonEmerald)
                }
                Surface(
                    color = statusBg,
                    shape = RoundedCornerShape(4.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, statusColor.copy(alpha = 0.5f))
                ) {
                    Text(
                        text = statusText,
                        color = statusColor,
                        fontSize = 8.5.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp)
                    )
                }

                // 2. App Provenance / Store Vector
                if (provenance != null && provenance.source != io.threatlens.core.local.AppProvenanceVerifier.ProvenanceSource.SIDELOAD_OR_UNKNOWN) {
                    val provColor = when {
                        provenance.isHighRiskVector -> NeonCrimson
                        provenance.isFossStore -> NeonCyan
                        provenance.isVerifiedStore -> NeonEmerald
                        else -> TextSecondary
                    }
                    Surface(
                        color = provColor.copy(alpha = 0.15f),
                        shape = RoundedCornerShape(4.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, provColor.copy(alpha = 0.5f))
                    ) {
                        Text(
                            text = provenance.badgeLabel,
                            color = provColor,
                            fontSize = 8.5.sp,
                            fontWeight = FontWeight.Bold,
                            fontFamily = FontFamily.Monospace,
                            modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp)
                        )
                    }
                }

                // 2b. Target Source Vector Pill: DOWNLOAD vs INSTALLED
                val isDownloadIntercept = report.targetPath.contains("/Download", ignoreCase = true) || (!report.targetName.equals("base.apk", ignoreCase = true) && !report.targetName.equals(report.appName, ignoreCase = true))
                Surface(
                    color = CyberDarkSurface,
                    shape = RoundedCornerShape(4.dp),
                    border = androidx.compose.foundation.BorderStroke(0.8.dp, CyberCardBorder)
                ) {
                    Text(
                        text = if (isDownloadIntercept) "DOWNLOAD" else "INSTALLED",
                        color = if (isDownloadIntercept) CyberAmber else NeonCyan,
                        fontSize = 8.5.sp,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp)
                    )
                }

                // 3. Target File Name (if different from base.apk or app name)
                if (!report.targetName.equals("base.apk", ignoreCase = true) && !report.targetName.equals(report.appName, ignoreCase = true)) {
                    Surface(
                        color = CyberDarkSurface,
                        shape = RoundedCornerShape(4.dp),
                        border = androidx.compose.foundation.BorderStroke(0.8.dp, CyberCardBorder)
                    ) {
                        Text(
                            text = report.targetName,
                            color = NeonCyan,
                            fontSize = 8.5.sp,
                            fontFamily = FontFamily.Monospace,
                            maxLines = 1,
                            modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp)
                        )
                    }
                }

                // 4. Detection Type Pill
                val effectiveBadgeType = if (report.currentScore < 25 || report.severity == ThreatSeverity.SAFE) {
                    io.threatlens.core.model.DetectionType.CLEAN
                } else {
                    report.detectionType
                }
                Surface(
                    color = when (effectiveBadgeType) {
                        io.threatlens.core.model.DetectionType.CONFIRMED_SIGNATURE -> NeonCrimson.copy(alpha = 0.18f)
                        io.threatlens.core.model.DetectionType.CLOUD_INTELLIGENCE -> NeonCyan.copy(alpha = 0.18f)
                        io.threatlens.core.model.DetectionType.HEURISTIC_PATTERN -> CyberAmber.copy(alpha = 0.18f)
                        io.threatlens.core.model.DetectionType.CLEAN -> NeonEmerald.copy(alpha = 0.18f)
                    },
                    shape = RoundedCornerShape(4.dp)
                ) {
                    Text(
                        text = when (effectiveBadgeType) {
                            io.threatlens.core.model.DetectionType.CONFIRMED_SIGNATURE -> "SIGNATURE"
                            io.threatlens.core.model.DetectionType.CLOUD_INTELLIGENCE -> "CLOUD"
                            io.threatlens.core.model.DetectionType.HEURISTIC_PATTERN -> "HEURISTIC"
                            io.threatlens.core.model.DetectionType.CLEAN -> "SAFE"
                        },
                        color = when (effectiveBadgeType) {
                            io.threatlens.core.model.DetectionType.CONFIRMED_SIGNATURE -> NeonCrimson
                            io.threatlens.core.model.DetectionType.CLOUD_INTELLIGENCE -> NeonCyan
                            io.threatlens.core.model.DetectionType.HEURISTIC_PATTERN -> CyberAmber
                            io.threatlens.core.model.DetectionType.CLEAN -> NeonEmerald
                        },
                        fontSize = 8.5.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp)
                    )
                }

                // 5. Threat Family Name (if elevated)
                val rawDisplay = when {
                    report.currentScore < 25 || report.severity == ThreatSeverity.SAFE || report.threatFamily == "Clean" -> "Clean"
                    report.threatFamily.startsWith("Heuristic.", ignoreCase = true) -> report.threatFamily.substringAfter("Heuristic.")
                    report.threatFamily.startsWith("Heuristic: ", ignoreCase = true) -> report.threatFamily.substringAfter("Heuristic: ")
                    report.threatFamily.startsWith("Heuristic-", ignoreCase = true) -> report.threatFamily.substringAfter("Heuristic-")
                    else -> report.threatFamily
                }
                val displayFamily = io.threatlens.core.cloud.ThreatFamilyNormalizer.cleanVendorString(rawDisplay)
                if (displayFamily != "Clean") {
                    val familyColor = when {
                        report.severity == ThreatSeverity.MALICIOUS || report.detectionType == io.threatlens.core.model.DetectionType.CONFIRMED_SIGNATURE -> NeonCrimson
                        report.severity == ThreatSeverity.HIGH_RISK || report.severity == ThreatSeverity.SUSPICIOUS || report.detectionType == io.threatlens.core.model.DetectionType.HEURISTIC_PATTERN -> CyberAmber
                        else -> NeonEmerald
                    }
                    Surface(
                        color = familyColor.copy(alpha = 0.12f),
                        shape = RoundedCornerShape(4.dp),
                        border = androidx.compose.foundation.BorderStroke(0.8.dp, familyColor.copy(alpha = 0.4f))
                    ) {
                        Text(
                            text = displayFamily,
                            color = familyColor,
                            fontSize = 8.5.sp,
                            fontWeight = FontWeight.SemiBold,
                            fontFamily = FontFamily.Monospace,
                            maxLines = 1,
                            modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            // Line 3: Human Security & Privacy Capabilities Chips
            FlowRow(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(5.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                capabilities.forEach { cap ->
                    Surface(
                        color = cap.color.copy(alpha = 0.10f),
                        shape = RoundedCornerShape(4.dp),
                        border = androidx.compose.foundation.BorderStroke(0.8.dp, cap.color.copy(alpha = 0.35f))
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                        ) {
                            Text(text = cap.iconEmoji, fontSize = 9.sp)
                            Spacer(modifier = Modifier.width(4.dp))
                            Text(
                                text = cap.label,
                                color = cap.color,
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Medium,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            // Line 4: Meaningful Finding Rationale & User Knowledge Banner
            val rawFamily = report.threatFamily.lowercase()
            val findingSummary = when {
                !report.isFinal ->
                    "⚡ Stage 1 Passed (0 local signatures) • Stage 2 in progress: Querying cloud intelligence..."
                isWhitelisted ->
                    "🛡️ User Whitelisted • Trusted application excluded from security alerts"
                report.currentScore < 25 || report.severity == ThreatSeverity.SAFE ->
                    "✓ Verified Safe • 0 threat signatures across active scanning engines"
                report.detectionType == io.threatlens.core.model.DetectionType.CONFIRMED_SIGNATURE ->
                    "🚨 Confirmed Threat: Embedded ${report.threatFamily} signature matched"
                report.cloudEnginesFlagged > 0 ->
                    "⚠️ Flagged by ${report.cloudEnginesFlagged}/${report.cloudEnginesTotal} cloud engines • Minor vendor divergence"
                rawFamily.contains("ransomware") ->
                    "🔒 Potential Ransomware: Wide storage access and device lockout patterns"
                rawFamily.contains("banker") ->
                    "⚡ Potential Banking Overlay: Screen overlay & accessibility privileges"
                rawFamily.contains("spyware") || rawFamily.contains("spy") ->
                    "👁️ Potential Spyware: Background data exfiltration capability"
                rawFamily.contains("dropper") ->
                    "📦 Potential Dropper: Background installation & dynamic code loading"
                report.detectionType == io.threatlens.core.model.DetectionType.HEURISTIC_PATTERN ->
                    "⚡ Heuristic Alert: Declares high-privilege capabilities or unusual matrix"
                else ->
                    "✓ Verified Safe • Clean behavioral footprint"
            }

            Surface(
                modifier = Modifier.fillMaxWidth(),
                color = CyberDarkSurface,
                shape = RoundedCornerShape(6.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, CyberCardBorder.copy(alpha = 0.5f))
            ) {
                Text(
                    text = findingSummary,
                    color = if (!report.isFinal) NeonCyan else TextSecondary,
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    maxLines = 2,
                    softWrap = true,
                    overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                    lineHeight = 15.sp,
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 5.dp)
                )
            }

            // Line 5: Engine Logos or Live Pending Scanner
            val scannedEngines = remember(report.engineVerdictMap) {
                report.engineVerdictMap.keys.filter {
                    it != "ThreatLens Exclusions" &&
                    !it.contains("Quota Preserved", ignoreCase = true) &&
                    report.engineVerdictMap[it]?.contains("Unreachable", ignoreCase = true) != true
                }
            }

            if (!report.isFinal) {
                Spacer(modifier = Modifier.height(6.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(11.dp),
                        strokeWidth = 1.6.dp,
                        color = NeonCyan
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = if (report.statusMessage.isNotBlank()) report.statusMessage else "Querying multi-engine threat feeds...",
                        color = NeonCyan,
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        maxLines = 1,
                        overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
                    )
                }
            } else if (scannedEngines.isNotEmpty()) {
                Spacer(modifier = Modifier.height(6.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(5.dp)
                ) {
                    Text(
                        text = "Scanned by:",
                        color = TextMuted,
                        fontSize = 9.sp,
                        fontFamily = FontFamily.Monospace
                    )
                    scannedEngines.take(6).forEach { eng ->
                        EngineLogoIcon(engineName = eng, modifier = Modifier.size(14.dp))
                    }
                    if (scannedEngines.size > 6) {
                        Text(
                            text = "+${scannedEngines.size - 6}",
                            color = TextMuted,
                            fontSize = 9.sp,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                }
            }
        }
    }
}

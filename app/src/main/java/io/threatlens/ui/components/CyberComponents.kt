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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
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

@Composable
fun ThreatItemRow(
    report: ThreatReport,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
            .clickable { onClick() }
            .border(
                1.dp,
                if (!report.isFinal) NeonCyan.copy(alpha = 0.5f) else CyberCardBorder.copy(alpha = 0.6f),
                RoundedCornerShape(12.dp)
            ),
        colors = CardDefaults.cardColors(containerColor = CyberCardSurface),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.Top
            ) {
                // App Logo / APK Icon aligned with top
                AppIconBadge(
                    packageName = report.packageName,
                    apkPath = report.targetPath,
                    isApk = report.isApk,
                    size = 46.dp,
                    modifier = Modifier.padding(top = 2.dp)
                )

                Spacer(modifier = Modifier.width(12.dp))

                Column(modifier = Modifier.weight(1f)) {
                    // Line 1: App Name & Score Badge + Chevron
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(
                            text = report.appName ?: report.targetName,
                            color = TextPrimary,
                            fontWeight = FontWeight.Bold,
                            fontSize = 15.sp,
                            maxLines = 2,
                            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f)
                        )
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

                    Spacer(modifier = Modifier.height(3.dp))

                    // Line 2: Package Name on its own row with full width and ellipsis
                    if (!report.packageName.isNullOrBlank() && report.packageName != report.appName) {
                        Text(
                            text = report.packageName,
                            color = TextMuted,
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            maxLines = 1,
                            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                            modifier = Modifier.fillMaxWidth()
                        )
                        Spacer(modifier = Modifier.height(3.dp))
                    }

                    // Line 3: Threat Family & Detected File Badge (Full width)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        if (!report.targetName.equals("base.apk", ignoreCase = true) && !report.targetName.equals(report.appName, ignoreCase = true)) {
                            Surface(
                                color = CyberDarkSurface,
                                shape = RoundedCornerShape(4.dp)
                            ) {
                                Text(
                                    text = report.targetName,
                                    color = NeonCyan,
                                    fontSize = 9.sp,
                                    fontFamily = FontFamily.Monospace,
                                    maxLines = 1,
                                    modifier = Modifier.padding(horizontal = 4.dp, vertical = 1.dp)
                                )
                            }
                            Spacer(modifier = Modifier.width(6.dp))
                        }
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
                            shape = RoundedCornerShape(3.dp)
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
                                fontSize = 8.sp,
                                fontWeight = FontWeight.Bold,
                                fontFamily = FontFamily.Monospace,
                                modifier = Modifier.padding(horizontal = 4.dp, vertical = 1.dp)
                            )
                        }
                        Spacer(modifier = Modifier.width(6.dp))
                        val familyColor = when {
                            report.severity == ThreatSeverity.MALICIOUS || report.detectionType == io.threatlens.core.model.DetectionType.CONFIRMED_SIGNATURE -> NeonCrimson
                            report.severity == ThreatSeverity.HIGH_RISK || report.severity == ThreatSeverity.SUSPICIOUS || report.detectionType == io.threatlens.core.model.DetectionType.HEURISTIC_PATTERN -> CyberAmber
                            else -> NeonEmerald
                        }

                        val rawDisplay = when {
                            report.currentScore < 25 || report.severity == ThreatSeverity.SAFE || report.threatFamily == "Clean" -> "Clean"
                            report.threatFamily.startsWith("Heuristic.", ignoreCase = true) -> report.threatFamily.substringAfter("Heuristic.")
                            report.threatFamily.startsWith("Heuristic: ", ignoreCase = true) -> report.threatFamily.substringAfter("Heuristic: ")
                            report.threatFamily.startsWith("Heuristic-", ignoreCase = true) -> report.threatFamily.substringAfter("Heuristic-")
                            else -> report.threatFamily
                        }
                        val displayFamily = io.threatlens.core.cloud.ThreatFamilyNormalizer.cleanVendorString(rawDisplay)

                        Text(
                            text = displayFamily,
                            color = familyColor,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1,
                            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f, fill = false)
                        )
                    }
                }
            }

            // Live status message or pending engines line
            if (!report.isFinal || report.statusMessage.isNotBlank()) {
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = if (!report.isFinal) "⚡ ${report.statusMessage}" else report.statusMessage,
                    color = if (!report.isFinal) NeonCyan else TextSecondary,
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    maxLines = 1
                )
            }
        }
    }
}

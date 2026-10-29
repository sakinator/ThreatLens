package io.threatlens.ui.screens

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.threatlens.core.cloud.CloudThreatAggregator
import io.threatlens.core.cloud.VirusTotalProvider
import io.threatlens.core.model.ThreatReport
import io.threatlens.ui.components.AppIconBadge
import io.threatlens.ui.components.EngineLogoIcon
import io.threatlens.ui.components.EngineStatusBadge
import io.threatlens.ui.components.GlassCard
import io.threatlens.ui.components.ScoreBadge
import io.threatlens.ui.components.VendorFindingBadge
import io.threatlens.ui.theme.*
import java.io.File

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun ThreatDetailSheet(
    report: ThreatReport,
    onDismiss: () -> Unit,
    onDelete: (ThreatReport) -> Unit,
    onUploadSample: ((ThreatReport) -> Unit)? = null,
    uploadProgress: VirusTotalProvider.UploadProgress? = null,
    isVtKeyConfigured: Boolean = false
) {
    val context = LocalContext.current
    var showConfirmDeleteDialog by remember { mutableStateOf(false) }
    var showUploadConfirmDialog by remember { mutableStateOf(false) }
    val expandedEngines = remember { mutableStateMapOf<String, Boolean>() }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        containerColor = CyberDarkSurface,
        dragHandle = { BottomSheetDefaults.DragHandle(color = CyberCardBorder) }
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp)
                .verticalScroll(rememberScrollState())
        ) {
            // Header
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // App Logo / APK Icon
                AppIconBadge(
                    packageName = report.packageName,
                    apkPath = report.targetPath,
                    isApk = report.isApk,
                    size = 54.dp
                )

                Spacer(modifier = Modifier.width(14.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = report.appName ?: report.targetName,
                        color = TextPrimary,
                        fontSize = 18.sp,
                        fontWeight = FontWeight.Bold,
                        maxLines = 2,
                        overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
                    )
                    Spacer(modifier = Modifier.height(2.dp))

                    // Package Name on its own row with ellipsis (never wraps vertically)
                    if (!report.packageName.isNullOrBlank() && report.packageName != report.appName) {
                        Text(
                            text = report.packageName,
                            color = TextMuted,
                            fontSize = 12.sp,
                            fontFamily = FontFamily.Monospace,
                            maxLines = 1,
                            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                    }

                    val provenance = remember(report.packageName) {
                        if (!report.packageName.isNullOrBlank()) {
                            io.threatlens.core.local.AppProvenanceVerifier.inspectProvenance(context, report.packageName)
                        } else null
                    }

                    Row(verticalAlignment = Alignment.CenterVertically) {
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
                                    fontSize = 10.sp,
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    maxLines = 1,
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                )
                            }
                            Spacer(modifier = Modifier.width(6.dp))
                        }

                        Surface(
                            color = CyberCardSurface,
                            shape = RoundedCornerShape(4.dp)
                        ) {
                            Text(
                                text = if (report.targetName.equals("base.apk", ignoreCase = true)) "INSTALLED APP" else "APK: ${report.targetName}",
                                color = NeonCyan,
                                fontSize = 10.sp,
                                fontFamily = FontFamily.Monospace,
                                maxLines = 1,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                            )
                        }
                        Spacer(modifier = Modifier.width(6.dp))
                        val familyColor = when {
                            report.currentScore >= 75 || report.threatFamily.contains("Trojan", ignoreCase = true) || report.threatFamily.contains("Malware", ignoreCase = true) -> NeonCrimson
                            report.currentScore >= 25 || report.threatFamily.contains("Suspicious", ignoreCase = true) -> CyberAmber
                            else -> NeonEmerald
                        }
                        val cleanFamilyName = if (report.currentScore < 25) "Clean" else report.threatFamily.removePrefix("Heuristic.")
                        Text(
                            text = cleanFamilyName,
                            color = familyColor,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold,
                            maxLines = 1,
                            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
                        )
                    }
                }
                Spacer(modifier = Modifier.width(10.dp))
                ScoreBadge(report.currentScore, report.severity, report.isFinal)
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Prominent Detection Type Banner (Clear distinction between Confirmed Malware Signature vs Heuristic Pattern)
            Surface(
                color = when (report.detectionType) {
                    io.threatlens.core.model.DetectionType.CONFIRMED_SIGNATURE -> NeonCrimson.copy(alpha = 0.15f)
                    io.threatlens.core.model.DetectionType.CLOUD_INTELLIGENCE -> NeonCyan.copy(alpha = 0.15f)
                    io.threatlens.core.model.DetectionType.HEURISTIC_PATTERN -> CyberAmber.copy(alpha = 0.15f)
                    io.threatlens.core.model.DetectionType.CLEAN -> NeonEmerald.copy(alpha = 0.15f)
                },
                shape = RoundedCornerShape(8.dp),
                border = androidx.compose.foundation.BorderStroke(
                    1.dp,
                    when (report.detectionType) {
                        io.threatlens.core.model.DetectionType.CONFIRMED_SIGNATURE -> NeonCrimson.copy(alpha = 0.7f)
                        io.threatlens.core.model.DetectionType.CLOUD_INTELLIGENCE -> NeonCyan.copy(alpha = 0.7f)
                        io.threatlens.core.model.DetectionType.HEURISTIC_PATTERN -> CyberAmber.copy(alpha = 0.7f)
                        io.threatlens.core.model.DetectionType.CLEAN -> NeonEmerald.copy(alpha = 0.7f)
                    }
                ),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = when (report.detectionType) {
                            io.threatlens.core.model.DetectionType.CONFIRMED_SIGNATURE -> Icons.Default.Shield
                            io.threatlens.core.model.DetectionType.CLOUD_INTELLIGENCE -> Icons.Default.CloudQueue
                            io.threatlens.core.model.DetectionType.HEURISTIC_PATTERN -> Icons.Default.Radar
                            io.threatlens.core.model.DetectionType.CLEAN -> Icons.Default.CheckCircle
                        },
                        contentDescription = null,
                        tint = when (report.detectionType) {
                            io.threatlens.core.model.DetectionType.CONFIRMED_SIGNATURE -> NeonCrimson
                            io.threatlens.core.model.DetectionType.CLOUD_INTELLIGENCE -> NeonCyan
                            io.threatlens.core.model.DetectionType.HEURISTIC_PATTERN -> CyberAmber
                            io.threatlens.core.model.DetectionType.CLEAN -> NeonEmerald
                        },
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = when (report.detectionType) {
                            io.threatlens.core.model.DetectionType.CONFIRMED_SIGNATURE -> "CONFIRMED MALWARE (SIGNATURE MATCH)"
                            io.threatlens.core.model.DetectionType.CLOUD_INTELLIGENCE -> "CLOUD INTELLIGENCE CONSENSUS DETECTION"
                            io.threatlens.core.model.DetectionType.HEURISTIC_PATTERN -> "HEURISTIC PATTERN (NOT A CONFIRMED MALWARE SIGNATURE)"
                            io.threatlens.core.model.DetectionType.CLEAN -> "VERIFIED SAFE & TRUSTED"
                        },
                        color = when (report.detectionType) {
                            io.threatlens.core.model.DetectionType.CONFIRMED_SIGNATURE -> NeonCrimson
                            io.threatlens.core.model.DetectionType.CLOUD_INTELLIGENCE -> NeonCyan
                            io.threatlens.core.model.DetectionType.HEURISTIC_PATTERN -> CyberAmber
                            io.threatlens.core.model.DetectionType.CLEAN -> NeonEmerald
                        },
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Transparent Threat Score Calculation & Rationale Card
            GlassCard {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "Threat Score Calculation & Rationale",
                        color = TextPrimary,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 14.sp,
                        modifier = Modifier.weight(1f)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "${report.currentScore}/100",
                        color = if (report.currentScore >= 75) NeonCrimson else if (report.currentScore >= 25) CyberAmber else NeonEmerald,
                        fontWeight = FontWeight.Black,
                        fontSize = 15.sp,
                        fontFamily = FontFamily.Monospace,
                        softWrap = false,
                        maxLines = 1
                    )
                }

                Spacer(modifier = Modifier.height(10.dp))

                val breakdown = report.scoreBreakdown ?: io.threatlens.core.model.ScoreBreakdown(
                    permissionScore = minOf(report.currentScore, 15),
                    heuristicScore = maxOf(0, report.currentScore - minOf(report.currentScore, 15)),
                    cloudScore = report.cloudScore,
                    totalScore = report.currentScore,
                    rationale = "Consolidated threat score based on on-device and cloud telemetry."
                )

                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    ScoreComponentRow("Known Malware Signatures & RAT Payloads", "+${breakdown.signatureScore} pts", breakdown.signatureScore > 0)
                    ScoreComponentRow("Permissions & Runtime Capability Weight", "+${breakdown.permissionScore} pts", breakdown.permissionScore > 0)
                    ScoreComponentRow("Static Behavioral Heuristics (Dropper/Accessibility)", "+${breakdown.heuristicScore} pts", breakdown.heuristicScore > 0)
                    ScoreComponentRow("Cloud Threat Intelligence Consensus", "+${breakdown.cloudScore} pts", breakdown.cloudScore > 0)
                }

                Spacer(modifier = Modifier.height(10.dp))

                Surface(
                    color = CyberDarkSurface,
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.padding(10.dp),
                        verticalAlignment = Alignment.Top
                    ) {
                        Icon(Icons.Default.Info, contentDescription = null, tint = NeonCyan, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = breakdown.rationale.ifBlank {
                                if (report.currentScore >= 75) {
                                    "Critical Risk: Matches a verified malware payload or confirmed Trojan signature."
                                } else if (report.currentScore >= 25) {
                                    "Elevated Privilege Finding: This application declares sensitive Android permissions. While not a confirmed Trojan, review its capabilities if untrusted."
                                } else {
                                    "Safe & Verified: No malicious signatures or hostile behavioral patterns were identified."
                                }
                            },
                            color = TextSecondary,
                            fontSize = 11.sp,
                            lineHeight = 16.sp
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Dynamic Scanning Progress Banner
            if (!report.isFinal) {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(1.dp, NeonCyan.copy(alpha = 0.6f), RoundedCornerShape(12.dp)),
                    colors = CardDefaults.cardColors(containerColor = CyberCardSurface)
                ) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(16.dp),
                                strokeWidth = 2.dp,
                                color = NeonCyan
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "Dynamic Multi-Engine Scan in Progress",
                                color = NeonCyan,
                                fontWeight = FontWeight.Bold,
                                fontSize = 13.sp
                            )
                        }
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = report.statusMessage,
                            color = TextSecondary,
                            fontSize = 12.sp,
                            fontFamily = FontFamily.Monospace
                        )
                    }
                }
                Spacer(modifier = Modifier.height(14.dp))
            }

            // AI Threat Analysis & Multi-Engine Breakdown Card
            if (!report.aiExplanation.isNullOrBlank()) {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(1.dp, NeonCyan.copy(alpha = 0.5f), RoundedCornerShape(14.dp)),
                    colors = CardDefaults.cardColors(containerColor = CyberCardSurface)
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            EngineLogoIcon("Google Gemini", modifier = Modifier.size(24.dp))
                            Spacer(modifier = Modifier.width(10.dp))
                            Text(
                                text = if (report.isFinal) "ThreatLens AI Threat Analysis" else "ThreatLens AI Initial Assessment (Live Scanning...)",
                                color = NeonCyan,
                                fontWeight = FontWeight.Bold,
                                fontSize = 14.sp
                            )
                        }
                        Spacer(modifier = Modifier.height(12.dp))
                        FormattedAiAnalysisView(markdownText = report.aiExplanation)
                    }
                }
                Spacer(modifier = Modifier.height(14.dp))
            } else if (!report.isFinal) {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(1.dp, NeonCyan.copy(alpha = 0.35f), RoundedCornerShape(14.dp)),
                    colors = CardDefaults.cardColors(containerColor = CyberCardSurface)
                ) {
                    Row(
                        modifier = Modifier.padding(14.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp,
                            color = NeonCyan
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Column {
                            Text(
                                text = "ThreatLens AI Evaluating Telemetry...",
                                color = NeonCyan,
                                fontWeight = FontWeight.Bold,
                                fontSize = 13.sp
                            )
                            Text(
                                text = "Synthesizing multi-engine verdicts, vendor findings & permissions...",
                                color = TextMuted,
                                fontSize = 11.sp
                            )
                        }
                    }
                }
                Spacer(modifier = Modifier.height(14.dp))
            }

            // Unified Multi-Engine Source-by-Source Intelligence Breakdown
            GlassCard {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            text = "Multi-Engine Threat Intelligence",
                            color = TextPrimary,
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 14.sp
                        )
                        Text(
                            text = "On-device heuristics, zero-key public cloud & sandboxes",
                            color = TextSecondary,
                            fontSize = 11.sp
                        )
                    }
                    Surface(
                        color = CyberDarkSurface,
                        shape = RoundedCornerShape(6.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, NeonCyan.copy(alpha = 0.4f))
                    ) {
                        Text(
                            text = "${maxOf(report.engineVerdictMap.size, 7)} Sources",
                            color = NeonCyan,
                            fontSize = 10.sp,
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                        )
                    }
                }

                Spacer(modifier = Modifier.height(12.dp))

                val allEngines = report.engineVerdictMap.toList()
                val (activeEngines, inactiveEngines) = allEngines.partition { (_, verdict) ->
                    !verdict.contains("not configured", ignoreCase = true) && !verdict.contains("Auth-Key", ignoreCase = true)
                }

                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    activeEngines.forEach { (sourceName, verdict) ->
                        val isPending = report.pendingEngines.contains(sourceName) || verdict.contains("Querying", ignoreCase = true) || verdict.contains("Scanning", ignoreCase = true)
                        val isMaliciousFlag = verdict.startsWith("Flagged", ignoreCase = true) || verdict.contains("Malicious", ignoreCase = true)
                        val isSuspicious = !isMaliciousFlag && (verdict.startsWith("Suspicious", ignoreCase = true) || verdict.contains("Suspicious", ignoreCase = true))
                        val isClean = !isMaliciousFlag && !isSuspicious && (verdict.startsWith("Clean", ignoreCase = true) || verdict.contains("Clean", ignoreCase = true) || verdict.contains("Verified", ignoreCase = true))
                        val isExpanded = expandedEngines[sourceName] ?: false

                        Surface(
                            color = CyberDarkSurface,
                            shape = RoundedCornerShape(10.dp),
                            border = androidx.compose.foundation.BorderStroke(
                                1.dp,
                                when {
                                    isPending -> NeonCyan.copy(alpha = 0.5f)
                                    isMaliciousFlag -> NeonCrimson.copy(alpha = 0.5f)
                                    isSuspicious -> CyberAmber.copy(alpha = 0.5f)
                                    isClean -> NeonEmerald.copy(alpha = 0.25f)
                                    else -> CyberCardBorder
                                }
                            ),
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { expandedEngines[sourceName] = !isExpanded }
                        ) {
                            Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp)) {
                                val isOfflineEngine = sourceName.contains("ThreatLens", ignoreCase = true) ||
                                                      sourceName.contains("ClamAV", ignoreCase = true) ||
                                                      sourceName.contains("YARA", ignoreCase = true)
                                val isZeroKeyEngine = sourceName == "AlienVault OTX" || sourceName == "CIRCL Hashlookup"
                                val engineBadgeText = when {
                                    isOfflineEngine -> "OFFLINE"
                                    isZeroKeyEngine -> "ZERO-KEY"
                                    else -> "CLOUD API"
                                }
                                val engineBadgeColor = when {
                                    isOfflineEngine -> NeonCyan
                                    isZeroKeyEngine -> NeonEmerald
                                    else -> TextSecondary
                                }

                                // Line 1: Header Row (Logo + Full Title + Chevron)
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    EngineLogoIcon(sourceName, modifier = Modifier.size(22.dp))
                                    Spacer(modifier = Modifier.width(10.dp))

                                    Text(
                                        text = sourceName,
                                        color = TextPrimary,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 13.sp,
                                        maxLines = 2,
                                        modifier = Modifier.weight(1f)
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Icon(
                                        imageVector = if (isExpanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                                        contentDescription = "Expand",
                                        tint = TextMuted,
                                        modifier = Modifier.size(18.dp)
                                    )
                                }

                                // Line 2: Engine Type Tag (OFFLINE, ZERO-KEY, CLOUD API) + Status Badge Pill + Verdict Summary
                                Spacer(modifier = Modifier.height(4.dp))
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(start = 32.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Surface(
                                        color = CyberCardSurface,
                                        shape = RoundedCornerShape(4.dp)
                                    ) {
                                        Text(
                                            text = engineBadgeText,
                                            color = engineBadgeColor,
                                            fontSize = 8.sp,
                                            fontWeight = FontWeight.Bold,
                                            fontFamily = FontFamily.Monospace,
                                            maxLines = 1,
                                            softWrap = false,
                                            modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp)
                                        )
                                    }
                                    Spacer(modifier = Modifier.width(6.dp))

                                    // Status Badge: Uniform pill alignment
                                    Surface(
                                        color = when {
                                            isPending -> NeonCyan.copy(alpha = 0.15f)
                                            isMaliciousFlag -> NeonCrimson.copy(alpha = 0.18f)
                                            isSuspicious -> CyberAmber.copy(alpha = 0.18f)
                                            isClean -> NeonEmerald.copy(alpha = 0.18f)
                                            else -> CyberCardSurface
                                        },
                                        shape = RoundedCornerShape(6.dp)
                                    ) {
                                        Box(
                                            contentAlignment = Alignment.Center,
                                            modifier = Modifier.padding(horizontal = 7.dp, vertical = 2.dp)
                                        ) {
                                            if (isPending) {
                                                Row(verticalAlignment = Alignment.CenterVertically) {
                                                    CircularProgressIndicator(
                                                        modifier = Modifier.size(9.dp),
                                                        strokeWidth = 1.5.dp,
                                                        color = NeonCyan
                                                    )
                                                    Spacer(modifier = Modifier.width(4.dp))
                                                    Text(
                                                        text = "SCAN",
                                                        color = NeonCyan,
                                                        fontSize = 8.sp,
                                                        fontWeight = FontWeight.Bold,
                                                        fontFamily = FontFamily.Monospace
                                                    )
                                                }
                                            } else {
                                                Text(
                                                    text = when {
                                                        isMaliciousFlag -> "FLAGGED"
                                                        isSuspicious -> "SUSPICIOUS"
                                                        isClean -> "CLEAN"
                                                        verdict.contains("Unreachable", ignoreCase = true) -> "OFFLINE"
                                                        else -> "UNINDEXED"
                                                    },
                                                    color = when {
                                                        isMaliciousFlag -> NeonCrimson
                                                        isSuspicious -> CyberAmber
                                                        isClean -> NeonEmerald
                                                        verdict.contains("Unreachable", ignoreCase = true) -> TextMuted
                                                        else -> TextMuted
                                                    },
                                                    fontSize = 8.sp,
                                                    fontWeight = FontWeight.Bold,
                                                    fontFamily = FontFamily.Monospace
                                                )
                                            }
                                        }
                                    }

                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        text = verdict,
                                        color = when {
                                            isPending -> NeonCyan
                                            isMaliciousFlag -> NeonCrimson
                                            isSuspicious -> CyberAmber
                                            isClean -> NeonEmerald
                                            else -> TextMuted
                                        },
                                        fontSize = 11.sp,
                                        maxLines = if (isExpanded) Int.MAX_VALUE else 2,
                                        overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                                        modifier = Modifier.weight(1f)
                                    )
                                }

                                // Expanded Engine Intelligence Details
                                if (isExpanded) {
                                    Spacer(modifier = Modifier.height(10.dp))
                                    Divider(color = CyberCardBorder.copy(alpha = 0.4f))
                                    Spacer(modifier = Modifier.height(8.dp))

                                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                        Text(
                                            text = "Full Engine Result:",
                                            color = TextMuted,
                                            fontSize = 10.sp,
                                            fontWeight = FontWeight.Bold
                                        )
                                        Text(
                                            text = verdict,
                                            color = if (isMaliciousFlag) NeonCrimson else if (isSuspicious) CyberAmber else if (isClean) NeonEmerald else TextSecondary,
                                            fontSize = 12.sp,
                                            fontFamily = FontFamily.Monospace
                                        )

                                        val details = report.engineDetailsMap[sourceName] ?: emptyList()
                                        if (details.isNotEmpty()) {
                                            Spacer(modifier = Modifier.height(6.dp))
                                            Text(
                                                text = if (sourceName == "VirusTotal") "Security Vendor Findings (${details.size} detections):" else "Observed Technical Findings:",
                                                color = if (isMaliciousFlag) NeonCrimson else if (isSuspicious) CyberAmber else NeonCyan,
                                                fontSize = 11.sp,
                                                fontWeight = FontWeight.Bold
                                            )
                                            Spacer(modifier = Modifier.height(3.dp))
                                            Column(
                                                modifier = Modifier
                                                    .fillMaxWidth()
                                                    .background(CyberBlack, RoundedCornerShape(8.dp))
                                                    .border(1.dp, CyberCardBorder.copy(alpha = 0.6f), RoundedCornerShape(8.dp))
                                                    .padding(8.dp),
                                                verticalArrangement = Arrangement.spacedBy(6.dp)
                                            ) {
                                                details.forEach { item ->
                                                    VendorFindingBadge(item = item, isMalicious = isMaliciousFlag)
                                                }
                                            }
                                        }

                                        Spacer(modifier = Modifier.height(4.dp))
                                        Text(
                                            text = when (sourceName) {
                                                "ThreatLens Local Engine" -> "Analyzed offline in <20ms using local signature database & static bytecode inspection."
                                                "AlienVault OTX" -> "Open Threat Exchange public pulse database tracking community threat indicators."
                                                "CIRCL Hashlookup" -> "Validated against NIST National Software Reference Library (NSRL) and CIRCL CERT feeds."
                                                "VirusTotal" -> "Multi-scanner aggregating 70+ industry antivirus scanning engines."
                                                "MalwareBazaar" -> "Abuse.ch community database collecting known malware samples and signatures."
                                                "MetaDefender" -> "OPSWAT multiscanning cloud verifying binaries against commercial vendor engines."
                                                "Hybrid Analysis" -> "Falcon Sandbox behavioral analysis providing deep dynamic detonation."
                                                "Kaspersky OpenTIP" -> "Kaspersky Threat Intelligence Portal enterprise hash intelligence."
                                                "Filescan.io" -> "Next-generation automated malware analysis and IOC extraction."
                                                else -> "Threat intelligence engine report."
                                            },
                                            color = TextMuted,
                                            fontSize = 11.sp,
                                            lineHeight = 15.sp
                                        )

                                        val webReportUrl = CloudThreatAggregator.getEngineWebReportUrl(sourceName, report.sha256)
                                        if (!webReportUrl.isNullOrBlank()) {
                                            Spacer(modifier = Modifier.height(8.dp))
                                            OutlinedButton(
                                                onClick = {
                                                    try {
                                                        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(webReportUrl))
                                                        context.startActivity(intent)
                                                    } catch (_: Exception) {}
                                                },
                                                modifier = Modifier.fillMaxWidth(),
                                                shape = RoundedCornerShape(8.dp),
                                                border = androidx.compose.foundation.BorderStroke(1.dp, NeonCyan.copy(alpha = 0.5f)),
                                                colors = ButtonDefaults.outlinedButtonColors(
                                                    containerColor = NeonCyan.copy(alpha = 0.08f),
                                                    contentColor = NeonCyan
                                                ),
                                                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                                            ) {
                                                Icon(
                                                    imageVector = Icons.Default.OpenInNew,
                                                    contentDescription = "View Web Results",
                                                    modifier = Modifier.size(14.dp)
                                                )
                                                Spacer(modifier = Modifier.width(6.dp))
                                                Text(
                                                    text = "View Web Results ($sourceName) ↗",
                                                    fontSize = 11.sp,
                                                    fontWeight = FontWeight.SemiBold
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if (inactiveEngines.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(4.dp))
                        var showInactiveEngines by remember { mutableStateOf(false) }

                        Surface(
                            color = CyberBlack.copy(alpha = 0.6f),
                            shape = RoundedCornerShape(10.dp),
                            border = androidx.compose.foundation.BorderStroke(1.dp, CyberCardBorder.copy(alpha = 0.7f)),
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { showInactiveEngines = !showInactiveEngines }
                        ) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.Info,
                                        contentDescription = "Inactive Engines",
                                        tint = TextMuted,
                                        modifier = Modifier.size(16.dp)
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = "${inactiveEngines.size} Engines Inactive (Missing API Key)",
                                            color = TextSecondary,
                                            fontWeight = FontWeight.SemiBold,
                                            fontSize = 12.sp
                                        )
                                        Text(
                                            text = "Skipped during scan • Configure keys in Settings",
                                            color = TextMuted,
                                            fontSize = 10.sp
                                        )
                                    }
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Surface(
                                        color = CyberCardSurface,
                                        shape = RoundedCornerShape(4.dp)
                                    ) {
                                        Text(
                                            text = "NO KEY",
                                            color = TextMuted,
                                            fontSize = 8.sp,
                                            fontWeight = FontWeight.Bold,
                                            fontFamily = FontFamily.Monospace,
                                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                        )
                                    }
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Icon(
                                        imageVector = if (showInactiveEngines) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                                        contentDescription = "Toggle",
                                        tint = TextMuted,
                                        modifier = Modifier.size(16.dp)
                                    )
                                }

                                if (showInactiveEngines) {
                                    Spacer(modifier = Modifier.height(10.dp))
                                    Divider(color = CyberCardBorder.copy(alpha = 0.4f))
                                    Spacer(modifier = Modifier.height(8.dp))
                                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                        inactiveEngines.forEach { (name, _) ->
                                            Column(
                                                modifier = Modifier
                                                    .fillMaxWidth()
                                                    .background(CyberBlack, RoundedCornerShape(6.dp))
                                                    .padding(horizontal = 10.dp, vertical = 6.dp)
                                            ) {
                                                Row(
                                                    modifier = Modifier.fillMaxWidth(),
                                                    verticalAlignment = Alignment.CenterVertically
                                                ) {
                                                    EngineLogoIcon(name, modifier = Modifier.size(16.dp))
                                                    Spacer(modifier = Modifier.width(8.dp))
                                                    Text(
                                                        text = name,
                                                        color = TextPrimary,
                                                        fontSize = 12.sp,
                                                        fontWeight = FontWeight.SemiBold
                                                    )
                                                }
                                                Spacer(modifier = Modifier.height(2.dp))
                                                Text(
                                                    text = "No results (API key not configured)",
                                                    color = TextMuted,
                                                    fontSize = 10.sp,
                                                    fontFamily = FontFamily.Monospace,
                                                    modifier = Modifier.padding(start = 24.dp)
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Spacer(modifier = Modifier.height(14.dp))

            // Deep Cloud Sandbox Detonation & Sample Submission Card
            val targetFile = remember(report.targetPath) { File(report.targetPath) }
            val fileExists = remember(report.targetPath) { targetFile.exists() && targetFile.length() > 0 }
            val isUnindexed = report.engineVerdictMap["VirusTotal"]?.contains("Unindexed", ignoreCase = true) == true || report.cloudEnginesTotal == 0

            if (fileExists && onUploadSample != null) {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(1.dp, NeonCyan.copy(alpha = 0.5f), RoundedCornerShape(12.dp)),
                    colors = CardDefaults.cardColors(containerColor = CyberCardSurface)
                ) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            EngineLogoIcon("VirusTotal", modifier = Modifier.size(24.dp))
                            Spacer(modifier = Modifier.width(10.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "VirusTotal Cloud Detonation",
                                    color = TextPrimary,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 13.sp
                                )
                                Text(
                                    text = if (isUnindexed) "Unindexed hash • Multi-scanner detonation" else "Submit binary for full dynamic sandbox analysis",
                                    color = TextMuted,
                                    fontSize = 11.sp
                                )
                            }
                            Surface(
                                color = if (isUnindexed) CyberAmber.copy(alpha = 0.15f) else NeonCyan.copy(alpha = 0.15f),
                                shape = RoundedCornerShape(4.dp)
                            ) {
                                Text(
                                    text = if (isUnindexed) "UNINDEXED" else "ON-DEMAND",
                                    color = if (isUnindexed) CyberAmber else NeonCyan,
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Bold,
                                    fontFamily = FontFamily.Monospace,
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(10.dp))

                        when (uploadProgress) {
                            is VirusTotalProvider.UploadProgress.Uploading -> {
                                Text(
                                    text = "Uploading APK to VirusTotal Multi-Scanner...",
                                    color = NeonCyan,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold
                                )
                                Spacer(modifier = Modifier.height(6.dp))
                                LinearProgressIndicator(
                                    progress = { uploadProgress.percentage / 100f },
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .height(6.dp)
                                        .clip(RoundedCornerShape(3.dp)),
                                    color = NeonCyan,
                                    trackColor = CyberDarkSurface
                                )
                                Spacer(modifier = Modifier.height(4.dp))
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Text(
                                        text = "${uploadProgress.bytesSent / (1024 * 1024)} MB / ${maxOf(1L, uploadProgress.totalBytes / (1024 * 1024))} MB",
                                        color = TextMuted,
                                        fontSize = 10.sp,
                                        fontFamily = FontFamily.Monospace
                                    )
                                    Text(
                                        text = "${uploadProgress.percentage}%",
                                        color = NeonCyan,
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Bold
                                    )
                                }
                            }
                            is VirusTotalProvider.UploadProgress.Queued -> {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(16.dp),
                                        strokeWidth = 2.dp,
                                        color = CyberAmber
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Column {
                                        Text(
                                            text = "Queued in Cloud Sandbox...",
                                            color = CyberAmber,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 11.sp
                                        )
                                        Text(
                                            text = "Awaiting worker slot (ID: ${uploadProgress.analysisId.take(16)}...)",
                                            color = TextMuted,
                                            fontSize = 10.sp,
                                            fontFamily = FontFamily.Monospace
                                        )
                                    }
                                }
                            }
                            is VirusTotalProvider.UploadProgress.InProgress -> {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    CircularProgressIndicator(
                                        modifier = Modifier.size(16.dp),
                                        strokeWidth = 2.dp,
                                        color = NeonCyan
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = "Multi-Engine Detonation in Progress...",
                                            color = NeonCyan,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 11.sp
                                        )
                                        Text(
                                            text = "${uploadProgress.completedEngines}/${uploadProgress.totalEngines} commercial AV vendors evaluated",
                                            color = TextSecondary,
                                            fontSize = 10.sp,
                                            fontFamily = FontFamily.Monospace
                                        )
                                    }
                                }
                            }
                            is VirusTotalProvider.UploadProgress.Completed -> {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        imageVector = Icons.Default.CheckCircle,
                                        contentDescription = null,
                                        tint = if (uploadProgress.result.maliciousCount > 0) NeonCrimson else NeonEmerald,
                                        modifier = Modifier.size(20.dp)
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            text = "✓ Cloud Detonation Complete",
                                            color = if (uploadProgress.result.maliciousCount > 0) NeonCrimson else NeonEmerald,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 12.sp
                                        )
                                        Text(
                                            text = "${uploadProgress.result.maliciousCount}/${uploadProgress.result.totalEngines} vendors flagged • Report updated live",
                                            color = TextPrimary,
                                            fontSize = 11.sp
                                        )
                                    }
                                }
                            }
                            is VirusTotalProvider.UploadProgress.Error -> {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(
                                        imageVector = Icons.Default.Warning,
                                        contentDescription = null,
                                        tint = CyberAmber,
                                        modifier = Modifier.size(20.dp)
                                    )
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Text(
                                        text = uploadProgress.message,
                                        color = CyberAmber,
                                        fontSize = 11.sp,
                                        modifier = Modifier.weight(1f)
                                    )
                                }
                            }
                            else -> {
                                Text(
                                    text = if (isVtKeyConfigured) {
                                        "Submit this ${targetFile.length() / (1024 * 1024)} MB APK to VirusTotal for multi-engine cloud detonation across 70+ commercial AV engines."
                                    } else {
                                        "Configure a free VirusTotal API key in Settings to upload unindexed APKs for live 70+ engine detonation."
                                    },
                                    color = TextSecondary,
                                    fontSize = 11.sp,
                                    lineHeight = 16.sp
                                )

                                Spacer(modifier = Modifier.height(10.dp))

                                Button(
                                    onClick = {
                                        if (isVtKeyConfigured) {
                                            showUploadConfirmDialog = true
                                        } else {
                                            android.widget.Toast.makeText(context, "Configure VirusTotal API key in Settings first", android.widget.Toast.LENGTH_SHORT).show()
                                        }
                                    },
                                    colors = ButtonDefaults.buttonColors(containerColor = if (isVtKeyConfigured) NeonCyan else CyberCardBorder),
                                    shape = RoundedCornerShape(8.dp),
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .height(40.dp)
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.CloudUpload,
                                        contentDescription = null,
                                        tint = if (isVtKeyConfigured) CyberBlack else TextMuted,
                                        modifier = Modifier.size(16.dp)
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        text = if (isVtKeyConfigured) "SUBMIT SAMPLE FOR DEEP DETONATION" else "CONFIGURE API KEY TO UPLOAD",
                                        color = if (isVtKeyConfigured) CyberBlack else TextMuted,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 11.sp
                                    )
                                }
                            }
                        }
                    }
                }
                Spacer(modifier = Modifier.height(14.dp))
            }

            // Observed Heuristics
            if (report.detectedBehaviors.isNotEmpty()) {
                GlassCard {
                    Text(
                        text = "Observed Findings & Heuristics",
                        color = TextPrimary,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 14.sp
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    report.detectedBehaviors.forEach { behavior ->
                        Text(
                            text = "• $behavior",
                            color = TextSecondary,
                            fontSize = 12.sp,
                            modifier = Modifier.padding(vertical = 2.dp)
                        )
                    }
                }
                Spacer(modifier = Modifier.height(14.dp))
            }

            // Permissions That May Be Misused
            if (report.dangerousPermissions.isNotEmpty()) {
                GlassCard {
                    Text(
                        text = "Permissions That May Be Misused",
                        color = TextPrimary,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 14.sp
                    )
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        text = "Standard sensitive capabilities and privileged system permissions declared by this application.",
                        color = TextMuted,
                        fontSize = 11.sp
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    FlowRow(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        val criticalPerms = setOf(
                            "BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW", "BIND_DEVICE_ADMIN", "REQUEST_INSTALL_PACKAGES"
                        )
                        report.dangerousPermissions.forEach { perm ->
                            val isCritical = criticalPerms.any { perm.endsWith(it, ignoreCase = true) || perm.equals(it, ignoreCase = true) }
                            val chipBg = if (isCritical) NeonCrimson.copy(alpha = 0.15f) else CyberAmber.copy(alpha = 0.12f)
                            val chipBorder = if (isCritical) NeonCrimson.copy(alpha = 0.45f) else CyberAmber.copy(alpha = 0.35f)
                            val chipText = if (isCritical) NeonCrimson else CyberAmber
                            Surface(
                                color = chipBg,
                                shape = RoundedCornerShape(6.dp),
                                border = androidx.compose.foundation.BorderStroke(1.dp, chipBorder)
                            ) {
                                Row(
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    if (isCritical) {
                                        Text(
                                            text = "CRITICAL ",
                                            color = NeonCrimson,
                                            fontSize = 9.sp,
                                            fontWeight = FontWeight.Black,
                                            fontFamily = FontFamily.Monospace
                                        )
                                    }
                                    Text(
                                        text = perm,
                                        color = chipText,
                                        fontSize = 11.sp,
                                        fontFamily = FontFamily.Monospace
                                    )
                                }
                            }
                        }
                    }
                }
                Spacer(modifier = Modifier.height(14.dp))
            }

            // Technical App & Binary Details
            GlassCard {
                Text(
                    text = "Technical File & Identity Details",
                    color = TextPrimary,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 14.sp
                )
                Spacer(modifier = Modifier.height(10.dp))

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("Application Name:", color = TextMuted, fontSize = 12.sp)
                    Text(report.appName ?: "Unknown", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                }
                Spacer(modifier = Modifier.height(6.dp))

                val provenance = remember(report.packageName) {
                    io.threatlens.core.local.AppProvenanceVerifier.inspectProvenance(context, report.packageName)
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("App Provenance / Store:", color = TextMuted, fontSize = 12.sp)
                    Surface(
                        color = if (provenance.isVerifiedStore || provenance.isSystemApp) NeonEmerald.copy(alpha = 0.15f) else CyberDarkSurface,
                        shape = RoundedCornerShape(4.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, if (provenance.isVerifiedStore || provenance.isSystemApp) NeonEmerald.copy(alpha = 0.5f) else CyberCardBorder)
                    ) {
                        Text(
                            text = provenance.badgeLabel,
                            color = if (provenance.isVerifiedStore || provenance.isSystemApp) NeonEmerald else TextSecondary,
                            fontSize = 9.sp,
                            fontWeight = FontWeight.Bold,
                            fontFamily = FontFamily.Monospace,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                        )
                    }
                }
                Spacer(modifier = Modifier.height(6.dp))

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("Detected APK File:", color = TextMuted, fontSize = 12.sp)
                    Text(report.targetName, color = NeonCyan, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                }
                Spacer(modifier = Modifier.height(6.dp))

                if (!report.packageName.isNullOrBlank()) {
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("Package Name:", color = TextMuted, fontSize = 12.sp)
                        Text(report.packageName, color = TextPrimary, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                }

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("Path:", color = TextMuted, fontSize = 12.sp)
                    Text(
                        report.targetPath,
                        color = TextSecondary,
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        maxLines = 1,
                        modifier = Modifier.padding(start = 12.dp)
                    )
                }
                Spacer(modifier = Modifier.height(6.dp))

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("File Size:", color = TextMuted, fontSize = 12.sp)
                    Text("${report.fileSize / 1024} KB", color = TextPrimary, fontSize = 12.sp)
                }
                Spacer(modifier = Modifier.height(6.dp))

                Column {
                    Text("SHA-256 Checksum:", color = TextMuted, fontSize = 11.sp)
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(report.sha256, color = TextSecondary, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            val isInstalled = remember(report) {
                if (report.targetPath.contains("/data/app")) true
                else if (!report.packageName.isNullOrBlank()) {
                    try {
                        context.packageManager.getPackageInfo(report.packageName, 0)
                        true
                    } catch (_: Exception) {
                        false
                    }
                } else false
            }

            // Primary Action Button (Uninstall for installed apps, Delete for downloaded files)
            val isConfirmedMalicious = report.currentScore >= 75
            Button(
                onClick = { showConfirmDeleteDialog = true },
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (isConfirmedMalicious) NeonCrimson else CyberDarkSurface
                ),
                border = if (!isConfirmedMalicious) androidx.compose.foundation.BorderStroke(1.dp, CyberAmber.copy(alpha = 0.6f)) else null,
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp)
            ) {
                Icon(
                    if (isInstalled) Icons.Default.DeleteForever else Icons.Default.Delete,
                    contentDescription = null,
                    tint = if (isConfirmedMalicious) Color.White else CyberAmber
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = when {
                        isConfirmedMalicious -> if (isInstalled) "UNINSTALL MALICIOUS THREAT" else "DELETE MALICIOUS FILE"
                        report.currentScore >= 25 -> if (isInstalled) "UNINSTALL APPLICATION (OPTIONAL)" else "DELETE FILE"
                        else -> if (isInstalled) "UNINSTALL APPLICATION" else "DELETE FILE"
                    },
                    fontWeight = FontWeight.Bold,
                    color = if (isConfirmedMalicious) Color.White else CyberAmber
                )
            }

            Spacer(modifier = Modifier.height(10.dp))

            // User Trust / Whitelist Button (Toggleable)
            var isWhitelisted by remember {
                mutableStateOf(io.threatlens.core.local.ThreatWhitelistManager.isWhitelisted(context, report.packageName, report.sha256))
            }

            OutlinedButton(
                onClick = {
                    if (isWhitelisted) {
                        if (!report.packageName.isNullOrBlank()) {
                            io.threatlens.core.local.ThreatWhitelistManager.removeApp(context, report.packageName)
                        }
                        isWhitelisted = false
                        android.widget.Toast.makeText(context, "Removed ${report.appName ?: report.targetName} from Trusted Whitelist", android.widget.Toast.LENGTH_SHORT).show()
                    } else {
                        if (!report.packageName.isNullOrBlank()) {
                            io.threatlens.core.local.ThreatWhitelistManager.addApp(context, report.packageName, report.appName ?: report.targetName, report.sha256)
                        }
                        io.threatlens.core.exclusions.ExclusionManager.addAvPath(report.targetPath)
                        io.threatlens.core.exclusions.ExclusionManager.addAvHash(report.sha256, report.targetName)
                        isWhitelisted = true
                        android.widget.Toast.makeText(context, "✓ Trusted ${report.appName ?: report.targetName} (Added to Whitelist)", android.widget.Toast.LENGTH_SHORT).show()
                        onDismiss()
                    }
                },
                colors = ButtonDefaults.outlinedButtonColors(contentColor = if (isWhitelisted) CyberAmber else NeonEmerald),
                border = androidx.compose.foundation.BorderStroke(1.dp, if (isWhitelisted) CyberAmber.copy(alpha = 0.6f) else NeonEmerald.copy(alpha = 0.6f)),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(44.dp)
            ) {
                Icon(if (isWhitelisted) Icons.Default.CheckCircle else Icons.Default.Shield, contentDescription = null, tint = if (isWhitelisted) CyberAmber else NeonEmerald, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = if (isWhitelisted) "Trusted Application (Tap to Revoke Trust)" else "Trust This App (Add to Whitelist)",
                    color = if (isWhitelisted) CyberAmber else NeonEmerald,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold
                )
            }

            Spacer(modifier = Modifier.height(24.dp))
        }
    }

    // Confirmation Popup Dialog for Delete / Uninstall
    if (showConfirmDeleteDialog) {
        val isInstalledApp = report.targetPath.contains("/data/app") || (!report.packageName.isNullOrBlank() && try {
            context.packageManager.getPackageInfo(report.packageName, 0)
            true
        } catch (_: Exception) { false })

        AlertDialog(
            onDismissRequest = { showConfirmDeleteDialog = false },
            containerColor = CyberDarkSurface,
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = if (isInstalledApp) Icons.Default.DeleteForever else Icons.Default.Warning,
                        contentDescription = null,
                        tint = NeonCrimson,
                        modifier = Modifier.size(24.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = if (isInstalledApp) "Uninstall Application?" else "Delete Malicious File?",
                        color = TextPrimary,
                        fontWeight = FontWeight.Bold,
                        fontSize = 16.sp
                    )
                }
            },
            text = {
                Text(
                    text = if (isInstalledApp) {
                        "Are you sure you want to uninstall \"${report.appName ?: report.targetName}\"?\n\nThis will open Android's system uninstaller to permanently remove this app from your device."
                    } else {
                        "Are you sure you want to permanently delete \"${report.targetName}\"?\n\nThis malicious file will be permanently erased from your storage."
                    },
                    color = TextSecondary,
                    fontSize = 13.sp,
                    lineHeight = 18.sp
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        showConfirmDeleteDialog = false
                        onDelete(report)
                        onDismiss()
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = NeonCrimson),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(if (isInstalledApp) "UNINSTALL" else "DELETE", color = Color.White, fontWeight = FontWeight.Black)
                }
            },
            dismissButton = {
                OutlinedButton(
                    onClick = { showConfirmDeleteDialog = false },
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = TextPrimary),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text("CANCEL")
                }
            }
        )
    }

    // Confirmation Dialog for Sample Upload to VirusTotal
    if (showUploadConfirmDialog && onUploadSample != null) {
        val targetFile = File(report.targetPath)
        val sizeMb = maxOf(1L, targetFile.length() / (1024 * 1024))
        AlertDialog(
            onDismissRequest = { showUploadConfirmDialog = false },
            containerColor = CyberDarkSurface,
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.CloudUpload, contentDescription = null, tint = NeonCyan, modifier = Modifier.size(24.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Submit Sample to VirusTotal?", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                }
            },
            text = {
                Column {
                    Text(
                        text = "You are about to upload this binary for dynamic multi-engine detonation:\n",
                        color = TextSecondary,
                        fontSize = 13.sp
                    )
                    Text("• Target: ${report.appName ?: report.targetName}", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                    Text("• File Size: $sizeMb MB", color = TextPrimary, fontSize = 12.sp)
                    Text("• Engines: 70+ commercial antivirus vendors", color = NeonCyan, fontSize = 12.sp)
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        text = "Note: Uploaded samples become accessible to global security researchers and antivirus vendors for threat intelligence.",
                        color = TextMuted,
                        fontSize = 11.sp
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        showUploadConfirmDialog = false
                        onUploadSample(report)
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = NeonCyan)
                ) {
                    Text("UPLOAD & DETONATE", color = CyberBlack, fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showUploadConfirmDialog = false }) {
                    Text("CANCEL", color = TextMuted)
                }
            }
        )
    }
}

@Composable
private fun ScoreComponentRow(name: String, scoreText: String, isElevated: Boolean) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = name,
            color = TextSecondary,
            fontSize = 11.sp,
            modifier = Modifier.weight(1f).padding(end = 8.dp)
        )
        Text(
            text = scoreText,
            color = if (isElevated) CyberAmber else TextMuted,
            fontWeight = FontWeight.Bold,
            fontSize = 11.sp,
            fontFamily = FontFamily.Monospace,
            softWrap = false
        )
    }
}

// ---------------------------------------------------------------------------
// High-Legibility Formatted AI Threat Analysis Composable
// ---------------------------------------------------------------------------

private data class AiSectionBlock(
    val title: String,
    val badgeLabel: String,
    val accentColor: Color,
    val rawLines: List<String>
)

@Composable
fun FormattedAiAnalysisView(
    markdownText: String,
    modifier: Modifier = Modifier
) {
    val sections = remember(markdownText) { parseAiMarkdownSections(markdownText) }

    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        sections.forEachIndexed { index, section ->
            Column(modifier = Modifier.fillMaxWidth()) {
                // Section Header with Neon Category Badge
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.padding(bottom = 8.dp)
                ) {
                    Surface(
                        color = section.accentColor.copy(alpha = 0.15f),
                        shape = RoundedCornerShape(4.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, section.accentColor.copy(alpha = 0.5f))
                    ) {
                        Text(
                            text = section.badgeLabel,
                            color = section.accentColor,
                            fontSize = 9.sp,
                            fontWeight = FontWeight.Bold,
                            fontFamily = FontFamily.Monospace,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                        )
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = section.title,
                        color = TextPrimary,
                        fontWeight = FontWeight.Bold,
                        fontSize = 13.sp
                    )
                }

                if (section.badgeLabel == "NOTICE") {
                    // Subtle info box for skipped/inactive unconfigured engines
                    Surface(
                        color = CyberBlack,
                        shape = RoundedCornerShape(8.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, CyberCardBorder.copy(alpha = 0.7f)),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier.padding(10.dp),
                            verticalAlignment = Alignment.Top
                        ) {
                            Icon(
                                imageVector = Icons.Default.Info,
                                contentDescription = null,
                                tint = TextMuted,
                                modifier = Modifier
                                    .size(16.dp)
                                    .padding(top = 1.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            val noticeContent = section.rawLines.filter { it.isNotBlank() }.joinToString(" ")
                            Text(
                                text = parseMarkdownInline(noticeContent),
                                fontSize = 11.sp,
                                lineHeight = 17.sp
                            )
                        }
                    }
                } else {
                    // Render lines with generous vertical spacing and stylized indicators
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        section.rawLines.forEach { line ->
                            val trimmed = line.trim()
                            if (trimmed.isNotBlank()) {
                                val isSubBullet = line.startsWith("   -") || line.startsWith("   •") || line.startsWith("  -") || line.startsWith("  •") || line.startsWith("\t-")
                                val isTopBullet = !isSubBullet && (trimmed.startsWith("•") || trimmed.startsWith("- ") || trimmed.startsWith("* "))
                                val numberedMatch = Regex("""^(\*\*?\d+\.?\*\*?|\d+\.)\s*(.*)""").find(trimmed)

                                when {
                                    isSubBullet -> {
                                        val content = trimmed.removePrefix("-").removePrefix("•").removePrefix("*").trim()
                                        Row(
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .padding(start = 14.dp, top = 2.dp),
                                            verticalAlignment = Alignment.Top
                                        ) {
                                            Text(
                                                text = "└─",
                                                color = section.accentColor.copy(alpha = 0.7f),
                                                fontSize = 11.sp,
                                                fontFamily = FontFamily.Monospace,
                                                modifier = Modifier.padding(end = 6.dp)
                                            )
                                            Text(
                                                text = parseMarkdownInline(content),
                                                fontSize = 12.sp,
                                                lineHeight = 18.sp
                                            )
                                        }
                                    }
                                    isTopBullet -> {
                                        val content = trimmed.removePrefix("•").removePrefix("-").removePrefix("*").trim()
                                        Row(
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .padding(top = 2.dp),
                                            verticalAlignment = Alignment.Top
                                        ) {
                                            Text(
                                                text = "▸",
                                                color = section.accentColor,
                                                fontSize = 13.sp,
                                                fontWeight = FontWeight.Bold,
                                                modifier = Modifier.padding(end = 8.dp)
                                            )
                                            Text(
                                                text = parseMarkdownInline(content),
                                                fontSize = 12.sp,
                                                lineHeight = 19.sp
                                            )
                                        }
                                    }
                                    numberedMatch != null -> {
                                        val numRaw = numberedMatch.groupValues[1].replace("*", "").replace(".", "").trim()
                                        val content = numberedMatch.groupValues[2].trim()
                                        Row(
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .padding(top = 2.dp),
                                            verticalAlignment = Alignment.Top
                                        ) {
                                            Surface(
                                                color = section.accentColor.copy(alpha = 0.15f),
                                                shape = RoundedCornerShape(4.dp),
                                                modifier = Modifier.padding(end = 8.dp, top = 1.dp)
                                            ) {
                                                Text(
                                                    text = numRaw,
                                                    color = section.accentColor,
                                                    fontSize = 10.sp,
                                                    fontWeight = FontWeight.Bold,
                                                    fontFamily = FontFamily.Monospace,
                                                    modifier = Modifier.padding(horizontal = 5.dp, vertical = 1.dp)
                                                )
                                            }
                                            Text(
                                                text = parseMarkdownInline(content),
                                                fontSize = 12.sp,
                                                lineHeight = 19.sp
                                            )
                                        }
                                    }
                                    else -> {
                                        Text(
                                            text = parseMarkdownInline(trimmed),
                                            fontSize = 12.sp,
                                            lineHeight = 19.sp
                                        )
                                    }
                                }
                            }
                        }
                    }
                }

                // Clean divider between sections
                if (index < sections.size - 1) {
                    Spacer(modifier = Modifier.height(12.dp))
                    Divider(color = CyberCardBorder.copy(alpha = 0.5f))
                }
            }
        }
    }
}

private fun parseAiMarkdownSections(rawMarkdown: String): List<AiSectionBlock> {
    val sections = mutableListOf<AiSectionBlock>()
    val lines = rawMarkdown.lines()

    var currentHeading = ""
    var currentLines = mutableListOf<String>()

    fun flushCurrentSection() {
        if (currentHeading.isNotEmpty() || currentLines.any { it.isNotBlank() }) {
            val (title, badge, color) = getSectionHeaderStyle(currentHeading)
            sections.add(
                AiSectionBlock(
                    title = title,
                    badgeLabel = badge,
                    accentColor = color,
                    rawLines = currentLines.toList()
                )
            )
            currentLines = mutableListOf()
        }
    }

    for (line in lines) {
        val trimmed = line.trim()
        if (isSectionHeader(trimmed)) {
            flushCurrentSection()
            currentHeading = trimmed
        } else {
            currentLines.add(line)
        }
    }
    flushCurrentSection()
    return sections
}

private fun isSectionHeader(line: String): Boolean {
    if (line.startsWith("#")) return true
    if (line.matches(Regex("""^(\d+\.|\*\*?\d+\.?\*\*?)\s*(🛡️|🔬|⚡|🔑|⚠️|🛑|ℹ️).*"""))) return true
    if (line.startsWith("🛡️") || line.startsWith("🔬") || line.startsWith("⚡") || line.startsWith("🔑") || line.startsWith("⚠️") || line.startsWith("🛑") || line.startsWith("ℹ️")) return true
    return false
}

private fun getSectionHeaderStyle(rawHeading: String): Triple<String, String, Color> {
    val clean = rawHeading
        .replace(Regex("""^[#\s\d\.\*]+"""), "")
        .replace(Regex("""^\s*(🛡️|🔬|⚡|🔑|⚠️|🛑|ℹ️)\s*"""), "")
        .replace("**", "")
        .trim()

    val lower = rawHeading.lowercase()
    return when {
        lower.contains("remediation") || lower.contains("action") || lower.contains("guidance") || lower.contains("recommended") || lower.contains("🛑") ->
            Triple(if (clean.isEmpty()) "Recommended Action & Guidance" else clean, "ADVISORY", CyberAmber)
        lower.contains("executive") || lower.contains("assessment") || lower.contains("verdict") ->
            Triple(if (clean.isEmpty()) "Executive Threat Assessment" else clean, "EXECUTIVE", NeonCyan)
        lower.contains("consensus") || lower.contains("vendor") || lower.contains("multi-engine") || lower.contains("🔬") ->
            Triple(if (clean.isEmpty()) "Multi-Engine Consensus" else clean, "CONSENSUS", Color(0xFF38BDF8))
        lower.contains("observed") || lower.contains("behavior") || lower.contains("⚡") ->
            Triple(if (clean.isEmpty()) "Observed Malicious Behaviors" else clean, "BEHAVIORS", NeonOrange)
        lower.contains("permission") || lower.contains("capability") || lower.contains("🔑") ->
            Triple(if (clean.isEmpty()) "Permissions That May Be Misused" else clean, "PERMISSIONS", CyberAmber)
        lower.contains("point-by-point") || lower.contains("finding") || lower.contains("technical") || lower.contains("risk") || lower.contains("⚠️") ->
            Triple(if (clean.isEmpty()) "Technical Findings & Risk" else clean, "FINDINGS", CyberAmber)
        lower.contains("notice") || lower.contains("coverage") || lower.contains("inactive") || lower.contains("unconfigured") || lower.contains("ℹ️") ->
            Triple(if (clean.isEmpty()) "Engine Coverage Notice" else clean, "COVERAGE", TextMuted)
        lower.contains("🛡️") ->
            Triple(if (clean.isEmpty()) "Threat Analysis" else clean, "ANALYSIS", NeonCyan)
        else ->
            Triple(if (clean.isEmpty()) "Security Analysis" else clean, "ANALYSIS", NeonCyan)
    }
}

private fun parseMarkdownInline(
    text: String,
    primaryColor: Color = TextPrimary,
    defaultColor: Color = TextSecondary
): AnnotatedString {
    return buildAnnotatedString {
        var currentIndex = 0
        val regex = Regex("""\*\*(.*?)\*\*""")
        val matches = regex.findAll(text)

        for (match in matches) {
            val range = match.range
            if (range.first > currentIndex) {
                withStyle(SpanStyle(color = defaultColor, fontWeight = FontWeight.Normal)) {
                    append(text.substring(currentIndex, range.first))
                }
            }
            val boldContent = match.groupValues[1]
            withStyle(SpanStyle(color = primaryColor, fontWeight = FontWeight.Bold)) {
                append(boldContent)
            }
            currentIndex = range.last + 1
        }

        if (currentIndex < text.length) {
            withStyle(SpanStyle(color = defaultColor, fontWeight = FontWeight.Normal)) {
                append(text.substring(currentIndex))
            }
        }
    }
}

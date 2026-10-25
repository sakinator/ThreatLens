package io.threatlens.ui.screens

import androidx.compose.foundation.border
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.threatlens.core.model.ThreatReport
import io.threatlens.ui.components.AppIconBadge
import io.threatlens.ui.components.EngineLogoIcon
import io.threatlens.ui.components.EngineStatusBadge
import io.threatlens.ui.components.GlassCard
import io.threatlens.ui.components.ScoreBadge
import io.threatlens.ui.theme.*

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun ThreatDetailSheet(
    report: ThreatReport,
    onDismiss: () -> Unit,
    onDelete: (ThreatReport) -> Unit
) {
    val context = LocalContext.current
    var showConfirmDeleteDialog by remember { mutableStateOf(false) }

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
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(modifier = Modifier.height(2.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Surface(
                            color = CyberCardSurface,
                            shape = RoundedCornerShape(4.dp)
                        ) {
                            Text(
                                text = "APK: ${report.targetName}",
                                color = NeonCyan,
                                fontSize = 11.sp,
                                fontFamily = FontFamily.Monospace,
                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                            )
                        }
                        if (!report.packageName.isNullOrBlank() && report.packageName != report.appName) {
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = report.packageName,
                                color = TextMuted,
                                fontSize = 11.sp,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                    }
                    Spacer(modifier = Modifier.height(3.dp))
                    Text(
                        text = report.threatFamily,
                        color = if (report.threatFamily != "Clean") NeonCrimson else NeonEmerald,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.SemiBold
                    )
                }
                ScoreBadge(report.currentScore, report.severity, report.isFinal)
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

            // AI Explanation Card with Gemini/Groq branding
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
                                text = "ThreatLens AI Threat Brief (Gemini 1.5 Flash)",
                                color = NeonCyan,
                                fontWeight = FontWeight.Bold,
                                fontSize = 14.sp
                            )
                        }
                        Spacer(modifier = Modifier.height(10.dp))
                        Text(
                            text = report.aiExplanation,
                            color = TextPrimary,
                            fontSize = 13.sp,
                            lineHeight = 19.sp
                        )
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

                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    report.engineVerdictMap.forEach { (sourceName, verdict) ->
                        val isPending = report.pendingEngines.contains(sourceName) || verdict.contains("Querying", ignoreCase = true) || verdict.contains("Scanning", ignoreCase = true)
                        val isFlagged = verdict.startsWith("Flagged", ignoreCase = true) || verdict.contains("Malicious", ignoreCase = true) || verdict.contains("Suspicious", ignoreCase = true)
                        val isClean = verdict.startsWith("Clean", ignoreCase = true) || verdict.contains("Clean", ignoreCase = true) || verdict.contains("Verified", ignoreCase = true)

                        Surface(
                            color = CyberDarkSurface,
                            shape = RoundedCornerShape(10.dp),
                            border = androidx.compose.foundation.BorderStroke(
                                1.dp,
                                when {
                                    isPending -> NeonCyan.copy(alpha = 0.5f)
                                    isFlagged -> NeonCrimson.copy(alpha = 0.5f)
                                    isClean -> NeonEmerald.copy(alpha = 0.25f)
                                    else -> CyberCardBorder
                                }
                            ),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 12.dp, vertical = 10.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                // Engine Logo
                                EngineLogoIcon(sourceName, modifier = Modifier.size(24.dp))
                                Spacer(modifier = Modifier.width(10.dp))

                                // Center Content: Source Name, Tag, Verdict
                                Column(modifier = Modifier.weight(1f)) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Text(
                                            text = sourceName,
                                            color = TextPrimary,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 13.sp
                                        )
                                        Spacer(modifier = Modifier.width(6.dp))
                                        Surface(
                                            color = CyberCardSurface,
                                            shape = RoundedCornerShape(4.dp)
                                        ) {
                                            Text(
                                                text = when (sourceName) {
                                                    "ThreatLens Local Engine" -> "LOCAL"
                                                    "AlienVault OTX", "CIRCL Hashlookup" -> "PUBLIC CLOUD"
                                                    else -> "CLOUD API"
                                                },
                                                color = when (sourceName) {
                                                    "ThreatLens Local Engine" -> NeonCyan
                                                    "AlienVault OTX", "CIRCL Hashlookup" -> NeonEmerald
                                                    else -> TextSecondary
                                                },
                                                fontSize = 8.sp,
                                                fontWeight = FontWeight.Bold,
                                                fontFamily = FontFamily.Monospace,
                                                modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp)
                                            )
                                        }
                                    }
                                    Spacer(modifier = Modifier.height(2.dp))
                                    Text(
                                        text = verdict,
                                        color = when {
                                            isPending -> NeonCyan
                                            isFlagged -> NeonCrimson
                                            isClean -> NeonEmerald
                                            else -> TextMuted
                                        },
                                        fontSize = 11.sp,
                                        maxLines = 2
                                    )
                                }

                                Spacer(modifier = Modifier.width(8.dp))

                                // Right Status Badge: Uniform fixed-width alignment
                                Surface(
                                    color = when {
                                        isPending -> NeonCyan.copy(alpha = 0.15f)
                                        isFlagged -> NeonCrimson.copy(alpha = 0.18f)
                                        isClean -> NeonEmerald.copy(alpha = 0.18f)
                                        else -> CyberCardSurface
                                    },
                                    shape = RoundedCornerShape(6.dp),
                                    modifier = Modifier.width(76.dp)
                                ) {
                                    Box(
                                        contentAlignment = Alignment.Center,
                                        modifier = Modifier.padding(vertical = 4.dp, horizontal = 4.dp)
                                    ) {
                                        if (isPending) {
                                            Row(verticalAlignment = Alignment.CenterVertically) {
                                                CircularProgressIndicator(
                                                    modifier = Modifier.size(10.dp),
                                                    strokeWidth = 1.5.dp,
                                                    color = NeonCyan
                                                )
                                                Spacer(modifier = Modifier.width(4.dp))
                                                Text(
                                                    text = "SCAN",
                                                    color = NeonCyan,
                                                    fontSize = 9.sp,
                                                    fontWeight = FontWeight.Bold,
                                                    fontFamily = FontFamily.Monospace
                                                )
                                            }
                                        } else {
                                            Text(
                                                text = when {
                                                    isFlagged -> "FLAGGED"
                                                    isClean -> "CLEAN"
                                                    verdict.contains("Auth-Key", ignoreCase = true) -> "KEY REQ"
                                                    else -> "OPTIONAL"
                                                },
                                                color = when {
                                                    isFlagged -> NeonCrimson
                                                    isClean -> NeonEmerald
                                                    verdict.contains("Auth-Key", ignoreCase = true) -> CyberAmber
                                                    else -> TextMuted
                                                },
                                                fontSize = 9.sp,
                                                fontWeight = FontWeight.Bold,
                                                fontFamily = FontFamily.Monospace
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Spacer(modifier = Modifier.height(14.dp))

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

            // Dangerous Permissions
            if (report.dangerousPermissions.isNotEmpty()) {
                GlassCard {
                    Text(
                        text = "Dangerous Permissions Flagged",
                        color = TextPrimary,
                        fontWeight = FontWeight.SemiBold,
                        fontSize = 14.sp
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    FlowRow(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        report.dangerousPermissions.forEach { perm ->
                            Surface(
                                color = NeonCrimson.copy(alpha = 0.15f),
                                shape = RoundedCornerShape(6.dp),
                                border = androidx.compose.foundation.BorderStroke(1.dp, NeonCrimson.copy(alpha = 0.4f))
                            ) {
                                Text(
                                    text = perm,
                                    color = NeonCrimson,
                                    fontSize = 11.sp,
                                    fontFamily = FontFamily.Monospace,
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                                )
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
            Button(
                onClick = { showConfirmDeleteDialog = true },
                colors = ButtonDefaults.buttonColors(containerColor = NeonCrimson),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp)
            ) {
                Icon(if (isInstalled) Icons.Default.DeleteForever else Icons.Default.Delete, contentDescription = null, tint = Color.White)
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = if (isInstalled) "UNINSTALL APPLICATION" else "PERMANENTLY DELETE FILE",
                    fontWeight = FontWeight.Bold,
                    color = Color.White
                )
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Add to Exclusions / Whitelist Button
            OutlinedButton(
                onClick = {
                    io.threatlens.core.exclusions.ExclusionManager.addAvPath(report.targetPath)
                    io.threatlens.core.exclusions.ExclusionManager.addAvHash(report.sha256, report.targetName)
                    android.widget.Toast.makeText(context, "✓ Added ${report.appName ?: report.targetName} to Whitelist", android.widget.Toast.LENGTH_SHORT).show()
                    onDismiss()
                },
                colors = ButtonDefaults.outlinedButtonColors(contentColor = NeonCyan),
                border = androidx.compose.foundation.BorderStroke(1.dp, NeonCyan.copy(alpha = 0.6f)),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(44.dp)
            ) {
                Icon(Icons.Default.Shield, contentDescription = null, tint = NeonCyan, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text("Add to Whitelist (Exclude from Future Scans)", color = NeonCyan, fontSize = 12.sp, fontWeight = FontWeight.Bold)
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
}

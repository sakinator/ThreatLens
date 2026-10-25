package io.threatlens.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.threatlens.core.model.ThreatSeverity
import io.threatlens.ui.components.CyberRadarShield
import io.threatlens.ui.components.GlassCard
import io.threatlens.ui.components.ThreatItemRow
import io.threatlens.ui.theme.*
import io.threatlens.ui.viewmodel.MainViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DashboardScreen(
    viewModel: MainViewModel,
    onNavigateSettings: () -> Unit
) {
    val isShieldActive by viewModel.isShieldActive.collectAsState()
    val scans by viewModel.scansList.collectAsState()
    val isScanning by viewModel.isScanning.collectAsState()
    val selectedReport by viewModel.selectedReport.collectAsState()

    val maliciousCount = scans.count { it.severity == ThreatSeverity.MALICIOUS || it.severity == ThreatSeverity.HIGH_RISK }
    val cleanCount = scans.count { it.severity == ThreatSeverity.SAFE }

    Scaffold(
        containerColor = CyberBlack,
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = "THREAT",
                            color = TextPrimary,
                            fontWeight = FontWeight.Black,
                            letterSpacing = 1.sp
                        )
                        Text(
                            text = "LENS",
                            color = NeonCyan,
                            fontWeight = FontWeight.Black,
                            letterSpacing = 1.sp
                        )
                    }
                },
                actions = {
                    IconButton(onClick = onNavigateSettings) {
                        Icon(
                            imageVector = Icons.Default.Settings,
                            contentDescription = "Settings",
                            tint = TextSecondary
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = CyberDarkSurface)
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            item {
                Spacer(modifier = Modifier.height(8.dp))
                // Central Shield & Status Card
                GlassCard {
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        CyberRadarShield(isProtected = isShieldActive)
                        Spacer(modifier = Modifier.height(14.dp))
                        Text(
                            text = if (isShieldActive) "REALTIME INTERCEPT ACTIVE" else "SHIELD DISABLED",
                            color = if (isShieldActive) NeonCyan else CyberAmber,
                            fontWeight = FontWeight.Bold,
                            fontSize = 16.sp,
                            letterSpacing = 0.5.sp
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = if (isShieldActive) "Monitoring downloads with zero-idle kernel inotify" else "Downloads are unmonitored",
                            color = TextSecondary,
                            fontSize = 12.sp
                        )
                        Spacer(modifier = Modifier.height(14.dp))
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.Center
                        ) {
                            Text(
                                text = "Active Defense",
                                color = TextPrimary,
                                fontSize = 14.sp,
                                fontWeight = FontWeight.SemiBold
                            )
                            Spacer(modifier = Modifier.width(12.dp))
                            Switch(
                                checked = isShieldActive,
                                onCheckedChange = { viewModel.toggleShield() },
                                colors = SwitchDefaults.colors(
                                    checkedThumbColor = NeonCyan,
                                    checkedTrackColor = CyberDarkSurface,
                                    uncheckedThumbColor = TextMuted,
                                    uncheckedTrackColor = CyberCardBorder
                                )
                            )
                        }
                    }
                }
            }

            // Stats row
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    MetricBox(
                        modifier = Modifier.weight(1f),
                        title = "INTERCEPTED",
                        value = "$maliciousCount",
                        valueColor = if (maliciousCount > 0) NeonCrimson else TextPrimary
                    )
                    MetricBox(
                        modifier = Modifier.weight(1f),
                        title = "VERIFIED SAFE",
                        value = "$cleanCount",
                        valueColor = NeonEmerald
                    )
                    MetricBox(
                        modifier = Modifier.weight(1f),
                        title = "IDLE CPU",
                        value = "0.0%",
                        valueColor = NeonCyan
                    )
                }
            }

            // Quick Actions
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    Button(
                        onClick = { viewModel.scanDownloadFolder() },
                        enabled = !isScanning,
                        modifier = Modifier.weight(1f).height(44.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = CyberCardSurface),
                        shape = RoundedCornerShape(10.dp)
                    ) {
                        Icon(Icons.Default.FolderOpen, contentDescription = null, tint = NeonCyan, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Scan Folder", color = TextPrimary, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                    }

                    Button(
                        onClick = { viewModel.simulateMalwareIntercept() },
                        modifier = Modifier.weight(1f).height(44.dp),
                        colors = ButtonDefaults.buttonColors(containerColor = CyberCardSurface),
                        shape = RoundedCornerShape(10.dp)
                    ) {
                        Icon(Icons.Default.BugReport, contentDescription = null, tint = CyberAmber, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Test AI Alert", color = TextPrimary, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                    }
                }
            }

            // Activity Log Header
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "REAL-TIME INTERCEPTION LOG",
                        color = TextSecondary,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 0.5.sp
                    )
                    if (isScanning) {
                        CircularProgressIndicator(modifier = Modifier.size(14.dp), color = NeonCyan, strokeWidth = 2.dp)
                    }
                }
            }

            // List of Scans
            if (scans.isEmpty()) {
                item {
                    GlassCard {
                        Box(
                            modifier = Modifier.fillMaxWidth().padding(vertical = 24.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = "No downloads intercepted yet.\nDownload an APK or tap 'Test AI Alert' above.",
                                color = TextMuted,
                                fontSize = 13.sp,
                                textAlign = androidx.compose.ui.text.style.TextAlign.Center
                            )
                        }
                    }
                }
            } else {
                items(scans, key = { it.id }) { report ->
                    ThreatItemRow(report = report) {
                        viewModel.selectReport(report)
                    }
                }
            }

            item {
                Spacer(modifier = Modifier.height(20.dp))
            }
        }
    }

    // Threat details modal bottom sheet
    selectedReport?.let { report ->
        ThreatDetailSheet(
            report = report,
            onDismiss = { viewModel.selectReport(null) },
            onDelete = { path -> viewModel.deleteFile(path) }
        )
    }
}

@Composable
fun MetricBox(
    modifier: Modifier = Modifier,
    title: String,
    value: String,
    valueColor: Color
) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(containerColor = CyberCardSurface),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(text = title, color = TextMuted, fontSize = 10.sp, fontWeight = FontWeight.Bold)
            Spacer(modifier = Modifier.height(4.dp))
            Text(text = value, color = valueColor, fontSize = 18.sp, fontWeight = FontWeight.ExtraBold)
        }
    }
}

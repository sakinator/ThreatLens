package io.threatlens.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.threatlens.R
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
    onNavigateScan: () -> Unit,
    onNavigateNews: () -> Unit,
    onNavigateSettings: () -> Unit
) {
    val isShieldActive by viewModel.isShieldActive.collectAsState()
    val scans by viewModel.scansList.collectAsState()
    val isScanning by viewModel.isScanning.collectAsState()
    val selectedReport by viewModel.selectedReport.collectAsState()

    val maliciousCount = scans.count { it.severity == ThreatSeverity.MALICIOUS || it.severity == ThreatSeverity.HIGH_RISK }
    val cleanCount = scans.count { it.severity == ThreatSeverity.SAFE }
    val isDeviceSafe = maliciousCount == 0

    Scaffold(
        containerColor = CyberBlack,
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            painter = painterResource(id = R.drawable.ic_threatlens_logo),
                            contentDescription = "ThreatLens Logo",
                            tint = NeonCyan,
                            modifier = Modifier.size(28.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
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
                Spacer(modifier = Modifier.height(4.dp))
                // Bitdefender Mobile Security Signature Hero Status Ring
                GlassCard {
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        CyberRadarShield(isProtected = isShieldActive && isDeviceSafe)
                        Spacer(modifier = Modifier.height(14.dp))
                        Text(
                            text = if (!isDeviceSafe) "YOUR DEVICE IS AT RISK" else if (isShieldActive) "YOU ARE PROTECTED" else "SHIELD IS OFF",
                            color = if (!isDeviceSafe) NeonCrimson else if (isShieldActive) NeonEmerald else CyberAmber,
                            fontWeight = FontWeight.Black,
                            fontSize = 17.sp,
                            letterSpacing = 0.5.sp
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = if (!isDeviceSafe) "$maliciousCount security threats require immediate attention" else "Real-time download intercept active • 0% idle load",
                            color = TextSecondary,
                            fontSize = 12.sp
                        )
                        Spacer(modifier = Modifier.height(16.dp))

                        // Bitdefender-style Primary Scan Button
                        Button(
                            onClick = onNavigateScan,
                            colors = ButtonDefaults.buttonColors(containerColor = NeonCyan),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(48.dp)
                        ) {
                            Icon(Icons.Default.Security, contentDescription = null, tint = CyberBlack)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("SCAN NOW (ON-DEMAND)", color = CyberBlack, fontWeight = FontWeight.Black, fontSize = 13.sp)
                        }
                    }
                }
            }

            // Quick Stats Row
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
                        title = "BATTERY DRAIN",
                        value = "< 0.5%",
                        valueColor = NeonCyan
                    )
                }
            }

            // Real-Time Interception Stream Header
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "REAL-TIME INTERCEPTION STREAM",
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
                            modifier = Modifier.fillMaxWidth().padding(20.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = "Zero threats detected in downloads.\nTap 'SCAN NOW' to run a deep device audit.",
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

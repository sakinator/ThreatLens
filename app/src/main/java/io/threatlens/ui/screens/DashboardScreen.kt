package io.threatlens.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.ui.text.font.FontFamily
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
    onNavigateSettings: () -> Unit,
    onNavigateWebProtection: () -> Unit = {}
) {
    val isShieldActive by viewModel.isShieldActive.collectAsState()
    val scans by viewModel.scansList.collectAsState()
    val isScanning by viewModel.isScanning.collectAsState()
    val fullScanState by viewModel.fullScanState.collectAsState()
    val selectedReport by viewModel.selectedReport.collectAsState()

    val isVpnActive by io.threatlens.core.vpn.ThreatLensVpnService.isVpnActive.collectAsState()
    val activeDns by io.threatlens.core.vpn.ThreatLensVpnService.activeDnsProvider.collectAsState()
    val filterIntensity by io.threatlens.core.vpn.DomainFilterEngine.filterIntensity.collectAsState()
    val mitmReport by io.threatlens.core.security.MitmDetector.lastReport.collectAsState()

    val isFullScanActive = fullScanState.status == io.threatlens.core.scanner.FullScanStatus.SCANNING || fullScanState.status == io.threatlens.core.scanner.FullScanStatus.PAUSED
    val maliciousCount = scans.count { it.severity == ThreatSeverity.MALICIOUS || it.severity == ThreatSeverity.HIGH_RISK } + fullScanState.threatsFound.size
    val cleanCount = scans.count { it.severity == ThreatSeverity.SAFE } + fullScanState.cleanCount
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
                        if (isFullScanActive) {
                            // Active Scan In-Progress Display
                            Box(
                                contentAlignment = Alignment.Center,
                                modifier = Modifier
                                    .size(130.dp)
                                    .clip(CircleShape)
                                    .background(CyberDarkSurface)
                                    .border(2.dp, NeonCyan, CircleShape)
                            ) {
                                CircularProgressIndicator(
                                    progress = { fullScanState.progress },
                                    modifier = Modifier.size(120.dp),
                                    color = NeonCyan,
                                    strokeWidth = 6.dp,
                                    trackColor = CyberCardBorder
                                )
                                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                    Text(
                                        text = "${(fullScanState.progress * 100).toInt()}%",
                                        color = NeonCyan,
                                        fontSize = 26.sp,
                                        fontWeight = FontWeight.Black,
                                        fontFamily = FontFamily.Monospace
                                    )
                                    Text(
                                        text = "${fullScanState.scannedCount}/${fullScanState.totalCount}",
                                        color = TextMuted,
                                        fontSize = 11.sp,
                                        fontFamily = FontFamily.Monospace
                                    )
                                }
                            }

                            Spacer(modifier = Modifier.height(10.dp))
                            Text(
                                text = "SYSTEM SCAN IN PROGRESS",
                                color = NeonCyan,
                                fontWeight = FontWeight.Black,
                                fontSize = 15.sp
                            )
                            Spacer(modifier = Modifier.height(3.dp))
                            Text(
                                text = fullScanState.currentItemName,
                                color = TextSecondary,
                                fontSize = 11.sp,
                                maxLines = 1
                            )

                            // Warning message under progress if threats detected so far
                            if (fullScanState.threatsFound.isNotEmpty()) {
                                Spacer(modifier = Modifier.height(8.dp))
                                Surface(
                                    color = NeonCrimson.copy(alpha = 0.15f),
                                    border = androidx.compose.foundation.BorderStroke(1.dp, NeonCrimson.copy(alpha = 0.5f)),
                                    shape = RoundedCornerShape(8.dp)
                                ) {
                                    Text(
                                        text = "⚠️ Device at risk: ${fullScanState.threatsFound.size} threats detected so far",
                                        color = NeonCrimson,
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp)
                                    )
                                }
                            }

                            Spacer(modifier = Modifier.height(14.dp))
                            Button(
                                onClick = onNavigateScan,
                                colors = ButtonDefaults.buttonColors(containerColor = NeonCyan),
                                shape = RoundedCornerShape(12.dp),
                                modifier = Modifier.fillMaxWidth().height(46.dp)
                            ) {
                                Icon(Icons.Default.Visibility, contentDescription = null, tint = CyberBlack)
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("VIEW ACTIVE SCAN", color = CyberBlack, fontWeight = FontWeight.Black, fontSize = 13.sp)
                            }
                        } else {
                            // Takes full space once scan is complete / idle
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

            // Web & Link Protection (Local VPN, DNS, MITM Defense)
            item {
                GlassCard(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onNavigateWebProtection() }
                        .border(
                            1.dp,
                            if (isVpnActive) NeonCyan.copy(alpha = 0.6f) else CyberCardBorder,
                            RoundedCornerShape(16.dp)
                        )
                ) {
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        verticalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Box(
                                    modifier = Modifier
                                        .size(36.dp)
                                        .background(
                                            if (isVpnActive) NeonCyan.copy(alpha = 0.2f) else CyberDarkSurface,
                                            CircleShape
                                        ),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.VpnLock,
                                        contentDescription = null,
                                        tint = if (isVpnActive) NeonCyan else TextMuted,
                                        modifier = Modifier.size(20.dp)
                                    )
                                }
                                Spacer(modifier = Modifier.width(10.dp))
                                Column {
                                    Text(
                                        text = "Web & Link Protection",
                                        color = Color.White,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 14.sp
                                    )
                                    Text(
                                        text = if (isVpnActive) "DNS Shield via ${activeDns.name}" else "Tap to configure local VPN & DNS",
                                        color = TextSecondary,
                                        fontSize = 11.sp
                                    )
                                }
                            }

                            Surface(
                                color = if (isVpnActive) NeonGreen.copy(alpha = 0.2f) else CyberDarkSurface,
                                shape = RoundedCornerShape(6.dp)
                            ) {
                                Text(
                                    text = if (isVpnActive) "ACTIVE" else "OFF",
                                    color = if (isVpnActive) NeonGreen else TextMuted,
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.Bold,
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                                )
                            }
                        }

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                Surface(
                                    color = CyberDarkSurface,
                                    shape = RoundedCornerShape(4.dp)
                                ) {
                                    Text(
                                        text = filterIntensity.title,
                                        color = Color(filterIntensity.badgeColorHex),
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                    )
                                }

                                Surface(
                                    color = CyberDarkSurface,
                                    shape = RoundedCornerShape(4.dp)
                                ) {
                                    Text(
                                        text = if (mitmReport.status == io.threatlens.core.security.MitmStatus.SECURE) "SSL Clean" else "MITM Alert",
                                        color = if (mitmReport.status == io.threatlens.core.security.MitmStatus.SECURE) NeonGreen else NeonRed,
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                    )
                                }
                            }

                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.clickable { onNavigateWebProtection() }
                            ) {
                                Text(
                                    text = "Configure",
                                    color = NeonCyan,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold
                                )
                                Icon(
                                    imageVector = Icons.Default.ChevronRight,
                                    contentDescription = null,
                                    tint = NeonCyan,
                                    modifier = Modifier.size(16.dp)
                                )
                            }
                        }
                    }
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
            onDelete = { threat -> viewModel.deleteThreat(threat) }
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

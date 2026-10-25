package io.threatlens.ui.screens

import androidx.compose.animation.core.*
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.threatlens.core.scanner.FullScanStatus
import io.threatlens.ui.components.GlassCard
import io.threatlens.ui.components.ThreatItemRow
import io.threatlens.ui.theme.*
import io.threatlens.ui.viewmodel.MainViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FullScanScreen(
    viewModel: MainViewModel
) {
    val scanState by viewModel.fullScanState.collectAsState()
    val isScanning = scanState.status == FullScanStatus.SCANNING
    val isCompleted = scanState.status == FullScanStatus.COMPLETED
    val context = androidx.compose.ui.platform.LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val isUpdatingSignatures by io.threatlens.core.update.SignatureUpdateService.isUpdating.collectAsState()

    Scaffold(
        containerColor = CyberBlack,
        topBar = {
            TopAppBar(
                title = { Text("On-Demand System Scan", color = TextPrimary, fontWeight = FontWeight.Bold) },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = CyberDarkSurface)
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            item {
                Spacer(modifier = Modifier.height(12.dp))
                // Central Bitdefender-style Circular Progress Gauge
                Box(
                    contentAlignment = Alignment.Center,
                    modifier = Modifier
                        .size(200.dp)
                        .clip(CircleShape)
                        .background(CyberCardSurface)
                        .border(
                            2.dp,
                            if (isScanning) NeonCyan else if (isCompleted && scanState.threatsFound.isEmpty()) NeonEmerald else CyberCardBorder,
                            CircleShape
                        )
                ) {
                    if (isScanning) {
                        CircularProgressIndicator(
                            progress = { scanState.progress },
                            modifier = Modifier.size(185.dp),
                            color = NeonCyan,
                            strokeWidth = 8.dp,
                            trackColor = CyberDarkSurface
                        )
                    }

                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        when (scanState.status) {
                            FullScanStatus.IDLE -> {
                                Icon(
                                    imageVector = Icons.Default.Shield,
                                    contentDescription = null,
                                    tint = NeonCyan,
                                    modifier = Modifier.size(56.dp)
                                )
                                Spacer(modifier = Modifier.height(6.dp))
                                Text(
                                    text = "Ready to Scan",
                                    color = TextSecondary,
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.SemiBold
                                )
                            }
                            FullScanStatus.SCANNING -> {
                                Text(
                                    text = "${(scanState.progress * 100).toInt()}%",
                                    color = NeonCyan,
                                    fontSize = 36.sp,
                                    fontWeight = FontWeight.Black,
                                    fontFamily = FontFamily.Monospace
                                )
                                Text(
                                    text = "${scanState.scannedCount}/${scanState.totalCount}",
                                    color = TextMuted,
                                    fontSize = 12.sp,
                                    fontFamily = FontFamily.Monospace
                                )
                            }
                            FullScanStatus.COMPLETED -> {
                                val hasThreats = scanState.threatsFound.isNotEmpty()
                                Icon(
                                    imageVector = if (hasThreats) Icons.Default.Warning else Icons.Default.CheckCircle,
                                    contentDescription = null,
                                    tint = if (hasThreats) NeonCrimson else NeonEmerald,
                                    modifier = Modifier.size(54.dp)
                                )
                                Spacer(modifier = Modifier.height(6.dp))
                                Text(
                                    text = if (hasThreats) "Threats Found!" else "Device Clean",
                                    color = if (hasThreats) NeonCrimson else NeonEmerald,
                                    fontSize = 16.sp,
                                    fontWeight = FontWeight.Bold
                                )
                            }
                            FullScanStatus.CANCELLED -> {
                                Icon(
                                    imageVector = Icons.Default.Cancel,
                                    contentDescription = null,
                                    tint = CyberAmber,
                                    modifier = Modifier.size(50.dp)
                                )
                                Text("Scan Cancelled", color = CyberAmber, fontSize = 13.sp)
                            }
                        }
                    }
                }
            }

            // Current scanning file info
            if (isScanning) {
                item {
                    GlassCard {
                        Text(
                            text = "Analyzing Application:",
                            color = TextMuted,
                            fontSize = 11.sp
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = scanState.currentItemName,
                            color = NeonCyan,
                            fontSize = 14.sp,
                            fontWeight = FontWeight.Bold,
                            maxLines = 1
                        )
                    }
                }
            }

            // Offline Virus Signatures & Definition Status Bar
            item {
                Surface(
                    color = CyberDarkSurface,
                    border = androidx.compose.foundation.BorderStroke(1.dp, CyberCardBorder),
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                            Icon(Icons.Default.Security, contentDescription = null, tint = NeonCyan, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Column {
                                Text(
                                    text = "Offline Signatures: ${io.threatlens.core.local.LocalSignatureDatabase.totalSignatures} Active",
                                    color = Color.White,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 12.sp
                                )
                                Text(
                                    text = "Sources: MalwareBazaar, CIRCL, ATT&CK, VX-Underground",
                                    color = TextMuted,
                                    fontSize = 9.sp
                                )
                            }
                        }

                        TextButton(
                            onClick = {
                                coroutineScope.launch {
                                    io.threatlens.core.update.SignatureUpdateService.updateSignaturesNow(context)
                                }
                            },
                            contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)
                        ) {
                            if (isUpdatingSignatures) {
                                CircularProgressIndicator(modifier = Modifier.size(12.dp), color = NeonCyan, strokeWidth = 1.5.dp)
                            } else {
                                Text("Update", color = NeonCyan, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }

            // Primary Action Button (Start Scan / Cancel)
            item {
                if (isScanning) {
                    OutlinedButton(
                        onClick = { viewModel.cancelFullScan() },
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = CyberAmber),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth().height(48.dp)
                    ) {
                        Icon(Icons.Default.Stop, contentDescription = "Cancel")
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Cancel Scan", fontWeight = FontWeight.Bold)
                    }
                } else {
                    Button(
                        onClick = { viewModel.startFullOnDemandScan() },
                        colors = ButtonDefaults.buttonColors(containerColor = NeonCyan),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth().height(52.dp)
                    ) {
                        Icon(Icons.Default.PlayArrow, contentDescription = "Start", tint = CyberBlack)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("START FULL DEVICE SCAN", color = CyberBlack, fontWeight = FontWeight.Black)
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    // Custom File Picker Scan
                    val context = androidx.compose.ui.platform.LocalContext.current
                    val coroutineScope = rememberCoroutineScope()
                    val filePickerLauncher = androidx.activity.compose.rememberLauncherForActivityResult(
                        contract = androidx.activity.result.contract.ActivityResultContracts.GetContent()
                    ) { uri ->
                        if (uri != null) {
                            coroutineScope.launch(kotlinx.coroutines.Dispatchers.IO) {
                                try {
                                    val tempFile = java.io.File(context.cacheDir, "manual_scan_target.apk")
                                    context.contentResolver.openInputStream(uri)?.use { input ->
                                        tempFile.outputStream().use { output -> input.copyTo(output) }
                                    }
                                    if (tempFile.exists()) {
                                        val report = io.threatlens.core.realtime.RealtimeScanCoordinator.streamScan(context, tempFile)
                                        viewModel.selectReport(report)
                                    }
                                } catch (_: Exception) {}
                            }
                        }
                    }

                    OutlinedButton(
                        onClick = { filePickerLauncher.launch("*/*") },
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = NeonCyan),
                        border = androidx.compose.foundation.BorderStroke(1.dp, NeonCyan.copy(alpha = 0.6f)),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth().height(46.dp)
                    ) {
                        Icon(Icons.Default.FolderOpen, contentDescription = null, tint = NeonCyan, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("CUSTOM SCAN (SELECT FILE / APK)", color = NeonCyan, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }

            // Scan Results Summary Card
            if (isCompleted) {
                item {
                    GlassCard {
                        Text(
                            text = "Full Scan Summary",
                            color = TextPrimary,
                            fontWeight = FontWeight.Bold,
                            fontSize = 15.sp
                        )
                        Spacer(modifier = Modifier.height(10.dp))
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("Total Scanned:", color = TextSecondary, fontSize = 13.sp)
                            Text("${scanState.totalCount} items", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        }
                        Spacer(modifier = Modifier.height(6.dp))
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("Verified Safe:", color = TextSecondary, fontSize = 13.sp)
                            Text("${scanState.cleanCount}", color = NeonEmerald, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        }
                        Spacer(modifier = Modifier.height(6.dp))
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("Threats Detected:", color = TextSecondary, fontSize = 13.sp)
                            Text("${scanState.threatsFound.size}", color = if (scanState.threatsFound.isNotEmpty()) NeonCrimson else NeonEmerald, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        }
                        Spacer(modifier = Modifier.height(6.dp))
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            Text("Duration:", color = TextSecondary, fontSize = 13.sp)
                            Text("${scanState.durationMs / 1000}s", color = TextPrimary, fontSize = 13.sp)
                        }
                    }
                }
            }

            // Threats Found List
            if (scanState.threatsFound.isNotEmpty()) {
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "THREATS REQUIRING ATTENTION (${scanState.threatsFound.size})",
                            color = NeonCrimson,
                            fontWeight = FontWeight.Bold,
                            fontSize = 12.sp
                        )
                    }
                }

                item {
                    Button(
                        onClick = {
                            scanState.threatsFound.forEach { threat ->
                                viewModel.deleteFile(threat.targetPath)
                            }
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = NeonCrimson),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth().height(48.dp)
                    ) {
                        Icon(Icons.Default.DeleteForever, contentDescription = null, tint = Color.White)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "DELETE ALL ${scanState.threatsFound.size} DETECTED THREATS",
                            fontWeight = FontWeight.Black,
                            color = Color.White,
                            fontSize = 12.sp
                        )
                    }
                }

                items(scanState.threatsFound) { report ->
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
}

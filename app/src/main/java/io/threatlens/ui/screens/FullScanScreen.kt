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
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FullScanScreen(
    viewModel: MainViewModel
) {
    val scanState by viewModel.fullScanState.collectAsState()
    val isScanning = scanState.status == FullScanStatus.SCANNING
    val isPaused = scanState.status == FullScanStatus.PAUSED
    val isCompleted = scanState.status == FullScanStatus.COMPLETED
    val selectedReport by viewModel.selectedReport.collectAsState()
    var showConfirmDeleteAllDialog by remember { mutableStateOf(false) }

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
                            when {
                                isScanning -> NeonCyan
                                isPaused -> CyberAmber
                                isCompleted && scanState.threatsFound.isEmpty() -> NeonEmerald
                                isCompleted && scanState.threatsFound.isNotEmpty() -> NeonCrimson
                                else -> CyberCardBorder
                            },
                            CircleShape
                        )
                ) {
                    if (isScanning || isPaused) {
                        CircularProgressIndicator(
                            progress = { scanState.progress },
                            modifier = Modifier.size(185.dp),
                            color = if (isScanning) NeonCyan else CyberAmber,
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
                            FullScanStatus.SCANNING, FullScanStatus.PAUSED -> {
                                Text(
                                    text = "${(scanState.progress * 100).toInt()}%",
                                    color = if (isScanning) NeonCyan else CyberAmber,
                                    fontSize = 36.sp,
                                    fontWeight = FontWeight.Black,
                                    fontFamily = FontFamily.Monospace
                                )
                                Text(
                                    text = if (isPaused) "SCAN PAUSED" else "${scanState.scannedCount}/${scanState.totalCount}",
                                    color = if (isPaused) CyberAmber else TextMuted,
                                    fontSize = 12.sp,
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = if (isPaused) FontWeight.Bold else FontWeight.Normal
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
                                    text = if (hasThreats) "Device at Risk!" else "Device Clean",
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
                                Text("Scan Aborted", color = CyberAmber, fontSize = 13.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }

            // IN-PROGRESS WARNING MESSAGE UNDER PROGRESS GAUGE (only when scan not yet complete)
            if ((isScanning || isPaused) && scanState.threatsFound.isNotEmpty()) {
                item {
                    Surface(
                        color = NeonCrimson.copy(alpha = 0.15f),
                        border = androidx.compose.foundation.BorderStroke(1.dp, NeonCrimson.copy(alpha = 0.6f)),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier.padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(Icons.Default.Warning, contentDescription = null, tint = NeonCrimson, modifier = Modifier.size(24.dp))
                            Spacer(modifier = Modifier.width(10.dp))
                            Column {
                                Text(
                                    text = "DEVICE AT RISK (${scanState.threatsFound.size} Threat${if (scanState.threatsFound.size > 1) "s" else ""} Detected)",
                                    color = NeonCrimson,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 13.sp
                                )
                                Text(
                                    text = "Scan in progress • Full risk analysis will expand once scan completes",
                                    color = TextSecondary,
                                    fontSize = 11.sp
                                )
                            }
                        }
                    }
                }
            }

            // Current scanning file info
            if (isScanning || isPaused) {
                item {
                    GlassCard {
                        Text(
                            text = if (isPaused) "Currently Paused At:" else "Analyzing Application:",
                            color = TextMuted,
                            fontSize = 11.sp
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = scanState.currentItemName,
                            color = if (isScanning) NeonCyan else CyberAmber,
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
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(
                                        text = "Offline Signatures: ${io.threatlens.core.local.LocalSignatureDatabase.totalSignatures} Active",
                                        color = Color.White,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 12.sp
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Surface(
                                        color = NeonEmerald.copy(alpha = 0.15f),
                                        shape = RoundedCornerShape(4.dp)
                                    ) {
                                        Text(
                                            text = io.threatlens.core.update.SignatureUpdateService.getFormattedLastUpdated(),
                                            color = NeonEmerald,
                                            fontSize = 9.sp,
                                            fontFamily = FontFamily.Monospace,
                                            fontWeight = FontWeight.Bold,
                                            modifier = Modifier.padding(horizontal = 4.dp, vertical = 1.dp)
                                        )
                                    }
                                }
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

            // Primary Action Buttons: Start / Pause / Resume / Abort
            item {
                if (isScanning) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Button(
                            onClick = { viewModel.pauseFullScan() },
                            colors = ButtonDefaults.buttonColors(containerColor = CyberAmber),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.weight(1f).height(48.dp)
                        ) {
                            Icon(Icons.Default.Pause, contentDescription = "Pause", tint = CyberBlack)
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("PAUSE", color = CyberBlack, fontWeight = FontWeight.Black)
                        }

                        OutlinedButton(
                            onClick = { viewModel.abortFullScan() },
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = NeonCrimson),
                            border = androidx.compose.foundation.BorderStroke(1.dp, NeonCrimson),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.weight(1f).height(48.dp)
                        ) {
                            Icon(Icons.Default.Stop, contentDescription = "Abort")
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("ABORT", color = NeonCrimson, fontWeight = FontWeight.Black)
                        }
                    }
                } else if (isPaused) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Button(
                            onClick = { viewModel.resumeFullScan() },
                            colors = ButtonDefaults.buttonColors(containerColor = NeonCyan),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.weight(1f).height(48.dp)
                        ) {
                            Icon(Icons.Default.PlayArrow, contentDescription = "Resume", tint = CyberBlack)
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("RESUME", color = CyberBlack, fontWeight = FontWeight.Black)
                        }

                        OutlinedButton(
                            onClick = { viewModel.abortFullScan() },
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = NeonCrimson),
                            border = androidx.compose.foundation.BorderStroke(1.dp, NeonCrimson),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier.weight(1f).height(48.dp)
                        ) {
                            Icon(Icons.Default.Stop, contentDescription = "Abort")
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("ABORT", color = NeonCrimson, fontWeight = FontWeight.Black)
                        }
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

            // FULL SPACE SCAN RESULTS SUMMARY (Takes full space once full scan is complete)
            if (isCompleted) {
                item {
                    val hasThreats = scanState.threatsFound.isNotEmpty()
                    Surface(
                        color = if (hasThreats) NeonCrimson.copy(alpha = 0.12f) else NeonEmerald.copy(alpha = 0.12f),
                        border = androidx.compose.foundation.BorderStroke(
                            1.dp,
                            if (hasThreats) NeonCrimson.copy(alpha = 0.7f) else NeonEmerald.copy(alpha = 0.7f)
                        ),
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(modifier = Modifier.padding(16.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(
                                    imageVector = if (hasThreats) Icons.Default.Warning else Icons.Default.CheckCircle,
                                    contentDescription = null,
                                    tint = if (hasThreats) NeonCrimson else NeonEmerald,
                                    modifier = Modifier.size(28.dp)
                                )
                                Spacer(modifier = Modifier.width(10.dp))
                                Column {
                                    Text(
                                        text = if (hasThreats) "DEVICE AT RISK: ${scanState.threatsFound.size} THREATS FOUND" else "DEVICE SECURE & PROTECTED",
                                        color = if (hasThreats) NeonCrimson else NeonEmerald,
                                        fontWeight = FontWeight.Black,
                                        fontSize = 15.sp
                                    )
                                    Text(
                                        text = if (hasThreats) "Immediate cleanup required to ensure device safety" else "All installed applications and downloads verified safe",
                                        color = TextSecondary,
                                        fontSize = 11.sp
                                    )
                                }
                            }

                            Spacer(modifier = Modifier.height(14.dp))
                            Divider(color = CyberCardBorder.copy(alpha = 0.4f))
                            Spacer(modifier = Modifier.height(10.dp))

                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                Text("Total Items Scanned:", color = TextSecondary, fontSize = 13.sp)
                                Text("${scanState.totalCount} items", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                            }
                            Spacer(modifier = Modifier.height(6.dp))
                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                Text("Verified Safe:", color = TextSecondary, fontSize = 13.sp)
                                Text("${scanState.cleanCount}", color = NeonEmerald, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                            }
                            Spacer(modifier = Modifier.height(6.dp))
                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                Text("Threats Flagged:", color = TextSecondary, fontSize = 13.sp)
                                Text("${scanState.threatsFound.size}", color = if (hasThreats) NeonCrimson else NeonEmerald, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                            }
                            Spacer(modifier = Modifier.height(6.dp))
                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                Text("Total Scan Duration:", color = TextSecondary, fontSize = 13.sp)
                                Text("${scanState.durationMs / 1000}s", color = TextPrimary, fontSize = 13.sp)
                            }
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
                        onClick = { showConfirmDeleteAllDialog = true },
                        colors = ButtonDefaults.buttonColors(containerColor = NeonCrimson),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth().height(48.dp)
                    ) {
                        Icon(Icons.Default.DeleteForever, contentDescription = null, tint = Color.White)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "UNINSTALL / DELETE ALL ${scanState.threatsFound.size} DETECTED THREATS",
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

    // Confirmation Dialog for Bulk Delete / Uninstall
    if (showConfirmDeleteAllDialog) {
        AlertDialog(
            onDismissRequest = { showConfirmDeleteAllDialog = false },
            containerColor = CyberDarkSurface,
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.DeleteForever, contentDescription = null, tint = NeonCrimson, modifier = Modifier.size(24.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Remove All ${scanState.threatsFound.size} Threats?", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                }
            },
            text = {
                Text(
                    text = "This will permanently delete all downloaded malicious files and launch system uninstallers for any detected app threats.",
                    color = TextSecondary,
                    fontSize = 13.sp,
                    lineHeight = 18.sp
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        showConfirmDeleteAllDialog = false
                        scanState.threatsFound.forEach { threat ->
                            viewModel.deleteThreat(threat)
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = NeonCrimson),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text("REMOVE ALL NOW", color = Color.White, fontWeight = FontWeight.Black)
                }
            },
            dismissButton = {
                OutlinedButton(
                    onClick = { showConfirmDeleteAllDialog = false },
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = TextPrimary),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text("CANCEL")
                }
            }
        )
    }

    // Modal Bottom Sheet for Threat Detail View
    selectedReport?.let { report ->
        ThreatDetailSheet(
            report = report,
            onDismiss = { viewModel.selectReport(null) },
            onDelete = { threat -> viewModel.deleteThreat(threat) }
        )
    }
}

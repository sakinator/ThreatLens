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
import io.threatlens.core.model.ThreatReport
import io.threatlens.core.model.ThreatSeverity
import io.threatlens.core.scanner.FullScanStatus
import io.threatlens.ui.components.GlassCard
import io.threatlens.ui.components.ThreatItemRow
import io.threatlens.ui.theme.*
import io.threatlens.ui.viewmodel.MainViewModel
import kotlinx.coroutines.launch

enum class ScanResultFilter {
    ALL,
    THREATS,
    SAFE
}

enum class ScanSortOption(val label: String) {
    MALWARE_FIRST("Malware → Suspicious → Clean"),
    SCORE_DESC("Threat Score (Highest First)"),
    NAME_ASC("Application Name (A → Z)")
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FullScanScreen(
    viewModel: MainViewModel
) {
    val scanState by viewModel.fullScanState.collectAsState()
    val isScanning = scanState.status == FullScanStatus.SCANNING
    val isPaused = scanState.status == FullScanStatus.PAUSED
    val isCompleted = scanState.status == FullScanStatus.COMPLETED
    val hasThreats = scanState.threatsFound.isNotEmpty()
    val selectedReport by viewModel.selectedReport.collectAsState()
    val uploadProgress by viewModel.uploadProgress.collectAsState()
    val vtKey by viewModel.vtKey.collectAsState()
    var showConfirmDeleteAllDialog by remember { mutableStateOf(false) }
    var selectedFilter by remember { mutableStateOf(ScanResultFilter.ALL) }
    var selectedSortOption by remember { mutableStateOf(ScanSortOption.MALWARE_FIRST) }
    var showSortDropdown by remember { mutableStateOf(false) }

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
                                val hasMalicious = scanState.threatsFound.any { it.severity == ThreatSeverity.MALICIOUS }
                                val hasSuspiciousOnly = scanState.threatsFound.isNotEmpty() && !hasMalicious
                                val hasThreats = hasMalicious || hasSuspiciousOnly
                                val gaugeColor = when {
                                    hasMalicious -> NeonCrimson
                                    hasSuspiciousOnly -> CyberAmber
                                    else -> NeonEmerald
                                }
                                val gaugeText = when {
                                    hasMalicious -> "Device at Risk!"
                                    hasSuspiciousOnly -> "Device May Be at Risk"
                                    else -> "Device Clean"
                                }

                                Icon(
                                    imageVector = if (hasThreats) Icons.Default.Warning else Icons.Default.CheckCircle,
                                    contentDescription = null,
                                    tint = gaugeColor,
                                    modifier = Modifier.size(54.dp)
                                )
                                Spacer(modifier = Modifier.height(6.dp))
                                Text(
                                    text = gaugeText,
                                    color = gaugeColor,
                                    fontSize = 15.sp,
                                    fontWeight = FontWeight.Bold
                                )
                            }
                            FullScanStatus.CANCELLED -> {
                                Icon(
                                    imageVector = Icons.Default.Cancel,
                                    contentDescription = null,
                                    tint = NeonCrimson,
                                    modifier = Modifier.size(50.dp)
                                )
                                Text("Scan Aborted", color = NeonCrimson, fontSize = 13.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }

            // IN-PROGRESS WARNING MESSAGE UNDER PROGRESS GAUGE (only when scan not yet complete)
            if ((isScanning || isPaused) && scanState.threatsFound.isNotEmpty()) {
                val hasMalicious = scanState.threatsFound.any { it.severity == ThreatSeverity.MALICIOUS }
                val bannerColor = if (hasMalicious) NeonCrimson else CyberAmber
                val bannerTitle = if (hasMalicious) {
                    "DEVICE AT RISK (${scanState.threatsFound.size} Threat${if (scanState.threatsFound.size > 1) "s" else ""} Detected)"
                } else {
                    "DEVICE MAY BE AT RISK (${scanState.threatsFound.size} Suspicious App${if (scanState.threatsFound.size > 1) "s" else ""} Detected)"
                }
                item {
                    Surface(
                        color = bannerColor.copy(alpha = 0.15f),
                        border = androidx.compose.foundation.BorderStroke(1.dp, bannerColor.copy(alpha = 0.6f)),
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            modifier = Modifier.padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(Icons.Default.Warning, contentDescription = null, tint = bannerColor, modifier = Modifier.size(24.dp))
                            Spacer(modifier = Modifier.width(10.dp))
                            Column {
                                Text(
                                    text = bannerTitle,
                                    color = bannerColor,
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
                                Text(
                                    text = "Offline Signatures: ${io.threatlens.core.local.LocalSignatureDatabase.totalSignatures} Active",
                                    color = Color.White,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 12.sp
                                )
                                Text(
                                    text = "Sources: ClamAV CVD, VirusTotal YARA, MalwareBazaar, CIRCL, ATT&CK",
                                    color = TextMuted,
                                    fontSize = 9.sp
                                )
                            }
                        }

                        Column(
                            horizontalAlignment = Alignment.End,
                            verticalArrangement = Arrangement.Center
                        ) {
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
                                    Text("UPDATE", color = NeonCyan, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                }
                            }
                            Text(
                                text = io.threatlens.core.update.SignatureUpdateService.getFormattedLastUpdated(),
                                color = TextMuted,
                                fontSize = 9.sp,
                                fontFamily = FontFamily.Monospace,
                                modifier = Modifier.padding(end = 8.dp)
                            )
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

                            Spacer(modifier = Modifier.height(14.dp))
                            Button(
                                onClick = {
                                    val exported = io.threatlens.core.export.ScanReportExporter.exportScanReport(
                                        context,
                                        scanState,
                                        scanState.allScannedReports
                                    )
                                    if (exported != null) {
                                        io.threatlens.core.export.ScanReportExporter.shareReportFile(context, exported)
                                    }
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = NeonCyan),
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier.fillMaxWidth().height(44.dp)
                            ) {
                                Icon(Icons.Default.Share, contentDescription = null, tint = CyberBlack, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("EXPORT SCAN REPORT (.JSON)", color = CyberBlack, fontWeight = FontWeight.Black, fontSize = 12.sp)
                            }
                        }
                    }
                }

                // Filter Tabs: ALL | THREATS | SAFE
                val allCount = scanState.allScannedReports.size.coerceAtLeast(scanState.totalCount)
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        // ALL Pill
                        Surface(
                            onClick = { selectedFilter = ScanResultFilter.ALL },
                            color = if (selectedFilter == ScanResultFilter.ALL) NeonCyan.copy(alpha = 0.2f) else CyberDarkSurface,
                            border = androidx.compose.foundation.BorderStroke(
                                1.dp,
                                if (selectedFilter == ScanResultFilter.ALL) NeonCyan else CyberCardBorder
                            ),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.weight(1f)
                        ) {
                            Text(
                                text = "ALL ($allCount)",
                                color = if (selectedFilter == ScanResultFilter.ALL) NeonCyan else TextSecondary,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                textAlign = TextAlign.Center,
                                modifier = Modifier.padding(vertical = 8.dp)
                            )
                        }

                        // THREATS Pill
                        Surface(
                            onClick = { selectedFilter = ScanResultFilter.THREATS },
                            color = if (selectedFilter == ScanResultFilter.THREATS) {
                                if (hasThreats) NeonCrimson.copy(alpha = 0.2f) else CyberDarkSurface
                            } else CyberDarkSurface,
                            border = androidx.compose.foundation.BorderStroke(
                                1.dp,
                                if (selectedFilter == ScanResultFilter.THREATS) {
                                    if (hasThreats) NeonCrimson else NeonCyan
                                } else CyberCardBorder
                            ),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.weight(1f)
                        ) {
                            Text(
                                text = "THREATS (${scanState.threatsFound.size})",
                                color = if (selectedFilter == ScanResultFilter.THREATS) {
                                    if (hasThreats) NeonCrimson else NeonCyan
                                } else TextSecondary,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                textAlign = TextAlign.Center,
                                modifier = Modifier.padding(vertical = 8.dp)
                            )
                        }

                        // SAFE Pill
                        Surface(
                            onClick = { selectedFilter = ScanResultFilter.SAFE },
                            color = if (selectedFilter == ScanResultFilter.SAFE) NeonEmerald.copy(alpha = 0.2f) else CyberDarkSurface,
                            border = androidx.compose.foundation.BorderStroke(
                                1.dp,
                                if (selectedFilter == ScanResultFilter.SAFE) NeonEmerald else CyberCardBorder
                            ),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.weight(1f)
                        ) {
                            Text(
                                text = "SAFE (${scanState.cleanCount})",
                                color = if (selectedFilter == ScanResultFilter.SAFE) NeonEmerald else TextSecondary,
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                textAlign = TextAlign.Center,
                                modifier = Modifier.padding(vertical = 8.dp)
                            )
                        }
                    }
                }

                // Sorting Selector Bar (Malware -> Suspicious -> Clean)
                item {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 4.dp, vertical = 2.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Default.Sort,
                                contentDescription = "Sort",
                                tint = NeonCyan,
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = "ORDER BY:",
                                color = TextMuted,
                                fontSize = 10.sp,
                                fontWeight = FontWeight.Bold,
                                fontFamily = FontFamily.Monospace,
                                letterSpacing = 0.5.sp
                            )
                        }

                        Box {
                            Surface(
                                onClick = { showSortDropdown = true },
                                color = CyberDarkSurface,
                                shape = RoundedCornerShape(6.dp),
                                border = androidx.compose.foundation.BorderStroke(1.dp, CyberCardBorder)
                            ) {
                                Row(
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = selectedSortOption.label,
                                        color = NeonCyan,
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Bold
                                    )
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Icon(
                                        imageVector = Icons.Default.ArrowDropDown,
                                        contentDescription = null,
                                        tint = NeonCyan,
                                        modifier = Modifier.size(16.dp)
                                    )
                                }
                            }

                            DropdownMenu(
                                expanded = showSortDropdown,
                                onDismissRequest = { showSortDropdown = false },
                                modifier = Modifier.background(CyberDarkSurface)
                            ) {
                                ScanSortOption.values().forEach { option ->
                                    DropdownMenuItem(
                                        text = {
                                            Text(
                                                text = option.label,
                                                color = if (selectedSortOption == option) NeonCyan else TextPrimary,
                                                fontSize = 12.sp,
                                                fontWeight = if (selectedSortOption == option) FontWeight.Bold else FontWeight.Normal
                                            )
                                        },
                                        onClick = {
                                            selectedSortOption = option
                                            showSortDropdown = false
                                        }
                                    )
                                }
                            }
                        }
                    }
                }
            }

            // Display Scanned Items based on scan state, filter and sort order
            val baseList = when {
                isCompleted -> when (selectedFilter) {
                    ScanResultFilter.THREATS -> scanState.threatsFound
                    ScanResultFilter.SAFE -> scanState.allScannedReports.filter { it.severity == ThreatSeverity.SAFE }
                    ScanResultFilter.ALL -> if (scanState.allScannedReports.isNotEmpty()) {
                        scanState.allScannedReports
                    } else {
                        scanState.threatsFound
                    }
                }
                scanState.threatsFound.isNotEmpty() -> scanState.threatsFound
                else -> emptyList()
            }

            val displayList = when (selectedSortOption) {
                ScanSortOption.MALWARE_FIRST -> baseList.sortedWith(
                    compareBy<ThreatReport> { report ->
                        when (report.severity) {
                            ThreatSeverity.MALICIOUS -> 0
                            ThreatSeverity.HIGH_RISK -> 1
                            ThreatSeverity.SUSPICIOUS -> 2
                            ThreatSeverity.SAFE -> 3
                        }
                    }.thenByDescending { it.currentScore }
                     .thenBy { (it.appName ?: it.targetName).lowercase() }
                )
                ScanSortOption.SCORE_DESC -> baseList.sortedByDescending { it.currentScore }
                ScanSortOption.NAME_ASC -> baseList.sortedBy { (it.appName ?: it.targetName).lowercase() }
            }

            if (displayList.isNotEmpty()) {
                val hasMalicious = displayList.any { it.severity == ThreatSeverity.MALICIOUS }
                val hasAnyThreatsInList = displayList.any { it.severity != ThreatSeverity.SAFE }

                if (hasAnyThreatsInList && (selectedFilter == ScanResultFilter.THREATS || (selectedFilter == ScanResultFilter.ALL && scanState.threatsFound.isNotEmpty()))) {
                    val sectionTitle = if (hasMalicious) {
                        "CRITICAL THREATS REQUIRING ATTENTION (${scanState.threatsFound.size})"
                    } else {
                        "SUSPICIOUS APPS REQUIRING REVIEW (${scanState.threatsFound.size})"
                    }
                    val sectionColor = if (hasMalicious) NeonCrimson else CyberAmber
                    val buttonText = if (hasMalicious) {
                        "UNINSTALL / DELETE ALL ${scanState.threatsFound.size} DETECTED THREATS"
                    } else {
                        "REVIEW / REMOVE ALL ${scanState.threatsFound.size} SUSPICIOUS APPS"
                    }

                    item {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = sectionTitle,
                                color = sectionColor,
                                fontWeight = FontWeight.Bold,
                                fontSize = 12.sp
                            )
                        }
                    }

                    item {
                        Button(
                            onClick = { showConfirmDeleteAllDialog = true },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = if (hasMalicious) NeonCrimson else CyberAmber.copy(alpha = 0.2f),
                                contentColor = if (hasMalicious) Color.White else CyberAmber
                            ),
                            border = if (hasMalicious) null else androidx.compose.foundation.BorderStroke(1.dp, CyberAmber.copy(alpha = 0.6f)),
                            shape = RoundedCornerShape(12.dp),
                            modifier = Modifier
                                .fillMaxWidth()
                                .heightIn(min = 48.dp)
                                .padding(vertical = 2.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.DeleteForever,
                                contentDescription = null,
                                tint = if (hasMalicious) Color.White else CyberAmber
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = buttonText,
                                fontWeight = FontWeight.Black,
                                fontSize = 12.sp,
                                maxLines = 1
                            )
                        }
                    }
                }

                items(displayList) { report ->
                    ThreatItemRow(report = report) {
                        viewModel.selectReport(report)
                    }
                }
            } else if (isCompleted && selectedFilter == ScanResultFilter.THREATS && scanState.threatsFound.isEmpty()) {
                item {
                    GlassCard {
                        Box(
                            modifier = Modifier.fillMaxWidth().padding(24.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = "✓ Zero threats detected across all scanned applications.",
                                color = NeonEmerald,
                                fontSize = 13.sp,
                                textAlign = TextAlign.Center,
                                fontWeight = FontWeight.Bold
                            )
                        }
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
            onDelete = { threat -> viewModel.deleteThreat(threat) },
            onUploadSample = { viewModel.uploadSampleToVirusTotal(it) },
            uploadProgress = uploadProgress,
            isVtKeyConfigured = vtKey.isNotBlank()
        )
    }
}

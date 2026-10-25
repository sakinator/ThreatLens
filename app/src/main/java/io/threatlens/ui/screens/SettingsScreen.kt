package io.threatlens.ui.screens

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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.threatlens.core.local.LocalSignatureDatabase
import io.threatlens.core.update.SignatureUpdateService
import io.threatlens.core.update.SignatureUpdateStatus
import io.threatlens.ui.components.EngineLogoIcon
import io.threatlens.ui.components.GlassCard
import io.threatlens.ui.theme.*
import io.threatlens.ui.viewmodel.MainViewModel
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    viewModel: MainViewModel,
    onBack: () -> Unit,
    onNavigateAbout: () -> Unit = {},
    onNavigateWebProtection: () -> Unit = {},
    onNavigateExclusions: () -> Unit = {}
) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()

    var openaiInput by remember { mutableStateOf(viewModel.openAiKey.value) }
    var claudeInput by remember { mutableStateOf(viewModel.claudeKey.value) }
    var geminiInput by remember { mutableStateOf(viewModel.geminiKey.value) }
    var groqInput by remember { mutableStateOf(viewModel.groqKey.value) }
    var vtInput by remember { mutableStateOf(viewModel.vtKey.value) }
    var haInput by remember { mutableStateOf(viewModel.haKey.value) }
    var kasperskyInput by remember { mutableStateOf(viewModel.kasperskyKey.value) }
    var metaDefenderInput by remember { mutableStateOf(viewModel.metaDefenderKey.value) }
    var filescanInput by remember { mutableStateOf(viewModel.filescanKey.value) }
    var savedSnackbar by remember { mutableStateOf(false) }

    val isUpdatingSignatures by SignatureUpdateService.isUpdating.collectAsState()
    val signatureStatus by SignatureUpdateService.status.collectAsState()
    val signatureVersion by SignatureUpdateService.signatureVersion.collectAsState()
    val lastUpdateTimestamp by SignatureUpdateService.lastUpdateTimestamp.collectAsState()
    var autoUpdateEnabled by remember { mutableStateOf(SignatureUpdateService.isAutoUpdateEnabled(context)) }
    var showSourcesDetail by remember { mutableStateOf(false) }

    Scaffold(
        containerColor = CyberBlack,
        topBar = {
            TopAppBar(
                title = { Text("ThreatLens Settings", color = TextPrimary, fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(imageVector = Icons.Default.ArrowBack, contentDescription = "Back", tint = NeonCyan)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = CyberDarkSurface)
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState())
        ) {
            Spacer(modifier = Modifier.height(14.dp))

            // Navigation to Web & Link Protection Screen
            GlassCard {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onNavigateWebProtection() },
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.VpnLock, contentDescription = null, tint = NeonCyan, modifier = Modifier.size(24.dp))
                        Spacer(modifier = Modifier.width(12.dp))
                        Column {
                            Text("Web & Link Protection", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                            Text("Local VPN, DNS selection, ad & malware blocking, MITM defense", color = TextSecondary, fontSize = 11.sp)
                        }
                    }
                    Icon(Icons.Default.ChevronRight, contentDescription = null, tint = TextMuted)
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Navigation to Exclusions & Whitelist (Bypassable Files, Apps & URLs)
            GlassCard {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onNavigateExclusions() },
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Shield, contentDescription = null, tint = NeonEmerald, modifier = Modifier.size(24.dp))
                        Spacer(modifier = Modifier.width(12.dp))
                        Column {
                            Text("Exclusions & Whitelist", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                            Text("Configure bypassable files, apps, folders & whitelisted URLs", color = TextSecondary, fontSize = 11.sp)
                        }
                    }
                    Icon(Icons.Default.ChevronRight, contentDescription = null, tint = TextMuted)
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Navigation to About & Software Updates Screen
            GlassCard {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onNavigateAbout() },
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Info, contentDescription = null, tint = NeonCyan, modifier = Modifier.size(24.dp))
                        Spacer(modifier = Modifier.width(12.dp))
                        Column {
                            Text("About ThreatLens & Credits", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                            Text("Version 1.0.0 • Check for updates & links", color = TextSecondary, fontSize = 11.sp)
                        }
                    }
                    Icon(Icons.Default.ChevronRight, contentDescription = null, tint = TextMuted)
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Battery & Performance Info Card
            GlassCard {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.BatteryChargingFull,
                        contentDescription = "Battery",
                        tint = NeonEmerald,
                        modifier = Modifier.size(24.dp)
                    )
                    Spacer(modifier = Modifier.width(10.dp))
                    Text(
                        text = "Zero-Idle Battery Mode Active",
                        color = NeonEmerald,
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp
                    )
                }
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "ThreatLens uses passive Linux inotify kernel events. The CPU remains asleep during idle; only executable payloads (.apk, .dex) trigger scans.",
                    color = TextSecondary,
                    fontSize = 12.sp,
                    lineHeight = 17.sp
                )
            }

            Spacer(modifier = Modifier.height(14.dp))

            // VIRUS SIGNATURE DATABASE & OFFLINE ENGINE SECTION
            GlassCard {
                Column(modifier = Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Default.Security,
                                contentDescription = null,
                                tint = NeonCyan,
                                modifier = Modifier.size(24.dp)
                            )
                            Spacer(modifier = Modifier.width(10.dp))
                            Column {
                                Text(
                                    text = "Virus Signature Database",
                                    color = Color.White,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 14.sp
                                )
                                Text(
                                    text = "100% Free On-Device Protection (No Internet Needed)",
                                    color = NeonGreen,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.SemiBold
                                )
                            }
                        }

                        Surface(
                            color = CyberDarkSurface,
                            shape = RoundedCornerShape(6.dp)
                        ) {
                            Text(
                                text = signatureVersion,
                                color = NeonCyan,
                                fontSize = 10.sp,
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                            )
                        }
                    }

                    Divider(color = CyberCardBorder.copy(alpha = 0.5f))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text(
                                text = "Active Threat Definitions",
                                color = TextMuted,
                                fontSize = 11.sp
                            )
                            Text(
                                text = "${LocalSignatureDatabase.totalSignatures} Signatures Loaded",
                                color = Color.White,
                                fontWeight = FontWeight.Bold,
                                fontSize = 13.sp
                            )
                        }

                        Column(horizontalAlignment = Alignment.End) {
                            Text(
                                text = "Last Updated",
                                color = TextMuted,
                                fontSize = 11.sp
                            )
                            Text(
                                text = java.text.SimpleDateFormat("MMM dd, HH:mm", java.util.Locale.getDefault()).format(java.util.Date(lastUpdateTimestamp)),
                                color = TextSecondary,
                                fontSize = 12.sp,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                    }

                    // Status feedback badge
                    when (val st = signatureStatus) {
                        is SignatureUpdateStatus.Updated -> {
                            Surface(
                                color = NeonGreen.copy(alpha = 0.15f),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Row(
                                    modifier = Modifier.padding(8.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(Icons.Default.CheckCircle, contentDescription = null, tint = NeonGreen, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        text = "+${st.newSignaturesCount} new malware definitions installed successfully!",
                                        color = NeonGreen,
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Bold
                                    )
                                }
                            }
                        }
                        is SignatureUpdateStatus.UpToDate -> {
                            Surface(
                                color = CyberDarkSurface,
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Row(
                                    modifier = Modifier.padding(8.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(Icons.Default.CheckCircle, contentDescription = null, tint = NeonCyan, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        text = "Definitions are up to date (${st.totalSignatures} active rules)",
                                        color = NeonCyan,
                                        fontSize = 11.sp
                                    )
                                }
                            }
                        }
                        is SignatureUpdateStatus.Failed -> {
                            Surface(
                                color = CyberAmber.copy(alpha = 0.15f),
                                shape = RoundedCornerShape(8.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Row(
                                    modifier = Modifier.padding(8.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(Icons.Default.Info, contentDescription = null, tint = CyberAmber, modifier = Modifier.size(16.dp))
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        text = "Cloud mirror timeout • Protected autonomously by local definitions",
                                        color = CyberAmber,
                                        fontSize = 11.sp
                                    )
                                }
                            }
                        }
                        else -> {}
                    }

                    // Update Signatures Button
                    Button(
                        onClick = {
                            coroutineScope.launch {
                                SignatureUpdateService.updateSignaturesNow(context)
                            }
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = NeonCyan),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(42.dp),
                        enabled = !isUpdatingSignatures
                    ) {
                        if (isUpdatingSignatures) {
                            CircularProgressIndicator(modifier = Modifier.size(16.dp), color = CyberBlack, strokeWidth = 2.dp)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("DOWNLOADING DEFINITIONS...", color = CyberBlack, fontWeight = FontWeight.Black, fontSize = 12.sp)
                        } else {
                            Icon(Icons.Default.Sync, contentDescription = null, tint = CyberBlack, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("UPDATE SIGNATURES NOW", color = CyberBlack, fontWeight = FontWeight.Black, fontSize = 12.sp)
                        }
                    }

                    // Nightly Wi-Fi Auto-Update Toggle
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Nightly Auto-Update (Wi-Fi + Charging)", color = Color.White, fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
                            Text("Silently updates malware definitions overnight on unmetered Wi-Fi when plugged in (0% battery drain)", color = TextSecondary, fontSize = 11.sp)
                        }
                        Switch(
                            checked = autoUpdateEnabled,
                            onCheckedChange = {
                                autoUpdateEnabled = it
                                SignatureUpdateService.setAutoUpdateEnabled(context, it)
                            },
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = CyberBlack,
                                checkedTrackColor = NeonCyan,
                                uncheckedThumbColor = TextMuted,
                                uncheckedTrackColor = CyberDarkSurface
                            )
                        )
                    }

                    Divider(color = CyberCardBorder.copy(alpha = 0.3f))

                    // Database Sources Transparency Header
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { showSourcesDetail = !showSourcesDetail },
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Source, contentDescription = null, tint = NeonCyan, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "Verified Database Sources (${LocalSignatureDatabase.DATABASE_SOURCES.size})",
                                color = TextPrimary,
                                fontWeight = FontWeight.Bold,
                                fontSize = 12.sp
                            )
                        }
                        Icon(
                            imageVector = if (showSourcesDetail) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                            contentDescription = "Toggle sources",
                            tint = NeonCyan
                        )
                    }

                    if (showSourcesDetail) {
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            LocalSignatureDatabase.DATABASE_SOURCES.forEach { source ->
                                Surface(
                                    color = CyberDarkSurface,
                                    shape = RoundedCornerShape(8.dp),
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                        Row(
                                            modifier = Modifier.fillMaxWidth(),
                                            horizontalArrangement = Arrangement.SpaceBetween,
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Text(
                                                text = source.name,
                                                color = Color.White,
                                                fontWeight = FontWeight.Bold,
                                                fontSize = 12.sp
                                            )
                                            Surface(
                                                color = NeonCyan.copy(alpha = 0.15f),
                                                shape = RoundedCornerShape(4.dp)
                                            ) {
                                                Text(
                                                    text = source.type,
                                                    color = NeonCyan,
                                                    fontSize = 9.sp,
                                                    fontWeight = FontWeight.Bold,
                                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                                )
                                            }
                                        }
                                        Text(
                                            text = source.description,
                                            color = TextSecondary,
                                            fontSize = 10.sp,
                                            lineHeight = 14.sp
                                        )
                                        Text(
                                            text = "Upstream: ${source.url}",
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
            }

            Spacer(modifier = Modifier.height(20.dp))

            // Free No-Auth Default Notice
            Surface(
                color = NeonEmerald.copy(alpha = 0.12f),
                border = androidx.compose.foundation.BorderStroke(1.dp, NeonEmerald.copy(alpha = 0.5f)),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier.padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Default.CheckCircle,
                        contentDescription = null,
                        tint = NeonEmerald,
                        modifier = Modifier.size(24.dp)
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Column {
                        Text(
                            text = "Free No-Auth Community Engines Active",
                            color = Color.White,
                            fontWeight = FontWeight.Bold,
                            fontSize = 13.sp
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = "All API keys below are completely OPTIONAL. ThreatLens operates at full capacity using Abuse.ch MalwareBazaar, community blocklists, and built-in offline AI intelligence by default without any keys.",
                            color = TextSecondary,
                            fontSize = 11.sp,
                            lineHeight = 16.sp
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            // AI EXPLAINER ENGINE SECTION
            Text(
                text = "OPTIONAL AI ENGINES (FREE FALLBACK ALWAYS ACTIVE)",
                color = NeonCyan,
                fontWeight = FontWeight.Bold,
                fontSize = 12.sp
            )
            Spacer(modifier = Modifier.height(8.dp))

            // OpenAI ChatGPT
            ApiKeyFieldWithIcon(
                engineName = "ChatGPT",
                label = "OpenAI ChatGPT API Key",
                placeholder = "sk-proj-...",
                hint = "Supports GPT-4o-mini & GPT-4o from platform.openai.com",
                value = openaiInput,
                onValueChange = { openaiInput = it }
            )

            Spacer(modifier = Modifier.height(12.dp))

            // Anthropic Claude
            ApiKeyFieldWithIcon(
                engineName = "Claude",
                label = "Anthropic Claude API Key",
                placeholder = "sk-ant-...",
                hint = "Supports Claude 3.5 Haiku from console.anthropic.com",
                value = claudeInput,
                onValueChange = { claudeInput = it }
            )

            Spacer(modifier = Modifier.height(12.dp))

            // Google Gemini
            ApiKeyFieldWithIcon(
                engineName = "Google Gemini",
                label = "Google Gemini API Key (Free)",
                placeholder = "AIzaSy...",
                hint = "Free 15 RPM tier via aistudio.google.com",
                value = geminiInput,
                onValueChange = { geminiInput = it }
            )

            Spacer(modifier = Modifier.height(12.dp))

            // Groq Cloud
            ApiKeyFieldWithIcon(
                engineName = "Groq Cloud",
                label = "Groq Cloud API Key (Free)",
                placeholder = "gsk_...",
                hint = "Ultra-fast Llama-3 inference via console.groq.com",
                value = groqInput,
                onValueChange = { groqInput = it }
            )

            Spacer(modifier = Modifier.height(24.dp))

            // CLOUD SCANNER KEYS SECTION
            Text(
                text = "MULTI-ENGINE CLOUD SCANNERS",
                color = NeonCyan,
                fontWeight = FontWeight.Bold,
                fontSize = 12.sp
            )
            Spacer(modifier = Modifier.height(8.dp))

            ApiKeyFieldWithIcon(
                engineName = "VirusTotal",
                label = "VirusTotal API Key (v3)",
                placeholder = "64-character hex key",
                hint = "Free tier: 4 req/min & 500/day at virustotal.com",
                value = vtInput,
                onValueChange = { vtInput = it }
            )

            Spacer(modifier = Modifier.height(12.dp))

            ApiKeyFieldWithIcon(
                engineName = "MetaDefender",
                label = "MetaDefender Cloud Key (OPSWAT)",
                placeholder = "Free API key",
                hint = "Multi-scans across ~30 engines at metadefender.com",
                value = metaDefenderInput,
                onValueChange = { metaDefenderInput = it }
            )

            Spacer(modifier = Modifier.height(12.dp))

            ApiKeyFieldWithIcon(
                engineName = "Hybrid Analysis",
                label = "Hybrid Analysis API Key",
                placeholder = "Secret API key",
                hint = "Falcon Sandbox behavioral analysis at hybrid-analysis.com",
                value = haInput,
                onValueChange = { haInput = it }
            )

            Spacer(modifier = Modifier.height(12.dp))

            ApiKeyFieldWithIcon(
                engineName = "Kaspersky OpenTIP",
                label = "Kaspersky OpenTIP API Key",
                placeholder = "Private token",
                hint = "Enterprise hash intelligence at opentip.kaspersky.com",
                value = kasperskyInput,
                onValueChange = { kasperskyInput = it }
            )

            Spacer(modifier = Modifier.height(12.dp))

            ApiKeyFieldWithIcon(
                engineName = "Filescan.io",
                label = "Filescan.io API Key",
                placeholder = "Bearer token",
                hint = "Free IOCs & report lookup at filescan.io",
                value = filescanInput,
                onValueChange = { filescanInput = it }
            )

            Spacer(modifier = Modifier.height(26.dp))

            // Save Button
            Button(
                onClick = {
                    viewModel.saveApiKeys(
                        openaiInput, claudeInput, geminiInput, groqInput,
                        vtInput, haInput, kasperskyInput, metaDefenderInput, filescanInput
                    )
                    savedSnackbar = true
                },
                colors = ButtonDefaults.buttonColors(containerColor = NeonCyan),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(50.dp)
            ) {
                Icon(Icons.Default.Save, contentDescription = "Save", tint = CyberBlack)
                Spacer(modifier = Modifier.width(8.dp))
                Text("Save Configuration", color = CyberBlack, fontWeight = FontWeight.Bold)
            }

            if (savedSnackbar) {
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = "✓ Configuration saved & applied to Real-time Shield",
                    color = NeonEmerald,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.SemiBold
                )
            }

            Spacer(modifier = Modifier.height(30.dp))
        }
    }
}

@Composable
fun ApiKeyFieldWithIcon(
    engineName: String,
    label: String,
    placeholder: String,
    hint: String,
    value: String,
    onValueChange: (String) -> Unit
) {
    Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            EngineLogoIcon(engineName = engineName, modifier = Modifier.size(18.dp))
            Spacer(modifier = Modifier.width(8.dp))
            Text(text = label, color = TextPrimary, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
        }
        Spacer(modifier = Modifier.height(4.dp))
        OutlinedTextField(
            value = value,
            onValueChange = onValueChange,
            placeholder = { Text(placeholder, color = TextMuted, fontSize = 13.sp) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(10.dp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = NeonCyan,
                unfocusedBorderColor = CyberCardBorder,
                focusedContainerColor = CyberCardSurface,
                unfocusedContainerColor = CyberCardSurface,
                focusedTextColor = TextPrimary,
                unfocusedTextColor = TextPrimary
            )
        )
        Spacer(modifier = Modifier.height(2.dp))
        Text(text = hint, color = TextSecondary, fontSize = 11.sp)
    }
}
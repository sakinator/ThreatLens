package io.threatlens.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
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
    var bazaarInput by remember { mutableStateOf(viewModel.bazaarKey.value) }
    var savedSnackbar by remember { mutableStateOf(false) }
    val isRealtimeShieldEnabled by viewModel.isRealtimeShieldEnabled.collectAsState()
    var showImportDialog by remember { mutableStateOf(false) }
    var importJsonText by remember { mutableStateOf("") }
    val versionName = remember { io.threatlens.core.update.UpdateCheckService.getInstalledVersionName(context) }
    val validationStatusMap = remember { mutableStateMapOf<String, io.threatlens.core.validation.ValidationStatus>() }
    var isValidatingAll by remember { mutableStateOf(false) }

    fun validateAndSaveSingle(provider: String, key: String) {
        viewModel.saveSingleApiKey(provider, key)
        savedSnackbar = true
        coroutineScope.launch {
            validationStatusMap[provider] = io.threatlens.core.validation.ValidationStatus.Validating
            val res = io.threatlens.core.validation.ApiKeyValidator.validate(provider, key)
            validationStatusMap[provider] = res
        }
    }

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
                            Text("Version $versionName • Check for updates & links", color = TextSecondary, fontSize = 11.sp)
                        }
                    }
                    Icon(Icons.Default.ChevronRight, contentDescription = null, tint = TextMuted)
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Real-Time Background Antivirus Protection Engine Toggle
            GlassCard {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(
                            imageVector = if (isRealtimeShieldEnabled) Icons.Default.Shield else Icons.Default.SecurityUpdateWarning,
                            contentDescription = null,
                            tint = if (isRealtimeShieldEnabled) NeonCyan else TextMuted,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(12.dp))
                        Column {
                            Text(
                                text = "Real-Time Antivirus Engine",
                                color = TextPrimary,
                                fontWeight = FontWeight.Bold,
                                fontSize = 14.sp
                            )
                            Text(
                                text = if (isRealtimeShieldEnabled) 
                                    "Active: Monitors downloads & installs as they happen" 
                                else 
                                    "Turned off: Manual on-demand scan mode only",
                                color = if (isRealtimeShieldEnabled) NeonCyan else TextMuted,
                                fontSize = 11.sp
                            )
                        }
                    }
                    Switch(
                        checked = isRealtimeShieldEnabled,
                        onCheckedChange = { viewModel.setRealtimeShieldEnabled(it) },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = CyberBlack,
                            checkedTrackColor = NeonCyan,
                            uncheckedThumbColor = TextMuted,
                            uncheckedTrackColor = CyberDarkSurface
                        )
                    )
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
                providerId = "openai",
                label = "OpenAI ChatGPT API Key",
                placeholder = "sk-proj-...",
                hint = "Supports GPT-4o-mini & GPT-4o from platform.openai.com",
                portalUrl = "https://platform.openai.com/api-keys",
                value = openaiInput,
                onValueChange = { openaiInput = it },
                status = validationStatusMap["openai"] ?: io.threatlens.core.validation.ValidationStatus.Idle,
                onSaveAndValidate = { validateAndSaveSingle("openai", openaiInput) }
            )

            Spacer(modifier = Modifier.height(12.dp))

            // Anthropic Claude
            ApiKeyFieldWithIcon(
                engineName = "Claude",
                providerId = "claude",
                label = "Anthropic Claude API Key",
                placeholder = "sk-ant-...",
                hint = "Supports Claude 3.5 Haiku from console.anthropic.com",
                portalUrl = "https://console.anthropic.com/settings/keys",
                value = claudeInput,
                onValueChange = { claudeInput = it },
                status = validationStatusMap["claude"] ?: io.threatlens.core.validation.ValidationStatus.Idle,
                onSaveAndValidate = { validateAndSaveSingle("claude", claudeInput) }
            )

            Spacer(modifier = Modifier.height(12.dp))

            // Google Gemini
            ApiKeyFieldWithIcon(
                engineName = "Google Gemini",
                providerId = "gemini",
                label = "Google Gemini API Key (Free)",
                placeholder = "AIzaSy...",
                hint = "Free 15 RPM tier via aistudio.google.com",
                portalUrl = "https://aistudio.google.com/app/apikey",
                value = geminiInput,
                onValueChange = { geminiInput = it },
                status = validationStatusMap["gemini"] ?: io.threatlens.core.validation.ValidationStatus.Idle,
                onSaveAndValidate = { validateAndSaveSingle("gemini", geminiInput) }
            )

            Spacer(modifier = Modifier.height(12.dp))

            // Groq Cloud
            ApiKeyFieldWithIcon(
                engineName = "Groq Cloud",
                providerId = "groq",
                label = "Groq Cloud API Key (Free)",
                placeholder = "gsk_...",
                hint = "Ultra-fast Llama-3 inference via console.groq.com",
                portalUrl = "https://console.groq.com/keys",
                value = groqInput,
                onValueChange = { groqInput = it },
                status = validationStatusMap["groq"] ?: io.threatlens.core.validation.ValidationStatus.Idle,
                onSaveAndValidate = { validateAndSaveSingle("groq", groqInput) }
            )

            Spacer(modifier = Modifier.height(24.dp))

            // CLOUD SCANNER KEYS SECTION
            Text(
                text = "MULTI-ENGINE CLOUD SCANNERS",
                color = NeonCyan,
                fontWeight = FontWeight.Bold,
                fontSize = 12.sp
            )
            Spacer(modifier = Modifier.height(6.dp))

            Surface(
                color = CyberDarkSurface,
                shape = RoundedCornerShape(10.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, NeonEmerald.copy(alpha = 0.4f)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier.padding(10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Default.CloudQueue, contentDescription = null, tint = NeonEmerald, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "AlienVault OTX & CIRCL Hashlookup are active by default (Zero Key Required). The engines below are optional for expanded multi-engine coverage.",
                        color = TextSecondary,
                        fontSize = 11.sp
                    )
                }
            }
            Spacer(modifier = Modifier.height(10.dp))

            ApiKeyFieldWithIcon(
                engineName = "VirusTotal",
                providerId = "vt",
                label = "VirusTotal API Key (v3)",
                placeholder = "64-character hex key",
                hint = "Free tier: 4 req/min & 500/day at virustotal.com",
                portalUrl = "https://www.virustotal.com/gui/my-apikey",
                value = vtInput,
                onValueChange = { vtInput = it },
                status = validationStatusMap["vt"] ?: io.threatlens.core.validation.ValidationStatus.Idle,
                onSaveAndValidate = { validateAndSaveSingle("vt", vtInput) }
            )

            Spacer(modifier = Modifier.height(12.dp))

            ApiKeyFieldWithIcon(
                engineName = "MetaDefender",
                providerId = "metadefender",
                label = "MetaDefender Cloud Key (OPSWAT)",
                placeholder = "Free API key",
                hint = "Multi-scans across ~30 engines at metadefender.com",
                portalUrl = "https://metadefender.opswat.com/account",
                value = metaDefenderInput,
                onValueChange = { metaDefenderInput = it },
                status = validationStatusMap["metadefender"] ?: io.threatlens.core.validation.ValidationStatus.Idle,
                onSaveAndValidate = { validateAndSaveSingle("metadefender", metaDefenderInput) }
            )

            Spacer(modifier = Modifier.height(12.dp))

            ApiKeyFieldWithIcon(
                engineName = "Hybrid Analysis",
                providerId = "ha",
                label = "Hybrid Analysis API Key",
                placeholder = "Secret API key",
                hint = "Falcon Sandbox behavioral analysis at hybrid-analysis.com",
                portalUrl = "https://www.hybrid-analysis.com/apikeys",
                value = haInput,
                onValueChange = { haInput = it },
                status = validationStatusMap["ha"] ?: io.threatlens.core.validation.ValidationStatus.Idle,
                onSaveAndValidate = { validateAndSaveSingle("ha", haInput) }
            )

            Spacer(modifier = Modifier.height(12.dp))

            ApiKeyFieldWithIcon(
                engineName = "Kaspersky OpenTIP",
                providerId = "kaspersky",
                label = "Kaspersky OpenTIP API Key",
                placeholder = "Private token",
                hint = "Enterprise hash intelligence at opentip.kaspersky.com",
                portalUrl = "https://opentip.kaspersky.com/token",
                value = kasperskyInput,
                onValueChange = { kasperskyInput = it },
                status = validationStatusMap["kaspersky"] ?: io.threatlens.core.validation.ValidationStatus.Idle,
                onSaveAndValidate = { validateAndSaveSingle("kaspersky", kasperskyInput) }
            )

            Spacer(modifier = Modifier.height(12.dp))

            ApiKeyFieldWithIcon(
                engineName = "Filescan.io",
                providerId = "filescan",
                label = "Filescan.io API Key",
                placeholder = "Bearer token",
                hint = "Free IOCs & report lookup at filescan.io",
                portalUrl = "https://www.filescan.io/profile",
                value = filescanInput,
                onValueChange = { filescanInput = it },
                status = validationStatusMap["filescan"] ?: io.threatlens.core.validation.ValidationStatus.Idle,
                onSaveAndValidate = { validateAndSaveSingle("filescan", filescanInput) }
            )

            Spacer(modifier = Modifier.height(12.dp))

            ApiKeyFieldWithIcon(
                engineName = "MalwareBazaar",
                providerId = "bazaar",
                label = "MalwareBazaar Auth-Key (Abuse.ch)",
                placeholder = "Free Auth-Key token",
                hint = "Mandatory for Abuse.ch API queries; free registration at bazaar.abuse.ch",
                portalUrl = "https://bazaar.abuse.ch/account/",
                value = bazaarInput,
                onValueChange = { bazaarInput = it },
                status = validationStatusMap["bazaar"] ?: io.threatlens.core.validation.ValidationStatus.Idle,
                onSaveAndValidate = { validateAndSaveSingle("bazaar", bazaarInput) }
            )

            Spacer(modifier = Modifier.height(26.dp))

            // Primary Bulk Action: Save & Validate All Keys
            Button(
                onClick = {
                    viewModel.saveApiKeys(
                        openaiInput, claudeInput, geminiInput, groqInput,
                        vtInput, haInput, kasperskyInput, metaDefenderInput, filescanInput, bazaarInput
                    )
                    savedSnackbar = true
                    isValidatingAll = true
                    coroutineScope.launch {
                        val keyMap = mapOf(
                            "openai" to openaiInput,
                            "claude" to claudeInput,
                            "gemini" to geminiInput,
                            "groq" to groqInput,
                            "vt" to vtInput,
                            "metadefender" to metaDefenderInput,
                            "ha" to haInput,
                            "kaspersky" to kasperskyInput,
                            "filescan" to filescanInput,
                            "bazaar" to bazaarInput
                        )
                        keyMap.forEach { (prov, k) ->
                            if (k.isNotBlank()) {
                                validationStatusMap[prov] = io.threatlens.core.validation.ValidationStatus.Validating
                            }
                        }
                        val jobs = keyMap.map { (prov, k) ->
                            launch {
                                if (k.isNotBlank()) {
                                    val res = io.threatlens.core.validation.ApiKeyValidator.validate(prov, k)
                                    validationStatusMap[prov] = res
                                }
                            }
                        }
                        jobs.forEach { it.join() }
                        isValidatingAll = false
                    }
                },
                colors = ButtonDefaults.buttonColors(containerColor = NeonCyan),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(50.dp),
                enabled = !isValidatingAll
            ) {
                if (isValidatingAll) {
                    CircularProgressIndicator(modifier = Modifier.size(18.dp), color = CyberBlack, strokeWidth = 2.dp)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("VALIDATING ALL KEYS...", color = CyberBlack, fontWeight = FontWeight.Black)
                } else {
                    Icon(Icons.Default.CloudDone, contentDescription = "Validate All", tint = CyberBlack)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("SAVE & VALIDATE ALL KEYS", color = CyberBlack, fontWeight = FontWeight.Black)
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Secondary Quick Save Button (Save All Without Validating)
            OutlinedButton(
                onClick = {
                    viewModel.saveApiKeys(
                        openaiInput, claudeInput, geminiInput, groqInput,
                        vtInput, haInput, kasperskyInput, metaDefenderInput, filescanInput, bazaarInput
                    )
                    savedSnackbar = true
                },
                colors = ButtonDefaults.outlinedButtonColors(contentColor = NeonCyan),
                border = androidx.compose.foundation.BorderStroke(1.dp, NeonCyan.copy(alpha = 0.6f)),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(46.dp)
            ) {
                Icon(Icons.Default.Save, contentDescription = "Save", tint = NeonCyan, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text("SAVE ALL (INSTANT)", color = NeonCyan, fontWeight = FontWeight.Bold, fontSize = 12.sp)
            }

            if (savedSnackbar) {
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = "✓ Configuration saved & active in Real-time Shield",
                    color = NeonEmerald,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.SemiBold
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            // API Key Vault Backup & Portability Card (Export & Import)
            GlassCard {
                Column(modifier = Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.VpnKey,
                            contentDescription = null,
                            tint = NeonCyan,
                            modifier = Modifier.size(22.dp)
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Column {
                            Text(
                                text = "Key Vault Backup & Migration",
                                color = Color.White,
                                fontWeight = FontWeight.Bold,
                                fontSize = 14.sp
                            )
                            Text(
                                text = "Keys survive app updates automatically. Export to migrate or backup.",
                                color = TextSecondary,
                                fontSize = 11.sp
                            )
                        }
                    }

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        // Export Button
                        OutlinedButton(
                            onClick = {
                                val json = viewModel.exportApiKeys()
                                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                val clip = ClipData.newPlainText("ThreatLens_Keys_Backup", json)
                                clipboard.setPrimaryClip(clip)
                                Toast.makeText(context, "Exported keys copied to clipboard!", Toast.LENGTH_LONG).show()
                            },
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = NeonCyan),
                            border = androidx.compose.foundation.BorderStroke(1.dp, NeonCyan.copy(alpha = 0.5f)),
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Export Keys", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                        }

                        // Import Button
                        OutlinedButton(
                            onClick = {
                                try {
                                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                    val clipText = clipboard.primaryClip?.getItemAt(0)?.text?.toString() ?: ""
                                    if (clipText.contains("{") && clipText.contains("}")) {
                                        importJsonText = clipText
                                    }
                                } catch (_: Exception) {}
                                showImportDialog = true
                            },
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = NeonEmerald),
                            border = androidx.compose.foundation.BorderStroke(1.dp, NeonEmerald.copy(alpha = 0.5f)),
                            shape = RoundedCornerShape(10.dp),
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(Icons.Default.Download, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Import Keys", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                        }
                    }
                }
            }

            // Import Keys Dialog
            if (showImportDialog) {
                AlertDialog(
                    onDismissRequest = { showImportDialog = false },
                    containerColor = CyberDarkSurface,
                    title = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Key, contentDescription = null, tint = NeonCyan, modifier = Modifier.size(20.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Import API Keys Vault", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                        }
                    },
                    text = {
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text(
                                text = "Paste your exported JSON keys payload below:",
                                color = TextSecondary,
                                fontSize = 12.sp
                            )
                            OutlinedTextField(
                                value = importJsonText,
                                onValueChange = { importJsonText = it },
                                placeholder = { Text("{\n  \"keys\": {\n    \"openai\": \"...\"\n  }\n}", color = TextMuted, fontSize = 11.sp) },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(180.dp),
                                textStyle = androidx.compose.ui.text.TextStyle(
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 11.sp,
                                    color = TextPrimary
                                ),
                                colors = OutlinedTextFieldDefaults.colors(
                                    focusedBorderColor = NeonCyan,
                                    unfocusedBorderColor = CyberCardBorder,
                                    focusedContainerColor = CyberBlack,
                                    unfocusedContainerColor = CyberBlack
                                )
                            )
                        }
                    },
                    confirmButton = {
                        Button(
                            onClick = {
                                val (count, message) = viewModel.importApiKeys(importJsonText)
                                if (count > 0) {
                                    // Update screen text fields
                                    openaiInput = viewModel.openAiKey.value
                                    claudeInput = viewModel.claudeKey.value
                                    geminiInput = viewModel.geminiKey.value
                                    groqInput = viewModel.groqKey.value
                                    vtInput = viewModel.vtKey.value
                                    haInput = viewModel.haKey.value
                                    kasperskyInput = viewModel.kasperskyKey.value
                                    metaDefenderInput = viewModel.metaDefenderKey.value
                                    filescanInput = viewModel.filescanKey.value
                                    bazaarInput = viewModel.bazaarKey.value
                                    showImportDialog = false
                                }
                                Toast.makeText(context, message, Toast.LENGTH_LONG).show()
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = NeonCyan)
                        ) {
                            Text("Import & Save", color = CyberBlack, fontWeight = FontWeight.Bold)
                        }
                    },
                    dismissButton = {
                        TextButton(onClick = { showImportDialog = false }) {
                            Text("Cancel", color = TextMuted)
                        }
                    }
                )
            }

            Spacer(modifier = Modifier.height(30.dp))
        }
    }
}

@Composable
fun ApiKeyFieldWithIcon(
    engineName: String,
    providerId: String,
    label: String,
    placeholder: String,
    hint: String,
    portalUrl: String,
    value: String,
    onValueChange: (String) -> Unit,
    status: io.threatlens.core.validation.ValidationStatus,
    onSaveAndValidate: () -> Unit
) {
    val uriHandler = androidx.compose.ui.platform.LocalUriHandler.current

    Column(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.weight(1f)) {
                EngineLogoIcon(engineName = engineName, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(text = label, color = TextPrimary, fontSize = 13.sp, fontWeight = FontWeight.SemiBold, maxLines = 1)
            }
            // Hyperlink to get API key
            Text(
                text = "Get key here ↗",
                color = NeonCyan,
                fontSize = 12.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier
                    .clickable { uriHandler.openUri(portalUrl) }
                    .padding(start = 6.dp)
            )
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
        Spacer(modifier = Modifier.height(4.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = hint,
                color = TextSecondary,
                fontSize = 11.sp,
                modifier = Modifier.weight(1f)
            )
            Spacer(modifier = Modifier.width(8.dp))
            OutlinedButton(
                onClick = onSaveAndValidate,
                colors = ButtonDefaults.outlinedButtonColors(contentColor = NeonCyan),
                border = androidx.compose.foundation.BorderStroke(1.dp, NeonCyan.copy(alpha = 0.5f)),
                shape = RoundedCornerShape(8.dp),
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp),
                modifier = Modifier.height(30.dp),
                enabled = status !is io.threatlens.core.validation.ValidationStatus.Validating
            ) {
                if (status is io.threatlens.core.validation.ValidationStatus.Validating) {
                    CircularProgressIndicator(modifier = Modifier.size(12.dp), color = NeonCyan, strokeWidth = 1.5.dp)
                } else {
                    Text("Validate & Save", fontSize = 10.sp, fontWeight = FontWeight.Bold)
                }
            }
        }

        // Status Feedback line
        when (status) {
            is io.threatlens.core.validation.ValidationStatus.Validating -> {
                Spacer(modifier = Modifier.height(3.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(modifier = Modifier.size(10.dp), color = NeonCyan, strokeWidth = 1.5.dp)
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Validating with server...", color = NeonCyan, fontSize = 11.sp)
                }
            }
            is io.threatlens.core.validation.ValidationStatus.Valid -> {
                Spacer(modifier = Modifier.height(3.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.CheckCircle, contentDescription = null, tint = NeonEmerald, modifier = Modifier.size(13.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(status.message, color = NeonEmerald, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                }
            }
            is io.threatlens.core.validation.ValidationStatus.Invalid -> {
                Spacer(modifier = Modifier.height(3.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Error, contentDescription = null, tint = NeonCrimson, modifier = Modifier.size(13.dp))
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(status.error, color = NeonCrimson, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                }
            }
            else -> {}
        }
    }
}
package io.threatlens.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.BatteryChargingFull
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Save
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.threatlens.ui.components.EngineLogoIcon
import io.threatlens.ui.components.GlassCard
import io.threatlens.ui.theme.*
import io.threatlens.ui.viewmodel.MainViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    viewModel: MainViewModel,
    onBack: () -> Unit,
    onNavigateAbout: () -> Unit = {},
    onNavigateWebProtection: () -> Unit = {}
) {
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

    Scaffold(
        containerColor = CyberBlack,
        topBar = {
            TopAppBar(
                title = { Text("ThreatLens Settings", color = TextPrimary, fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = TextPrimary)
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
            Spacer(modifier = Modifier.height(16.dp))

            // Navigation to Web Protection & DNS Settings
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

            Spacer(modifier = Modifier.height(20.dp))

            // AI EXPLAINER ENGINE SECTION
            Text(
                text = "AI THREAT EXPLAINERS (CHOOSE ANY OR ALL)",
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

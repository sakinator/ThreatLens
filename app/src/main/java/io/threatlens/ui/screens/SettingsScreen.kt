package io.threatlens.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.BatteryChargingFull
import androidx.compose.material.icons.filled.Save
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.threatlens.ui.components.GlassCard
import io.threatlens.ui.theme.*
import io.threatlens.ui.viewmodel.MainViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    viewModel: MainViewModel,
    onBack: () -> Unit
) {
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

            Spacer(modifier = Modifier.height(18.dp))

            // AI Keys Section
            Text(
                text = "FREE AI THREAT EXPLAINER",
                color = NeonCyan,
                fontWeight = FontWeight.Bold,
                fontSize = 12.sp
            )
            Spacer(modifier = Modifier.height(8.dp))

            ApiKeyField(
                label = "Google Gemini API Key (Recommended)",
                placeholder = "AIzaSy...",
                hint = "Get a free 15 RPM key at aistudio.google.com",
                value = geminiInput,
                onValueChange = { geminiInput = it }
            )

            Spacer(modifier = Modifier.height(12.dp))

            ApiKeyField(
                label = "Groq Cloud API Key",
                placeholder = "gsk_...",
                hint = "Free ultra-fast Llama-3 inference at console.groq.com",
                value = groqInput,
                onValueChange = { groqInput = it }
            )

            Spacer(modifier = Modifier.height(20.dp))

            // Cloud Scanner Keys Section
            Text(
                text = "MULTI-ENGINE CLOUD SCANNERS",
                color = NeonCyan,
                fontWeight = FontWeight.Bold,
                fontSize = 12.sp
            )
            Spacer(modifier = Modifier.height(8.dp))

            ApiKeyField(
                label = "VirusTotal API Key (v3)",
                placeholder = "64-character hex key",
                hint = "Free tier: 4 req/min & 500/day at virustotal.com",
                value = vtInput,
                onValueChange = { vtInput = it }
            )

            Spacer(modifier = Modifier.height(12.dp))

            ApiKeyField(
                label = "MetaDefender Cloud Key (OPSWAT)",
                placeholder = "Free API key",
                hint = "Checks ~30 engines at metadefender.com",
                value = metaDefenderInput,
                onValueChange = { metaDefenderInput = it }
            )

            Spacer(modifier = Modifier.height(12.dp))

            ApiKeyField(
                label = "Hybrid Analysis API Key",
                placeholder = "Secret API key",
                hint = "Free sandbox behavioral analysis at hybrid-analysis.com",
                value = haInput,
                onValueChange = { haInput = it }
            )

            Spacer(modifier = Modifier.height(12.dp))

            ApiKeyField(
                label = "Kaspersky OpenTIP API Key",
                placeholder = "Private token",
                hint = "Free enterprise hash reputation at opentip.kaspersky.com",
                value = kasperskyInput,
                onValueChange = { kasperskyInput = it }
            )

            Spacer(modifier = Modifier.height(12.dp))

            ApiKeyField(
                label = "Filescan.io API Key",
                placeholder = "Bearer token",
                hint = "Free IOCs & report lookup at filescan.io",
                value = filescanInput,
                onValueChange = { filescanInput = it }
            )

            Spacer(modifier = Modifier.height(24.dp))

            // Save Button
            Button(
                onClick = {
                    viewModel.saveApiKeys(
                        geminiInput, groqInput, vtInput, haInput,
                        kasperskyInput, metaDefenderInput, filescanInput
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

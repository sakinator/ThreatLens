package io.threatlens.ui.screens

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.Image
import androidx.compose.foundation.border
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
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.threatlens.R
import io.threatlens.core.update.UpdateCheckService
import io.threatlens.core.update.UpdateInfo
import io.threatlens.ui.components.EngineLogoIcon
import io.threatlens.ui.components.GlassCard
import io.threatlens.ui.theme.*
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun AboutScreen(
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    var isCheckingUpdates by remember { mutableStateOf(false) }
    var updateResult by remember { mutableStateOf<UpdateInfo?>(null) }

    Scaffold(
        containerColor = CyberBlack,
        topBar = {
            TopAppBar(
                title = { Text("About ThreatLens", color = TextPrimary, fontWeight = FontWeight.Bold) },
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
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(16.dp))

            // Logo & Title
            Icon(
                painter = painterResource(id = R.drawable.ic_threatlens_logo),
                contentDescription = "ThreatLens Logo",
                tint = NeonCyan,
                modifier = Modifier.size(64.dp)
            )
            Spacer(modifier = Modifier.height(10.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("THREAT", color = TextPrimary, fontWeight = FontWeight.Black, fontSize = 22.sp, letterSpacing = 1.sp)
                Text("LENS", color = NeonCyan, fontWeight = FontWeight.Black, fontSize = 22.sp, letterSpacing = 1.sp)
            }
            Spacer(modifier = Modifier.height(4.dp))
            Surface(
                color = NeonCyan.copy(alpha = 0.15f),
                shape = RoundedCornerShape(8.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, NeonCyan.copy(alpha = 0.4f))
            ) {
                Text(
                    text = "v1.0.0 • Open-Source Edition",
                    color = NeonCyan,
                    fontSize = 11.sp,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                )
            }

            Spacer(modifier = Modifier.height(20.dp))

            // Check for Updates Card
            GlassCard {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text("Software Updates", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                        Text("Current Version: v${UpdateCheckService.CURRENT_VERSION}", color = TextSecondary, fontSize = 11.sp)
                    }

                    Button(
                        onClick = {
                            coroutineScope.launch {
                                isCheckingUpdates = true
                                updateResult = UpdateCheckService.checkForUpdates()
                                isCheckingUpdates = false
                            }
                        },
                        enabled = !isCheckingUpdates,
                        colors = ButtonDefaults.buttonColors(containerColor = NeonCyan),
                        shape = RoundedCornerShape(10.dp)
                    ) {
                        if (isCheckingUpdates) {
                            CircularProgressIndicator(modifier = Modifier.size(16.dp), color = CyberBlack, strokeWidth = 2.dp)
                        } else {
                            Icon(Icons.Default.SystemUpdate, contentDescription = null, tint = CyberBlack, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Check Now", color = CyberBlack, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                        }
                    }
                }

                // Update result message
                updateResult?.let { result ->
                    Spacer(modifier = Modifier.height(12.dp))
                    if (result.hasUpdate) {
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .border(1.dp, NeonEmerald, RoundedCornerShape(10.dp)),
                            colors = CardDefaults.cardColors(containerColor = CyberDarkSurface)
                        ) {
                            Column(modifier = Modifier.padding(12.dp)) {
                                Text("🎉 New Version Available: v${result.latestVersion}", color = NeonEmerald, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                                if (!result.changelog.isNullOrBlank()) {
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(result.changelog, color = TextSecondary, fontSize = 11.sp, maxLines = 3)
                                }
                                Spacer(modifier = Modifier.height(8.dp))
                                Button(
                                    onClick = {
                                        val url = result.downloadApkUrl ?: result.releaseUrl
                                        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                                    },
                                    colors = ButtonDefaults.buttonColors(containerColor = NeonEmerald),
                                    shape = RoundedCornerShape(8.dp),
                                    modifier = Modifier.fillMaxWidth().height(38.dp)
                                ) {
                                    Text("Download Latest APK ↗", color = CyberBlack, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                                }
                            }
                        }
                    } else {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.CheckCircle, contentDescription = null, tint = NeonEmerald, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("ThreatLens is up to date!", color = NeonEmerald, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Project Description
            GlassCard {
                Text("About Project", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "ThreatLens is an open-source hybrid Android antivirus designed for zero-idle battery consumption (<0.5% per 24 hours). It delivers instant download interception (Kaspersky/Sophos style), multi-cloud reputation aggregation, and free AI explanations to demystify complex malware.",
                    color = TextSecondary,
                    fontSize = 12.sp,
                    lineHeight = 17.sp
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Credits Section
            GlassCard {
                Text("Credits & Collaborators", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                Spacer(modifier = Modifier.height(10.dp))

                CreditRow(title = "Lead Creator", name = "sakinator", url = "https://github.com/sakinator", context = context)
                CreditRow(title = "Threat Intelligence", name = "VirusTotal, Abuse.ch, Kaspersky OpenTIP, OPSWAT MetaDefender, Hybrid Analysis, Filescan.io", url = null, context = context)
                CreditRow(title = "AI Intelligence", name = "Google Gemini, Anthropic Claude, OpenAI ChatGPT, Groq Cloud", url = null, context = context)
                CreditRow(title = "UI Architecture", name = "Inspired by Bitdefender Mobile Security & Sophos Intercept X", url = null, context = context)
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Official Links Card
            GlassCard {
                Text("Official Links & Resources", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                Spacer(modifier = Modifier.height(10.dp))

                LinkRow(title = "GitHub Repository", url = "https://github.com/sakinator/ThreatLens", context = context)
                LinkRow(title = "Releases & APK Downloads", url = "https://github.com/sakinator/ThreatLens/releases", context = context)
                LinkRow(title = "Issue Tracker & Bug Reports", url = "https://github.com/sakinator/ThreatLens/issues", context = context)
                LinkRow(title = "License: MIT Open Source", url = "https://opensource.org/licenses/MIT", context = context)
            }

            Spacer(modifier = Modifier.height(30.dp))
        }
    }
}

@Composable
fun CreditRow(
    title: String,
    name: String,
    url: String?,
    context: android.content.Context
) {
    Column(modifier = Modifier.padding(vertical = 4.dp)) {
        Text(text = title, color = NeonCyan, fontSize = 11.sp, fontWeight = FontWeight.Bold)
        Spacer(modifier = Modifier.height(2.dp))
        if (url != null) {
            Text(
                text = "$name ↗",
                color = TextPrimary,
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.clickable {
                    try {
                        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                    } catch (_: Exception) {}
                }
            )
        } else {
            Text(text = name, color = TextSecondary, fontSize = 12.sp)
        }
    }
}

@Composable
fun LinkRow(
    title: String,
    url: String,
    context: android.content.Context
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable {
                try {
                    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                } catch (_: Exception) {}
            }
            .padding(vertical = 6.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(text = title, color = TextPrimary, fontSize = 13.sp, fontWeight = FontWeight.Medium)
        Icon(Icons.Default.OpenInNew, contentDescription = null, tint = NeonCyan, modifier = Modifier.size(16.dp))
    }
}

package io.threatlens.ui.screens

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
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
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.threatlens.core.model.ThreatSeverity
import io.threatlens.core.security.MitmDetector
import io.threatlens.core.security.MitmStatus
import io.threatlens.core.vpn.*
import io.threatlens.ui.components.GlassCard
import io.threatlens.ui.theme.*
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WebProtectionScreen(
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()

    val isVpnActive by ThreatLensVpnService.isVpnActive.collectAsState()
    val activeDns by ThreatLensVpnService.activeDnsProvider.collectAsState()
    val filterMode by DomainFilterEngine.filterMode.collectAsState()
    val filterIntensity by DomainFilterEngine.filterIntensity.collectAsState()
    val blockedEvents by DomainFilterEngine.blockedEvents.collectAsState()
    val adsBlocked by DomainFilterEngine.totalAdsBlocked.collectAsState()
    val malwareBlocked by DomainFilterEngine.totalMalwareBlocked.collectAsState()
    val mitmReport by MitmDetector.lastReport.collectAsState()

    var isScanningMitm by remember { mutableStateOf(false) }

    val vpnPrepareLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            val intent = Intent(context, ThreatLensVpnService::class.java).apply {
                action = ThreatLensVpnService.ACTION_START
            }
            context.startService(intent)
        }
    }

    Scaffold(
        containerColor = CyberBlack,
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "WEB & LINK SHIELD",
                        color = TextPrimary,
                        fontSize = 17.sp,
                        fontWeight = FontWeight.Black,
                        letterSpacing = 1.sp
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            imageVector = Icons.Default.ArrowBack,
                            contentDescription = "Back",
                            tint = NeonCyan
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

                // Master Shield Status Card
                GlassCard(
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(
                            1.dp,
                            if (isVpnActive) NeonCyan else CyberCardBorder,
                            RoundedCornerShape(16.dp)
                        )
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(48.dp)
                                .background(
                                    if (isVpnActive) NeonCyan.copy(alpha = 0.2f) else CyberDarkSurface,
                                    CircleShape
                                ),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = if (isVpnActive) Icons.Default.VpnLock else Icons.Default.VpnKeyOff,
                                contentDescription = null,
                                tint = if (isVpnActive) NeonCyan else TextMuted,
                                modifier = Modifier.size(26.dp)
                            )
                        }

                        Spacer(modifier = Modifier.width(14.dp))

                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = if (isVpnActive) "Link Shield Active" else "Link Shield Paused",
                                color = if (isVpnActive) Color.White else TextMuted,
                                fontWeight = FontWeight.Bold,
                                fontSize = 16.sp
                            )
                            Text(
                                text = if (isVpnActive) "On-Device Loopback (0.0% Battery)" else "Tap switch to enable DNS filtering",
                                color = TextSecondary,
                                fontSize = 12.sp
                            )
                        }

                        Switch(
                            checked = isVpnActive,
                            onCheckedChange = { enable ->
                                if (enable) {
                                    val prepIntent = VpnService.prepare(context)
                                    if (prepIntent != null) {
                                        vpnPrepareLauncher.launch(prepIntent)
                                    } else {
                                        val intent = Intent(context, ThreatLensVpnService::class.java).apply {
                                            action = ThreatLensVpnService.ACTION_START
                                        }
                                        context.startService(intent)
                                    }
                                } else {
                                    val intent = Intent(context, ThreatLensVpnService::class.java).apply {
                                        action = ThreatLensVpnService.ACTION_STOP
                                    }
                                    context.startService(intent)
                                }
                            },
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = CyberBlack,
                                checkedTrackColor = NeonCyan,
                                uncheckedThumbColor = TextMuted,
                                uncheckedTrackColor = CyberDarkSurface
                            )
                        )
                    }

                    if (isVpnActive) {
                        Spacer(modifier = Modifier.height(14.dp))
                        Divider(color = CyberCardBorder.copy(alpha = 0.4f))
                        Spacer(modifier = Modifier.height(12.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceAround
                        ) {
                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                Text(
                                    text = "$malwareBlocked",
                                    color = NeonRed,
                                    fontSize = 20.sp,
                                    fontWeight = FontWeight.Black
                                )
                                Text(
                                    text = "Threats Stopped",
                                    color = TextSecondary,
                                    fontSize = 11.sp
                                )
                            }

                            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                Text(
                                    text = "$adsBlocked",
                                    color = NeonCyan,
                                    fontSize = 20.sp,
                                    fontWeight = FontWeight.Black
                                )
                                Text(
                                    text = "Ads & Trackers Blocked",
                                    color = TextSecondary,
                                    fontSize = 11.sp
                                )
                            }
                        }
                    }
                }
            }

            // Security Level / Filter Intensity (Essential Shield, Balanced Sentinel, Zero-Trust Fortress)
            item {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = "PROTECTION INTENSITY",
                        color = NeonCyan,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.sp
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        FilterIntensity.values().forEach { intensity ->
                            val isSelected = filterIntensity == intensity
                            val color = Color(intensity.badgeColorHex)

                            Surface(
                                modifier = Modifier
                                    .weight(1f)
                                    .clickable { DomainFilterEngine.setFilterIntensity(intensity) }
                                    .border(
                                        width = if (isSelected) 1.5.dp else 1.dp,
                                        color = if (isSelected) color else CyberCardBorder,
                                        shape = RoundedCornerShape(10.dp)
                                    ),
                                color = if (isSelected) color.copy(alpha = 0.15f) else CyberDarkSurface,
                                shape = RoundedCornerShape(10.dp)
                            ) {
                                Column(
                                    modifier = Modifier.padding(vertical = 10.dp, horizontal = 6.dp),
                                    horizontalAlignment = Alignment.CenterHorizontally
                                ) {
                                    Text(
                                        text = intensity.title,
                                        color = if (isSelected) color else TextSecondary,
                                        fontWeight = FontWeight.Black,
                                        fontSize = 11.sp,
                                        textAlign = androidx.compose.ui.text.style.TextAlign.Center
                                    )
                                    Spacer(modifier = Modifier.height(2.dp))
                                    Text(
                                        text = intensity.subtitle,
                                        color = TextMuted,
                                        fontSize = 10.sp
                                    )
                                }
                            }
                        }
                    }

                    Text(
                        text = filterIntensity.description,
                        color = TextSecondary,
                        fontSize = 11.sp,
                        lineHeight = 16.sp
                    )

                    // Suggested DNS Recommendation Bar for Active Level
                    val suggestedProvider = DnsProviders.getById(filterIntensity.suggestedDnsId)
                    val isSuggestedAlreadySelected = activeDns.id == suggestedProvider.id

                    Surface(
                        color = if (isSuggestedAlreadySelected) CyberDarkSurface else NeonCyan.copy(alpha = 0.12f),
                        border = androidx.compose.foundation.BorderStroke(
                            1.dp,
                            if (isSuggestedAlreadySelected) CyberCardBorder else NeonCyan.copy(alpha = 0.6f)
                        ),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                if (!isSuggestedAlreadySelected) {
                                    ThreatLensVpnService.setDnsProvider(suggestedProvider)
                                }
                            }
                    ) {
                        Row(
                            modifier = Modifier.padding(10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.weight(1f)
                            ) {
                                Icon(
                                    imageVector = if (isSuggestedAlreadySelected) Icons.Default.CheckCircle else Icons.Default.Recommend,
                                    contentDescription = null,
                                    tint = if (isSuggestedAlreadySelected) NeonGreen else NeonCyan,
                                    modifier = Modifier.size(20.dp)
                                )
                                Spacer(modifier = Modifier.width(10.dp))
                                Column {
                                    Text(
                                        text = if (isSuggestedAlreadySelected) "Active DNS matches recommendation:" else "Suggested DNS for ${filterIntensity.title}:",
                                        color = TextMuted,
                                        fontSize = 10.sp
                                    )
                                    Text(
                                        text = "${suggestedProvider.name} (${suggestedProvider.primaryIp})",
                                        color = Color.White,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 12.sp
                                    )
                                }
                            }

                            if (!isSuggestedAlreadySelected) {
                                Button(
                                    onClick = { ThreatLensVpnService.setDnsProvider(suggestedProvider) },
                                    colors = ButtonDefaults.buttonColors(containerColor = NeonCyan),
                                    contentPadding = PaddingValues(horizontal = 10.dp, vertical = 2.dp),
                                    modifier = Modifier.height(28.dp)
                                ) {
                                    Text(
                                        text = "Apply Suggested",
                                        color = CyberBlack,
                                        fontWeight = FontWeight.Black,
                                        fontSize = 10.sp
                                    )
                                }
                            }
                        }
                    }
                }
            }

            // Filter Scope (Malware Only, Ads Only, Both)
            item {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = "FILTERING SCOPE",
                        color = NeonCyan,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.sp
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        listOf(
                            Triple(FilterMode.BOTH, "All (Both)", Icons.Default.Shield),
                            Triple(FilterMode.MALWARE_ONLY, "Malware Only", Icons.Default.GppBad),
                            Triple(FilterMode.ADS_ONLY, "Ads Only", Icons.Default.Block)
                        ).forEach { (mode, label, icon) ->
                            val isSelected = filterMode == mode
                            Surface(
                                modifier = Modifier
                                    .weight(1f)
                                    .clickable { DomainFilterEngine.setFilterMode(mode) }
                                    .border(
                                        width = if (isSelected) 1.5.dp else 1.dp,
                                        color = if (isSelected) NeonCyan else CyberCardBorder,
                                        shape = RoundedCornerShape(10.dp)
                                    ),
                                color = if (isSelected) NeonCyan.copy(alpha = 0.12f) else CyberDarkSurface,
                                shape = RoundedCornerShape(10.dp)
                            ) {
                                Row(
                                    modifier = Modifier.padding(vertical = 10.dp, horizontal = 6.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.Center
                                ) {
                                    Icon(
                                        imageVector = icon,
                                        contentDescription = null,
                                        tint = if (isSelected) NeonCyan else TextMuted,
                                        modifier = Modifier.size(14.dp)
                                    )
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text(
                                        text = label,
                                        color = if (isSelected) NeonCyan else TextSecondary,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 11.sp
                                    )
                                }
                            }
                        }
                    }
                }
            }

            // Secure DNS Provider Selector (AdGuard, Cloudflare, Quad9, Control D, NextDNS, Mullvad, Google)
            item {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "SECURE UPSTREAM DNS PROVIDER",
                            color = NeonCyan,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 1.sp
                        )

                        Text(
                            text = activeDns.name,
                            color = activeDns.primaryColor,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold
                        )
                    }

                    LazyRow(
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        items(DnsProviders.ALL_PROVIDERS) { provider ->
                            val isSelected = activeDns.id == provider.id
                            val isSuggestedForCurrentLevel = provider.id == filterIntensity.suggestedDnsId

                            Surface(
                                modifier = Modifier
                                    .width(175.dp)
                                    .clickable { ThreatLensVpnService.setDnsProvider(provider) }
                                    .border(
                                        width = if (isSelected) 2.dp else if (isSuggestedForCurrentLevel) 1.5.dp else 1.dp,
                                        color = if (isSelected) provider.primaryColor else if (isSuggestedForCurrentLevel) NeonCyan else CyberCardBorder,
                                        shape = RoundedCornerShape(12.dp)
                                    ),
                                color = if (isSelected) provider.primaryColor.copy(alpha = 0.15f) else CyberDarkSurface,
                                shape = RoundedCornerShape(12.dp)
                            ) {
                                Column(
                                    modifier = Modifier.padding(12.dp),
                                    verticalArrangement = Arrangement.spacedBy(6.dp)
                                ) {
                                    if (isSuggestedForCurrentLevel) {
                                        Surface(
                                            color = NeonCyan.copy(alpha = 0.2f),
                                            shape = RoundedCornerShape(4.dp)
                                        ) {
                                            Text(
                                                text = "⭐ SUGGESTED FOR YOU",
                                                color = NeonCyan,
                                                fontSize = 9.sp,
                                                fontWeight = FontWeight.Black,
                                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                            )
                                        }
                                    }

                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        // Original Brand Badge Emblem
                                        Surface(
                                            color = provider.primaryColor,
                                            shape = RoundedCornerShape(6.dp)
                                        ) {
                                            Text(
                                                text = provider.brandTag,
                                                color = Color.White,
                                                fontSize = 12.sp,
                                                fontWeight = FontWeight.Black,
                                                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                            )
                                        }

                                        if (isSelected) {
                                            Icon(
                                                imageVector = Icons.Default.CheckCircle,
                                                contentDescription = "Selected",
                                                tint = provider.primaryColor,
                                                modifier = Modifier.size(16.dp)
                                            )
                                        }
                                    }

                                    Text(
                                        text = provider.name,
                                        color = Color.White,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 13.sp
                                    )

                                    Text(
                                        text = provider.primaryIp,
                                        color = TextMuted,
                                        fontSize = 10.sp,
                                        fontFamily = FontFamily.Monospace
                                    )

                                    Text(
                                        text = provider.recommendationBadge ?: provider.features.firstOrNull() ?: "Fast Resolver",
                                        color = provider.accentColor,
                                        fontSize = 9.sp,
                                        fontWeight = FontWeight.Bold,
                                        maxLines = 1
                                    )
                                }
                            }
                        }
                    }
                }
            }

            // MITM Defense & Network Integrity Card
            item {
                GlassCard(
                    modifier = Modifier
                        .fillMaxWidth()
                        .border(
                            1.dp,
                            when (mitmReport.status) {
                                MitmStatus.COMPROMISED -> NeonRed
                                MitmStatus.WARNING -> Color(0xFFFFA000)
                                MitmStatus.SECURE -> NeonGreen.copy(alpha = 0.4f)
                            },
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
                                Icon(
                                    imageVector = when (mitmReport.status) {
                                        MitmStatus.COMPROMISED -> Icons.Default.Warning
                                        MitmStatus.WARNING -> Icons.Default.ReportProblem
                                        MitmStatus.SECURE -> Icons.Default.VerifiedUser
                                    },
                                    contentDescription = null,
                                    tint = when (mitmReport.status) {
                                        MitmStatus.COMPROMISED -> NeonRed
                                        MitmStatus.WARNING -> Color(0xFFFFA000)
                                        MitmStatus.SECURE -> NeonGreen
                                    },
                                    modifier = Modifier.size(20.dp)
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = "MITM & SSL INTEGRITY",
                                    color = TextPrimary,
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.Bold
                                )
                            }

                            Button(
                                onClick = {
                                    isScanningMitm = true
                                    coroutineScope.launch {
                                        MitmDetector.auditNetworkIntegrity(context)
                                        isScanningMitm = false
                                    }
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = CyberDarkSurface),
                                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
                                modifier = Modifier.height(30.dp),
                                enabled = !isScanningMitm
                            ) {
                                if (isScanningMitm) {
                                    CircularProgressIndicator(modifier = Modifier.size(12.dp), color = NeonCyan, strokeWidth = 1.5.dp)
                                } else {
                                    Text("Audit Now", color = NeonCyan, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                }
                            }
                        }

                        Text(
                            text = when (mitmReport.status) {
                                MitmStatus.COMPROMISED -> "CRITICAL: Potential Man-in-the-Middle condition detected! Unsanctioned Root CA or DNS poisoning found."
                                MitmStatus.WARNING -> "WARNING: Active HTTP proxy or untrusted network redirection in place."
                                MitmStatus.SECURE -> "Clean: No user root certificates, rogue proxies, or captive portal DNS poisoning detected."
                            },
                            color = when (mitmReport.status) {
                                MitmStatus.COMPROMISED -> NeonRed
                                MitmStatus.WARNING -> Color(0xFFFFA000)
                                MitmStatus.SECURE -> TextSecondary
                            },
                            fontSize = 12.sp,
                            lineHeight = 17.sp
                        )

                        if (mitmReport.findings.isNotEmpty()) {
                            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                mitmReport.findings.forEach { finding ->
                                    Surface(
                                        color = CyberDarkSurface,
                                        shape = RoundedCornerShape(8.dp),
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                            Text(
                                                text = finding.title,
                                                color = if (finding.severity == ThreatSeverity.MALICIOUS) NeonRed else Color(0xFFFFA000),
                                                fontSize = 12.sp,
                                                fontWeight = FontWeight.Bold
                                            )
                                            Text(
                                                text = finding.detail,
                                                color = TextMuted,
                                                fontSize = 11.sp
                                            )
                                            Text(
                                                text = "Remedy: ${finding.remediation}",
                                                color = NeonCyan,
                                                fontSize = 10.sp
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Real-time Intercepted Threats Feed
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "LIVE INTERCEPT LOG (${blockedEvents.size})",
                        color = NeonCyan,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 1.sp
                    )

                    if (blockedEvents.isNotEmpty()) {
                        Text(
                            text = "Clear",
                            color = TextMuted,
                            fontSize = 12.sp,
                            modifier = Modifier.clickable { DomainFilterEngine.clearHistory() }
                        )
                    }
                }
            }

            if (blockedEvents.isEmpty()) {
                item {
                    GlassCard(modifier = Modifier.fillMaxWidth()) {
                        Text(
                            text = "No links blocked yet. Live DNS queries are actively audited by ThreatLens on-device filter.",
                            color = TextMuted,
                            fontSize = 12.sp,
                            modifier = Modifier.padding(vertical = 8.dp)
                        )
                    }
                }
            } else {
                items(blockedEvents) { event ->
                    GlassCard(modifier = Modifier.fillMaxWidth()) {
                        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Surface(
                                    color = Color(event.category.badgeColorHex).copy(alpha = 0.2f),
                                    shape = RoundedCornerShape(4.dp)
                                ) {
                                    Text(
                                        text = event.category.label,
                                        color = Color(event.category.badgeColorHex),
                                        fontSize = 9.sp,
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                    )
                                }

                                Text(
                                    text = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault()).format(event.timestamp),
                                    color = TextMuted,
                                    fontSize = 10.sp,
                                    fontFamily = FontFamily.Monospace
                                )
                            }

                            Text(
                                text = event.domain,
                                color = Color.White,
                                fontWeight = FontWeight.Bold,
                                fontSize = 13.sp,
                                fontFamily = FontFamily.Monospace
                            )

                            Text(
                                text = "Sources: ${event.sources.joinToString(", ")}",
                                color = TextMuted,
                                fontSize = 10.sp
                            )
                        }
                    }
                }
            }

            item {
                Spacer(modifier = Modifier.height(24.dp))
            }
        }
    }
}

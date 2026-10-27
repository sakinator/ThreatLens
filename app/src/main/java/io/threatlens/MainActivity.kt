package io.threatlens

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Article
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import io.threatlens.ui.screens.DashboardScreen
import io.threatlens.ui.screens.FullScanScreen
import io.threatlens.ui.screens.NewsScreen
import io.threatlens.ui.screens.SettingsScreen
import io.threatlens.ui.theme.*
import io.threatlens.ui.viewmodel.MainViewModel

class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels()

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* Permission granted or rejected */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        checkAndRequestPermissions()
        handleThreatIntent(intent)
        io.threatlens.core.system.ShieldWatchdogJobService.ensureShieldRunning(this)
        io.threatlens.core.system.ShieldWatchdogJobService.scheduleWatchdog(this)

        setContent {
            ThreatLensTheme {
                var currentTab by remember { mutableStateOf("dashboard") }

                Scaffold(
                    containerColor = CyberBlack,
                    bottomBar = {
                        NavigationBar(
                            containerColor = CyberDarkSurface,
                            contentColor = TextPrimary
                        ) {
                            NavigationBarItem(
                                selected = currentTab == "dashboard",
                                onClick = { currentTab = "dashboard" },
                                icon = { Icon(Icons.Default.Security, contentDescription = "Shield") },
                                label = { Text("Shield") },
                                colors = NavigationBarItemDefaults.colors(
                                    selectedIconColor = CyberBlack,
                                    selectedTextColor = NeonCyan,
                                    indicatorColor = NeonCyan,
                                    unselectedIconColor = TextMuted,
                                    unselectedTextColor = TextMuted
                                )
                            )

                            NavigationBarItem(
                                selected = currentTab == "scan",
                                onClick = { currentTab = "scan" },
                                icon = { Icon(Icons.Default.Radar, contentDescription = "Full Scan") },
                                label = { Text("Scanner") },
                                colors = NavigationBarItemDefaults.colors(
                                    selectedIconColor = CyberBlack,
                                    selectedTextColor = NeonCyan,
                                    indicatorColor = NeonCyan,
                                    unselectedIconColor = TextMuted,
                                    unselectedTextColor = TextMuted
                                )
                            )

                            NavigationBarItem(
                                selected = currentTab == "vulns",
                                onClick = { currentTab = "vulns" },
                                icon = { Icon(Icons.Default.BugReport, contentDescription = "Vulnerabilities") },
                                label = { Text("Vulns") },
                                colors = NavigationBarItemDefaults.colors(
                                    selectedIconColor = CyberBlack,
                                    selectedTextColor = NeonCyan,
                                    indicatorColor = NeonCyan,
                                    unselectedIconColor = TextMuted,
                                    unselectedTextColor = TextMuted
                                )
                            )

                            NavigationBarItem(
                                selected = currentTab == "news",
                                onClick = { currentTab = "news" },
                                icon = { Icon(Icons.Default.Article, contentDescription = "Threat Pulse") },
                                label = { Text("News") },
                                colors = NavigationBarItemDefaults.colors(
                                    selectedIconColor = CyberBlack,
                                    selectedTextColor = NeonCyan,
                                    indicatorColor = NeonCyan,
                                    unselectedIconColor = TextMuted,
                                    unselectedTextColor = TextMuted
                                )
                            )

                            NavigationBarItem(
                                selected = currentTab == "settings",
                                onClick = { currentTab = "settings" },
                                icon = { Icon(Icons.Default.Settings, contentDescription = "Settings") },
                                label = { Text("Settings") },
                                colors = NavigationBarItemDefaults.colors(
                                    selectedIconColor = CyberBlack,
                                    selectedTextColor = NeonCyan,
                                    indicatorColor = NeonCyan,
                                    unselectedIconColor = TextMuted,
                                    unselectedTextColor = TextMuted
                                )
                            )
                        }
                    }
                ) { innerPadding ->
                    Surface(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(innerPadding),
                        color = CyberBlack
                    ) {
                        when (currentTab) {
                            "dashboard" -> {
                                DashboardScreen(
                                    viewModel = viewModel,
                                    onNavigateScan = { currentTab = "scan" },
                                    onNavigateNews = { currentTab = "news" },
                                    onNavigateSettings = { currentTab = "settings" },
                                    onNavigateWebProtection = { currentTab = "web_protection" }
                                )
                            }
                            "web_protection" -> {
                                io.threatlens.ui.screens.WebProtectionScreen(
                                    onBack = { currentTab = "dashboard" },
                                    onNavigateExclusions = { currentTab = "exclusions" }
                                )
                            }
                            "scan" -> {
                                FullScanScreen(viewModel = viewModel)
                            }
                            "vulns" -> {
                                io.threatlens.ui.screens.VulnerabilityScreen()
                            }
                            "news" -> {
                                NewsScreen(viewModel = viewModel)
                            }
                            "settings" -> {
                                SettingsScreen(
                                    viewModel = viewModel,
                                    onBack = { currentTab = "dashboard" },
                                    onNavigateAbout = { currentTab = "about" },
                                    onNavigateWebProtection = { currentTab = "web_protection" },
                                    onNavigateExclusions = { currentTab = "exclusions" }
                                )
                            }
                            "exclusions" -> {
                                io.threatlens.ui.screens.ExclusionsScreen(
                                    onBack = { currentTab = "settings" }
                                )
                            }
                            "about" -> {
                                io.threatlens.ui.screens.AboutScreen(
                                    onBack = { currentTab = "settings" }
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    private fun checkAndRequestPermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!Environment.isExternalStorageManager()) {
                try {
                    val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION).apply {
                        data = Uri.parse("package:$packageName")
                    }
                    startActivity(intent)
                } catch (_: Exception) {
                    val intent = Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
                    startActivity(intent)
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleThreatIntent(intent)
    }

    private fun handleThreatIntent(intent: Intent?) {
        val threatId = intent?.getStringExtra("THREAT_ID")
        val threatSha256 = intent?.getStringExtra("THREAT_SHA256")
        if (threatId != null || threatSha256 != null) {
            val matched = viewModel.scansList.value.firstOrNull {
                (threatId != null && it.id == threatId) ||
                (threatSha256 != null && it.sha256.equals(threatSha256, ignoreCase = true))
            }
            if (matched != null) {
                viewModel.selectReport(matched)
            }
        }
    }
}

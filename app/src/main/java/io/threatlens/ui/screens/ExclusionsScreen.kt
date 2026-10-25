package io.threatlens.ui.screens

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
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
import io.threatlens.core.exclusions.ExclusionManager
import io.threatlens.core.exclusions.ExclusionType
import io.threatlens.ui.components.GlassCard
import io.threatlens.ui.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExclusionsScreen(
    onBack: () -> Unit
) {
    val context = LocalContext.current
    var selectedTab by remember { mutableStateOf(0) } // 0: Antivirus, 1: VPN & Web

    val avExclusions by ExclusionManager.avExclusionItems.collectAsState()
    val vpnExclusions by ExclusionManager.vpnExclusionItems.collectAsState()

    var showAddDialog by remember { mutableStateOf(false) }
    var dialogType by remember { mutableStateOf(ExclusionType.AV_PATH) }
    var dialogInputValue by remember { mutableStateOf("") }

    Scaffold(
        containerColor = CyberBlack,
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "EXCLUSIONS & WHITELIST",
                        color = TextPrimary,
                        fontSize = 17.sp,
                        fontWeight = FontWeight.Black,
                        letterSpacing = 1.sp
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = NeonCyan)
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
        ) {
            // Tab Switcher (Antivirus Exclusions vs VPN & Web Exclusions)
            TabRow(
                selectedTabIndex = selectedTab,
                containerColor = CyberDarkSurface,
                contentColor = NeonCyan,
                divider = { Divider(color = CyberCardBorder) }
            ) {
                Tab(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    text = {
                        Text(
                            text = "🛡️ Antivirus (${avExclusions.size})",
                            fontWeight = FontWeight.Bold,
                            color = if (selectedTab == 0) NeonCyan else TextMuted
                        )
                    }
                )
                Tab(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    text = {
                        Text(
                            text = "🌐 VPN & Web (${vpnExclusions.size})",
                            fontWeight = FontWeight.Bold,
                            color = if (selectedTab == 1) NeonCyan else TextMuted
                        )
                    }
                )
            }

            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 16.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                item {
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = if (selectedTab == 0)
                            "Items below will be completely bypassed by Real-time, On-Demand, and Custom file scans."
                        else
                            "Apps below will route outside the local VPN tunnel, and domains below will never be blocked by DNS.",
                        color = TextSecondary,
                        fontSize = 12.sp,
                        lineHeight = 17.sp
                    )
                }

                // Action Buttons to Add Exclusions
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        if (selectedTab == 0) {
                            Button(
                                onClick = {
                                    dialogType = ExclusionType.AV_PATH
                                    dialogInputValue = ""
                                    showAddDialog = true
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = CyberCardSurface),
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier.weight(1f)
                            ) {
                                Icon(Icons.Default.Add, contentDescription = null, tint = NeonCyan, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Add File / Path", color = Color.White, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                            }

                            Button(
                                onClick = {
                                    dialogType = ExclusionType.AV_PACKAGE
                                    dialogInputValue = ""
                                    showAddDialog = true
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = CyberCardSurface),
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier.weight(1f)
                            ) {
                                Icon(Icons.Default.Add, contentDescription = null, tint = NeonCyan, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Add App Pkg", color = Color.White, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                            }
                        } else {
                            Button(
                                onClick = {
                                    dialogType = ExclusionType.VPN_BYPASS_APP
                                    dialogInputValue = ""
                                    showAddDialog = true
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = CyberCardSurface),
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier.weight(1f)
                            ) {
                                Icon(Icons.Default.Add, contentDescription = null, tint = NeonCyan, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Bypass App", color = Color.White, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                            }

                            Button(
                                onClick = {
                                    dialogType = ExclusionType.VPN_WHITELIST_DOMAIN
                                    dialogInputValue = ""
                                    showAddDialog = true
                                },
                                colors = ButtonDefaults.buttonColors(containerColor = CyberCardSurface),
                                shape = RoundedCornerShape(10.dp),
                                modifier = Modifier.weight(1f)
                            ) {
                                Icon(Icons.Default.Add, contentDescription = null, tint = NeonCyan, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Whitelist URL", color = Color.White, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }

                val currentItems = if (selectedTab == 0) avExclusions else vpnExclusions

                if (currentItems.isEmpty()) {
                    item {
                        GlassCard {
                            Box(modifier = Modifier.fillMaxWidth().padding(24.dp), contentAlignment = Alignment.Center) {
                                Text(
                                    text = "No exclusions configured yet.\nTap an 'Add' button above to whitelist trusted items.",
                                    color = TextMuted,
                                    fontSize = 12.sp,
                                    textAlign = androidx.compose.ui.text.style.TextAlign.Center
                                )
                            }
                        }
                    }
                } else {
                    items(currentItems, key = { it.id }) { item ->
                        GlassCard {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Icon(
                                        imageVector = when (item.type) {
                                            ExclusionType.AV_PACKAGE -> Icons.Default.Apps
                                            ExclusionType.AV_PATH -> Icons.Default.InsertDriveFile
                                            ExclusionType.AV_HASH -> Icons.Default.Pin
                                            ExclusionType.VPN_BYPASS_APP -> Icons.Default.VpnKeyOff
                                            ExclusionType.VPN_WHITELIST_DOMAIN -> Icons.Default.Language
                                        },
                                        contentDescription = null,
                                        tint = NeonCyan,
                                        modifier = Modifier.size(20.dp)
                                    )
                                    Spacer(modifier = Modifier.width(12.dp))
                                    Column {
                                        Text(
                                            text = item.value,
                                            color = Color.White,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 13.sp,
                                            fontFamily = FontFamily.Monospace,
                                            maxLines = 1
                                        )
                                        Text(
                                            text = when (item.type) {
                                                ExclusionType.AV_PACKAGE -> "Bypassed from Virus Scans"
                                                ExclusionType.AV_PATH -> "Bypassed File / Folder Path"
                                                ExclusionType.AV_HASH -> "Whitelisted SHA-256 Hash"
                                                ExclusionType.VPN_BYPASS_APP -> "Direct Internet (Skips VPN Tunnel)"
                                                ExclusionType.VPN_WHITELIST_DOMAIN -> "Allowed Domain (Never Sinkholed)"
                                            },
                                            color = TextMuted,
                                            fontSize = 11.sp
                                        )
                                    }
                                }

                                IconButton(
                                    onClick = {
                                        when (item.type) {
                                            ExclusionType.AV_PACKAGE -> ExclusionManager.removeAvPackage(item.value)
                                            ExclusionType.AV_PATH -> ExclusionManager.removeAvPath(item.value)
                                            ExclusionType.AV_HASH -> ExclusionManager.removeAvHash(item.value)
                                            ExclusionType.VPN_BYPASS_APP -> ExclusionManager.removeVpnBypassedApp(item.value)
                                            ExclusionType.VPN_WHITELIST_DOMAIN -> ExclusionManager.removeVpnWhitelistedDomain(item.value)
                                        }
                                    }
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.DeleteOutline,
                                        contentDescription = "Remove",
                                        tint = NeonCrimson,
                                        modifier = Modifier.size(20.dp)
                                    )
                                }
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

    // Add Exclusion Modal Dialog
    if (showAddDialog) {
        AlertDialog(
            onDismissRequest = { showAddDialog = false },
            containerColor = CyberDarkSurface,
            title = {
                Text(
                    text = when (dialogType) {
                        ExclusionType.AV_PATH -> "Add Bypassable File or Folder"
                        ExclusionType.AV_PACKAGE -> "Add Bypassable App Package"
                        ExclusionType.VPN_BYPASS_APP -> "Add App to Bypass VPN Tunnel"
                        ExclusionType.VPN_WHITELIST_DOMAIN -> "Add Whitelisted URL / Domain"
                        else -> "Add Exclusion"
                    },
                    color = Color.White,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = when (dialogType) {
                            ExclusionType.AV_PATH -> "Enter full file or directory path (e.g. /sdcard/Download/my_folder):"
                            ExclusionType.AV_PACKAGE -> "Enter Android package name (e.g. com.example.app):"
                            ExclusionType.VPN_BYPASS_APP -> "Enter package name to bypass VPN (e.g. com.chase.sig.android):"
                            ExclusionType.VPN_WHITELIST_DOMAIN -> "Enter domain name to never block (e.g. custom-server.com):"
                            else -> "Enter value:"
                        },
                        color = TextSecondary,
                        fontSize = 12.sp
                    )
                    OutlinedTextField(
                        value = dialogInputValue,
                        onValueChange = { dialogInputValue = it },
                        modifier = Modifier.fillMaxWidth(),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = NeonCyan,
                            unfocusedBorderColor = CyberCardBorder,
                            focusedTextColor = Color.White,
                            unfocusedTextColor = Color.White
                        ),
                        singleLine = true
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        val v = dialogInputValue.trim()
                        if (v.isNotBlank()) {
                            when (dialogType) {
                                ExclusionType.AV_PATH -> ExclusionManager.addAvPath(v)
                                ExclusionType.AV_PACKAGE -> ExclusionManager.addAvPackage(v)
                                ExclusionType.VPN_BYPASS_APP -> ExclusionManager.addVpnBypassedApp(v)
                                ExclusionType.VPN_WHITELIST_DOMAIN -> ExclusionManager.addVpnWhitelistedDomain(v)
                                else -> {}
                            }
                            showAddDialog = false
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = NeonCyan)
                ) {
                    Text("Add Exclusion", color = CyberBlack, fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showAddDialog = false }) {
                    Text("Cancel", color = TextMuted)
                }
            }
        )
    }
}

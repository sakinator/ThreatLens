package io.threatlens.ui.screens

import android.widget.Toast
import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.threatlens.core.vpn.DomainFilterEngine
import io.threatlens.core.vpn.ThreatCategory
import io.threatlens.ui.components.GlassCard
import io.threatlens.ui.theme.*
import java.text.SimpleDateFormat
import java.util.*

/**
 * Interactive Blocked Sites History & URL Whitelist Sheet.
 *
 * Allows users to inspect live DNS sinkhole events, unblock any domain with one touch,
 * and whitelist arbitrary URLs or domain names directly from the ThreatLens interface.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BlockedSitesSheet(
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val blockedEvents by DomainFilterEngine.blockedEvents.collectAsState()
    val totalAds by DomainFilterEngine.totalAdsBlocked.collectAsState()
    val totalMalware by DomainFilterEngine.totalMalwareBlocked.collectAsState()
    val whitelistedDomains by DomainFilterEngine.whitelistedDomains.collectAsState()

    var selectedTab by remember { mutableStateOf(0) } // 0: Blocked Log, 1: Whitelisted
    var customUrlInput by remember { mutableStateOf("") }
    var searchQuery by remember { mutableStateOf("") }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        containerColor = CyberBlack,
        dragHandle = {
            Box(
                modifier = Modifier
                    .padding(vertical = 10.dp)
                    .width(42.dp)
                    .height(4.dp)
                    .background(CyberCardBorder, RoundedCornerShape(2.dp))
            )
        }
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .fillMaxHeight(0.9f)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            // Header Row
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(36.dp)
                            .background(NeonCyan.copy(alpha = 0.15f), CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.Shield,
                            contentDescription = null,
                            tint = NeonCyan,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                    Spacer(modifier = Modifier.width(10.dp))
                    Column {
                        Text(
                            text = "BLOCKED THREATS & SINKHOLE",
                            color = TextPrimary,
                            fontWeight = FontWeight.Black,
                            fontSize = 15.sp,
                            letterSpacing = 0.5.sp
                        )
                        Text(
                            text = "Touch any threat to inspect and unblock",
                            color = TextSecondary,
                            fontSize = 11.sp
                        )
                    }
                }

                IconButton(onClick = onDismiss) {
                    Icon(
                        imageVector = Icons.Default.Close,
                        contentDescription = "Close",
                        tint = TextMuted
                    )
                }
            }

            // Interactive Threat Counters Pill Bar
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Surface(
                    modifier = Modifier.weight(1f),
                    color = CyberDarkSurface,
                    shape = RoundedCornerShape(10.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, NeonRed.copy(alpha = 0.4f))
                ) {
                    Column(
                        modifier = Modifier.padding(vertical = 8.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            text = "$totalMalware",
                            color = NeonRed,
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Black
                        )
                        Text(
                            text = "C2 & Phish Stopped",
                            color = TextSecondary,
                            fontSize = 10.sp
                        )
                    }
                }

                Surface(
                    modifier = Modifier.weight(1f),
                    color = CyberDarkSurface,
                    shape = RoundedCornerShape(10.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, NeonCyan.copy(alpha = 0.4f))
                ) {
                    Column(
                        modifier = Modifier.padding(vertical = 8.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            text = "$totalAds",
                            color = NeonCyan,
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Black
                        )
                        Text(
                            text = "Trackers Sinkholed",
                            color = TextSecondary,
                            fontSize = 10.sp
                        )
                    }
                }

                Surface(
                    modifier = Modifier.weight(1f),
                    color = CyberDarkSurface,
                    shape = RoundedCornerShape(10.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, NeonEmerald.copy(alpha = 0.4f))
                ) {
                    Column(
                        modifier = Modifier.padding(vertical = 8.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            text = "${whitelistedDomains.size}",
                            color = NeonEmerald,
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Black
                        )
                        Text(
                            text = "User Whitelisted",
                            color = TextSecondary,
                            fontSize = 10.sp
                        )
                    }
                }
            }

            // Quick Whitelist Input Field
            GlassCard(modifier = Modifier.fillMaxWidth()) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = "WHITELIST ANY DOMAIN OR URL",
                        color = NeonCyan,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 0.5.sp
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = customUrlInput,
                            onValueChange = { customUrlInput = it },
                            placeholder = {
                                Text(
                                    text = "e.g. example.com or https://...",
                                    color = TextMuted,
                                    fontSize = 12.sp
                                )
                            },
                            singleLine = true,
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedTextColor = Color.White,
                                unfocusedTextColor = Color.White,
                                focusedBorderColor = NeonCyan,
                                unfocusedBorderColor = CyberCardBorder,
                                focusedContainerColor = CyberDarkSurface,
                                unfocusedContainerColor = CyberDarkSurface
                            ),
                            modifier = Modifier.weight(1f)
                        )

                        Button(
                            onClick = {
                                val trimmed = customUrlInput.trim()
                                if (trimmed.isNotEmpty()) {
                                    DomainFilterEngine.whitelistDomain(trimmed)
                                    Toast.makeText(context, "✓ Whitelisted $trimmed", Toast.LENGTH_SHORT).show()
                                    customUrlInput = ""
                                }
                            },
                            colors = ButtonDefaults.buttonColors(containerColor = NeonEmerald),
                            shape = RoundedCornerShape(8.dp),
                            contentPadding = PaddingValues(horizontal = 14.dp, vertical = 12.dp)
                        ) {
                            Text(
                                text = "Whitelist",
                                color = CyberBlack,
                                fontWeight = FontWeight.Black,
                                fontSize = 12.sp
                            )
                        }
                    }
                }
            }

            // Tab Switcher
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
                            text = "Blocked Log (${blockedEvents.size})",
                            fontWeight = FontWeight.Bold,
                            fontSize = 12.sp
                        )
                    }
                )
                Tab(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    text = {
                        Text(
                            text = "Whitelisted (${whitelistedDomains.size})",
                            fontWeight = FontWeight.Bold,
                            fontSize = 12.sp
                        )
                    }
                )
            }

            // Tab Content
            when (selectedTab) {
                0 -> {
                    // Search Bar for Blocked History
                    if (blockedEvents.isNotEmpty()) {
                        OutlinedTextField(
                            value = searchQuery,
                            onValueChange = { searchQuery = it },
                            placeholder = { Text("Filter blocked hosts...", color = TextMuted, fontSize = 12.sp) },
                            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, tint = TextMuted) },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                            colors = OutlinedTextFieldDefaults.colors(
                                focusedTextColor = Color.White,
                                unfocusedTextColor = Color.White,
                                focusedBorderColor = NeonCyan.copy(alpha = 0.5f),
                                unfocusedBorderColor = CyberCardBorder,
                                focusedContainerColor = CyberDarkSurface,
                                unfocusedContainerColor = CyberDarkSurface
                            )
                        )
                    }

                    val filteredEvents = remember(blockedEvents, searchQuery) {
                        if (searchQuery.isBlank()) blockedEvents
                        else blockedEvents.filter { it.domain.contains(searchQuery.trim(), ignoreCase = true) }
                    }

                    if (filteredEvents.isEmpty()) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 32.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = if (blockedEvents.isEmpty()) "No connections blocked yet. Real-time web shield is running." else "No matches found for '$searchQuery'.",
                                color = TextMuted,
                                fontSize = 12.sp
                            )
                        }
                    } else {
                        LazyColumn(
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                            modifier = Modifier.fillMaxSize()
                        ) {
                            items(filteredEvents, key = { it.id }) { event ->
                                BlockedSiteRow(
                                    event = event,
                                    onUnblock = {
                                        DomainFilterEngine.whitelistDomain(event.domain)
                                        Toast.makeText(context, "✓ Unblocked & Whitelisted ${event.domain}", Toast.LENGTH_SHORT).show()
                                    }
                                )
                            }
                            item { Spacer(modifier = Modifier.height(16.dp)) }
                        }
                    }
                }
                1 -> {
                    val whitelistList = whitelistedDomains.toList().sorted()
                    if (whitelistList.isEmpty()) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 32.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = "No domains whitelisted yet. Enter any domain or URL above to bypass filtering.",
                                color = TextMuted,
                                fontSize = 12.sp
                            )
                        }
                    } else {
                        LazyColumn(
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                            modifier = Modifier.fillMaxSize()
                        ) {
                            items(whitelistList) { domain ->
                                WhitelistedDomainRow(
                                    domain = domain,
                                    onRemove = {
                                        DomainFilterEngine.unwhitelistDomain(domain)
                                        Toast.makeText(context, "Removed $domain from Whitelist", Toast.LENGTH_SHORT).show()
                                    }
                                )
                            }
                            item { Spacer(modifier = Modifier.height(16.dp)) }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun BlockedSiteRow(
    event: io.threatlens.core.vpn.BlockedEvent,
    onUnblock: () -> Unit
) {
    Surface(
        color = CyberDarkSurface,
        shape = RoundedCornerShape(10.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, CyberCardBorder),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Surface(
                    color = Color(event.category.badgeColorHex).copy(alpha = 0.15f),
                    shape = RoundedCornerShape(4.dp)
                ) {
                    Text(
                        text = event.category.label,
                        color = Color(event.category.badgeColorHex),
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                }

                Text(
                    text = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(event.timestamp),
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
                text = event.reason,
                color = TextSecondary,
                fontSize = 11.sp,
                maxLines = 2
            )

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = "Feeds: ${event.sources.joinToString(", ")}",
                    color = TextMuted,
                    fontSize = 10.sp,
                    modifier = Modifier.weight(1f)
                )

                Button(
                    onClick = onUnblock,
                    colors = ButtonDefaults.buttonColors(containerColor = NeonCyan.copy(alpha = 0.15f)),
                    border = androidx.compose.foundation.BorderStroke(1.dp, NeonCyan),
                    shape = RoundedCornerShape(6.dp),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp),
                    modifier = Modifier.height(26.dp)
                ) {
                    Text(
                        text = "Unblock",
                        color = NeonCyan,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }
    }
}

@Composable
private fun WhitelistedDomainRow(
    domain: String,
    onRemove: () -> Unit
) {
    Surface(
        color = CyberDarkSurface,
        shape = RoundedCornerShape(10.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, CyberCardBorder),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.weight(1f)
            ) {
                Icon(
                    imageVector = Icons.Default.CheckCircle,
                    contentDescription = null,
                    tint = NeonEmerald,
                    modifier = Modifier.size(16.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = domain,
                    color = Color.White,
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp,
                    fontFamily = FontFamily.Monospace
                )
            }

            IconButton(
                onClick = onRemove,
                modifier = Modifier.size(28.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.DeleteOutline,
                    contentDescription = "Remove",
                    tint = TextMuted,
                    modifier = Modifier.size(18.dp)
                )
            }
        }
    }
}

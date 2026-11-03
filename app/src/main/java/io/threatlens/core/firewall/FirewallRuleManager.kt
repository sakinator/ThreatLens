package io.threatlens.core.firewall

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.ConcurrentHashMap

/**
 * P3: Autonomous Per-App Network Firewall Manager.
 *
 * Provides granular zero-trust application firewall capabilities.
 * Allows users to sever outbound and inbound internet connectivity for any selected application
 * directly on the on-device TUN VPN layer without root privileges or device modifications.
 */
object FirewallRuleManager {

    private const val PREFS_NAME = "threatlens_firewall_rules"
    private const val KEY_BLOCKED_PACKAGES = "blocked_packages"

    private lateinit var prefs: SharedPreferences
    private val blockedSet = ConcurrentHashMap.newKeySet<String>()

    private val _blockedPackages = MutableStateFlow<Set<String>>(emptySet())
    val blockedPackages: StateFlow<Set<String>> = _blockedPackages.asStateFlow()

    private val _totalBlocked = MutableStateFlow(0)
    val totalBlocked: StateFlow<Int> = _totalBlocked.asStateFlow()

    fun init(context: Context) {
        prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val saved = prefs.getStringSet(KEY_BLOCKED_PACKAGES, emptySet()) ?: emptySet()
        blockedSet.clear()
        blockedSet.addAll(saved)
        updateFlow()
    }

    fun blockApp(packageName: String) {
        val norm = packageName.trim()
        if (norm.isNotEmpty()) {
            blockedSet.add(norm)
            save()
            updateFlow()
        }
    }

    fun unblockApp(packageName: String) {
        val norm = packageName.trim()
        if (blockedSet.remove(norm)) {
            save()
            updateFlow()
        }
    }

    fun toggleApp(packageName: String): Boolean {
        val norm = packageName.trim()
        val newState: Boolean
        if (blockedSet.contains(norm)) {
            blockedSet.remove(norm)
            newState = false
        } else {
            blockedSet.add(norm)
            newState = true
        }
        save()
        updateFlow()
        return newState
    }

    fun isAppBlocked(packageName: String): Boolean {
        return blockedSet.contains(packageName.trim())
    }

    fun getBlockedPackages(): Set<String> {
        return blockedSet.toSet()
    }

    fun clearAllRules() {
        blockedSet.clear()
        save()
        updateFlow()
    }

    private fun save() {
        if (::prefs.isInitialized) {
            prefs.edit().putStringSet(KEY_BLOCKED_PACKAGES, HashSet(blockedSet)).apply()
        }
    }

    private fun updateFlow() {
        val current = blockedSet.toSet()
        _blockedPackages.value = current
        _totalBlocked.value = current.size
    }
}

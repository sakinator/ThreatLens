package io.threatlens.core.exclusions

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File
import java.util.concurrent.ConcurrentHashMap

data class ExcludedItem(
    val id: String = java.util.UUID.randomUUID().toString(),
    val value: String,
    val label: String,
    val type: ExclusionType,
    val addedTimestamp: Long = System.currentTimeMillis()
)

enum class ExclusionType {
    AV_PACKAGE,
    AV_PATH,
    AV_HASH,
    VPN_BYPASS_APP,
    VPN_WHITELIST_DOMAIN
}

object ExclusionManager {

    private const val PREFS_NAME = "threatlens_exclusions"
    private const val KEY_AV_PACKAGES = "av_packages"
    private const val KEY_AV_PATHS = "av_paths"
    private const val KEY_AV_HASHES = "av_hashes"
    private const val KEY_VPN_BYPASS_APPS = "vpn_bypass_apps"
    private const val KEY_VPN_DOMAINS = "vpn_domains"

    private lateinit var prefs: SharedPreferences

    // In-Memory Sets for O(1) high-speed evaluation in scanning loops & packet parsing
    private val avPackages = ConcurrentHashMap.newKeySet<String>()
    private val avPaths = ConcurrentHashMap.newKeySet<String>()
    private val avHashes = ConcurrentHashMap.newKeySet<String>()
    private val vpnBypassedApps = ConcurrentHashMap.newKeySet<String>()
    private val vpnWhitelistedDomains = ConcurrentHashMap.newKeySet<String>()

    private val _avExclusionItems = MutableStateFlow<List<ExcludedItem>>(emptyList())
    val avExclusionItems: StateFlow<List<ExcludedItem>> = _avExclusionItems.asStateFlow()

    private val _vpnExclusionItems = MutableStateFlow<List<ExcludedItem>>(emptyList())
    val vpnExclusionItems: StateFlow<List<ExcludedItem>> = _vpnExclusionItems.asStateFlow()

    fun init(context: Context) {
        prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        // Load AV Exclusions
        avPackages.addAll(prefs.getStringSet(KEY_AV_PACKAGES, emptySet()) ?: emptySet())
        avPaths.addAll(prefs.getStringSet(KEY_AV_PATHS, emptySet()) ?: emptySet())
        avHashes.addAll(prefs.getStringSet(KEY_AV_HASHES, emptySet()) ?: emptySet())

        // Load VPN Exclusions
        vpnBypassedApps.addAll(prefs.getStringSet(KEY_VPN_BYPASS_APPS, emptySet()) ?: emptySet())
        vpnWhitelistedDomains.addAll(prefs.getStringSet(KEY_VPN_DOMAINS, emptySet()) ?: emptySet())

        // Seed default safe developer / system exclusions if empty
        if (avPackages.isEmpty()) {
            avPackages.add("com.android.chrome")
            avPackages.add("com.google.android.apps.docs")
        }

        refreshFlows()
    }

    // ==================== ANTIVIRUS EXCLUSIONS ====================

    fun addAvPackage(packageName: String, label: String = packageName) {
        val norm = packageName.trim()
        if (norm.isNotBlank()) {
            avPackages.add(norm)
            persistSet(KEY_AV_PACKAGES, avPackages)
            refreshFlows()
        }
    }

    fun removeAvPackage(packageName: String) {
        avPackages.remove(packageName.trim())
        persistSet(KEY_AV_PACKAGES, avPackages)
        refreshFlows()
    }

    fun addAvPath(path: String) {
        val norm = File(path.trim()).absolutePath
        if (norm.isNotBlank()) {
            avPaths.add(norm)
            persistSet(KEY_AV_PATHS, avPaths)
            refreshFlows()
        }
    }

    fun removeAvPath(path: String) {
        avPaths.remove(File(path.trim()).absolutePath)
        persistSet(KEY_AV_PATHS, avPaths)
        refreshFlows()
    }

    fun addAvHash(hash: String, label: String = "Known Clean Hash") {
        val norm = hash.trim().lowercase()
        if (norm.length == 64) {
            avHashes.add(norm)
            persistSet(KEY_AV_HASHES, avHashes)
            refreshFlows()
        }
    }

    fun removeAvHash(hash: String) {
        avHashes.remove(hash.trim().lowercase())
        persistSet(KEY_AV_HASHES, avHashes)
        refreshFlows()
    }

    fun isPathExcluded(path: String): Boolean {
        val norm = File(path).absolutePath
        return avPaths.contains(norm) || avPaths.any { norm.startsWith(it) }
    }

    fun isPackageExcluded(packageName: String): Boolean {
        return avPackages.contains(packageName.trim())
    }

    fun isHashExcluded(hash: String): Boolean {
        return avHashes.contains(hash.trim().lowercase())
    }

    // ==================== VPN & WEB SHIELD EXCLUSIONS ====================

    fun addVpnBypassedApp(packageName: String) {
        val norm = packageName.trim()
        if (norm.isNotBlank()) {
            vpnBypassedApps.add(norm)
            persistSet(KEY_VPN_BYPASS_APPS, vpnBypassedApps)
            refreshFlows()
        }
    }

    fun removeVpnBypassedApp(packageName: String) {
        vpnBypassedApps.remove(packageName.trim())
        persistSet(KEY_VPN_BYPASS_APPS, vpnBypassedApps)
        refreshFlows()
    }

    fun isVpnAppBypassed(packageName: String): Boolean {
        return vpnBypassedApps.contains(packageName.trim())
    }

    fun getVpnBypassedApps(): Set<String> {
        return vpnBypassedApps.toSet()
    }

    fun addVpnWhitelistedDomain(domain: String) {
        val norm = normalizeDomain(domain)
        if (norm.isNotBlank()) {
            vpnWhitelistedDomains.add(norm)
            persistSet(KEY_VPN_DOMAINS, vpnWhitelistedDomains)
            refreshFlows()
        }
    }

    fun removeVpnWhitelistedDomain(domain: String) {
        vpnWhitelistedDomains.remove(normalizeDomain(domain))
        persistSet(KEY_VPN_DOMAINS, vpnWhitelistedDomains)
        refreshFlows()
    }

    fun isDomainWhitelisted(domain: String): Boolean {
        val norm = normalizeDomain(domain)
        return vpnWhitelistedDomains.contains(norm) || vpnWhitelistedDomains.any { norm.endsWith(".$it") }
    }

    // ==================== HELPERS ====================

    private fun persistSet(key: String, set: Set<String>) {
        if (::prefs.isInitialized) {
            prefs.edit().putStringSet(key, HashSet(set)).apply()
        }
    }

    private fun refreshFlows() {
        val avList = mutableListOf<ExcludedItem>()
        avPackages.forEach { avList.add(ExcludedItem(value = it, label = "Package: $it", type = ExclusionType.AV_PACKAGE)) }
        avPaths.forEach { avList.add(ExcludedItem(value = it, label = "Path: $it", type = ExclusionType.AV_PATH)) }
        avHashes.forEach { avList.add(ExcludedItem(value = it, label = "SHA-256: ${it.take(16)}...", type = ExclusionType.AV_HASH)) }
        _avExclusionItems.value = avList

        val vpnList = mutableListOf<ExcludedItem>()
        vpnBypassedApps.forEach { vpnList.add(ExcludedItem(value = it, label = "Bypassed App: $it", type = ExclusionType.VPN_BYPASS_APP)) }
        vpnWhitelistedDomains.forEach { vpnList.add(ExcludedItem(value = it, label = "Whitelisted Domain: $it", type = ExclusionType.VPN_WHITELIST_DOMAIN)) }
        _vpnExclusionItems.value = vpnList
    }

    private fun normalizeDomain(raw: String): String {
        var d = raw.trim().lowercase()
        if (d.startsWith("http://")) d = d.removePrefix("http://")
        if (d.startsWith("https://")) d = d.removePrefix("https://")
        val slashIdx = d.indexOf('/')
        if (slashIdx != -1) d = d.substring(0, slashIdx)
        val colonIdx = d.indexOf(':')
        if (colonIdx != -1) d = d.substring(0, colonIdx)
        if (d.endsWith('.')) d = d.dropLast(1)
        return d
    }
}

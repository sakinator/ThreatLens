package io.threatlens.ui.viewmodel

import android.app.Application
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.core.content.ContextCompat
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.threatlens.core.model.ThreatReport
import io.threatlens.core.model.ThreatSeverity
import io.threatlens.core.news.CyberNewsArticle
import io.threatlens.core.news.CyberNewsFeedService
import io.threatlens.core.news.GeoLocationService
import io.threatlens.core.news.UserLocation
import io.threatlens.core.realtime.RealtimeDownloadShieldService
import io.threatlens.core.realtime.RealtimeScanCoordinator
import io.threatlens.core.scanner.FullScanState
import io.threatlens.core.scanner.FullSystemScanner
import io.threatlens.core.storage.ApiKeyVault
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val prefs = application.getSharedPreferences("threatlens_prefs", Context.MODE_PRIVATE)

    private val _isRealtimeShieldEnabled = MutableStateFlow(prefs.getBoolean("key_realtime_shield_enabled", true))
    val isRealtimeShieldEnabled: StateFlow<Boolean> = _isRealtimeShieldEnabled.asStateFlow()

    private val _isShieldActive = MutableStateFlow(true)
    val isShieldActive: StateFlow<Boolean> = _isShieldActive.asStateFlow()

    private val _scansList = MutableStateFlow<List<ThreatReport>>(emptyList())
    val scansList: StateFlow<List<ThreatReport>> = _scansList.asStateFlow()

    private val _selectedReport = MutableStateFlow<ThreatReport?>(null)
    val selectedReport: StateFlow<ThreatReport?> = _selectedReport.asStateFlow()

    // Full On-Demand Scan State (Bitdefender-style)
    val fullScanState: StateFlow<FullScanState> = FullSystemScanner.scanState

    private val _isScanning = MutableStateFlow(false)
    val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()

    // News Feed State
    private val _userLocation = MutableStateFlow(UserLocation())
    val userLocation: StateFlow<UserLocation> = _userLocation.asStateFlow()

    private val _newsArticles = MutableStateFlow<List<CyberNewsArticle>>(emptyList())
    val newsArticles: StateFlow<List<CyberNewsArticle>> = _newsArticles.asStateFlow()

    private val _isNewsLoading = MutableStateFlow(false)
    val isNewsLoading: StateFlow<Boolean> = _isNewsLoading.asStateFlow()

    // API Keys state
    val openAiKey = MutableStateFlow(prefs.getString("openai_key", "") ?: "")
    val claudeKey = MutableStateFlow(prefs.getString("claude_key", "") ?: "")
    val geminiKey = MutableStateFlow(prefs.getString("gemini_key", "") ?: "")
    val groqKey = MutableStateFlow(prefs.getString("groq_key", "") ?: "")
    val vtKey = MutableStateFlow(prefs.getString("vt_key", "") ?: "")
    val haKey = MutableStateFlow(prefs.getString("ha_key", "") ?: "")
    val kasperskyKey = MutableStateFlow(prefs.getString("kaspersky_key", "") ?: "")
    val metaDefenderKey = MutableStateFlow(prefs.getString("metadefender_key", "") ?: "")
    val filescanKey = MutableStateFlow(prefs.getString("filescan_key", "") ?: "")
    val bazaarKey = MutableStateFlow(prefs.getString("bazaar_key", "") ?: "")

    init {
        // Initialize API Key Vault immediately
        ApiKeyVault.init(application)
        reloadKeysFromPrefs()

        viewModelScope.launch {
            RealtimeScanCoordinator.scanReports.collect { newReport ->
                val current = _scansList.value.toMutableList()
                current.removeAll { it.sha256 == newReport.sha256 }
                current.add(0, newReport)
                _scansList.value = current
            }
        }

        if (_isRealtimeShieldEnabled.value) {
            startShieldService()
        } else {
            _isShieldActive.value = false
        }
        loadCyberNews()
    }

    fun startShieldService() {
        val app = getApplication<Application>()
        val intent = Intent(app, RealtimeDownloadShieldService::class.java)
        ContextCompat.startForegroundService(app, intent)
        _isShieldActive.value = true
    }

    fun stopShieldService() {
        val app = getApplication<Application>()
        val intent = Intent(app, RealtimeDownloadShieldService::class.java)
        app.stopService(intent)
        _isShieldActive.value = false
    }

    fun toggleShield() {
        if (_isShieldActive.value) stopShieldService() else startShieldService()
    }

    fun setRealtimeShieldEnabled(enabled: Boolean) {
        _isRealtimeShieldEnabled.value = enabled
        prefs.edit().putBoolean("key_realtime_shield_enabled", enabled).commit()
        if (enabled) {
            startShieldService()
        } else {
            stopShieldService()
        }
    }

    fun selectReport(report: ThreatReport?) {
        _selectedReport.value = report
    }

    fun startFullOnDemandScan() {
        FullSystemScanner.startFullScan(getApplication())
    }

    fun pauseFullScan() {
        FullSystemScanner.pauseScan()
    }

    fun resumeFullScan() {
        FullSystemScanner.resumeScan()
    }

    fun abortFullScan() {
        FullSystemScanner.abortScan()
    }

    fun cancelFullScan() {
        FullSystemScanner.cancelScan()
    }

    fun loadCyberNews() {
        viewModelScope.launch(Dispatchers.IO) {
            _isNewsLoading.value = true
            val loc = GeoLocationService.detectLocation()
            _userLocation.value = loc
            val articles = CyberNewsFeedService.fetchDailyMalwareNews(loc)
            _newsArticles.value = articles
            _isNewsLoading.value = false
        }
    }

    fun deleteThreat(report: ThreatReport) {
        viewModelScope.launch(Dispatchers.IO) {
            val app = getApplication<Application>()
            var fileDeleted = false
            val isInstalled = report.targetPath.contains("/data/app") || (!report.packageName.isNullOrBlank() && try {
                app.packageManager.getPackageInfo(report.packageName, 0)
                true
            } catch (_: Exception) { false })

            if (isInstalled && !report.packageName.isNullOrBlank()) {
                withContext(Dispatchers.Main) {
                    try {
                        val intent = Intent(Intent.ACTION_DELETE).apply {
                            data = Uri.parse("package:${report.packageName}")
                            flags = Intent.FLAG_ACTIVITY_NEW_TASK
                        }
                        app.startActivity(intent)
                        Toast.makeText(app, "Opening uninstaller for ${report.appName ?: report.targetName}...", Toast.LENGTH_SHORT).show()
                    } catch (_: Exception) {
                        Toast.makeText(app, "Could not launch system uninstaller", Toast.LENGTH_SHORT).show()
                    }
                }
            } else {
                try {
                    val file = File(report.targetPath)
                    if (file.exists()) {
                        fileDeleted = file.delete()
                    }
                } catch (_: Exception) {}

                withContext(Dispatchers.Main) {
                    val label = report.appName ?: report.targetName
                    if (fileDeleted) {
                        Toast.makeText(app, "✓ File deleted successfully: $label", Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(app, "✓ Removed from scan results: $label", Toast.LENGTH_SHORT).show()
                    }
                }
            }

            val current = _scansList.value.toMutableList()
            current.removeAll { it.targetPath == report.targetPath || it.sha256 == report.sha256 }
            _scansList.value = current
            _selectedReport.value = null
        }
    }

    fun deleteFile(path: String) {
        viewModelScope.launch(Dispatchers.IO) {
            val file = File(path)
            var deleted = false
            if (file.exists()) {
                deleted = file.delete()
            }
            val current = _scansList.value.toMutableList()
            current.removeAll { it.targetPath == path }
            _scansList.value = current
            _selectedReport.value = null

            withContext(Dispatchers.Main) {
                if (deleted) {
                    Toast.makeText(getApplication(), "✓ File deleted successfully", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(getApplication(), "✓ Threat removed from list", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    fun saveApiKeys(
        openai: String,
        claude: String,
        gemini: String,
        groq: String,
        vt: String,
        ha: String,
        kaspersky: String,
        metaDefender: String,
        filescan: String,
        bazaar: String = ""
    ) {
        val app = getApplication<Application>()
        ApiKeyVault.saveAllKeys(
            context = app,
            openai = openai,
            claude = claude,
            gemini = gemini,
            groq = groq,
            vt = vt,
            ha = ha,
            kaspersky = kaspersky,
            metaDefender = metaDefender,
            filescan = filescan,
            bazaar = bazaar
        )

        openAiKey.value = openai.trim()
        claudeKey.value = claude.trim()
        geminiKey.value = gemini.trim()
        groqKey.value = groq.trim()
        vtKey.value = vt.trim()
        haKey.value = ha.trim()
        kasperskyKey.value = kaspersky.trim()
        metaDefenderKey.value = metaDefender.trim()
        filescanKey.value = filescan.trim()
        bazaarKey.value = bazaar.trim()
    }

    fun saveSingleApiKey(provider: String, key: String) {
        val trimmed = key.trim()
        val app = getApplication<Application>()
        ApiKeyVault.saveSingleKey(app, provider, trimmed)

        when (provider.lowercase()) {
            "openai" -> openAiKey.value = trimmed
            "claude" -> claudeKey.value = trimmed
            "gemini" -> geminiKey.value = trimmed
            "groq" -> groqKey.value = trimmed
            "vt", "virustotal" -> vtKey.value = trimmed
            "ha", "hybridanalysis" -> haKey.value = trimmed
            "kaspersky" -> kasperskyKey.value = trimmed
            "metadefender" -> metaDefenderKey.value = trimmed
            "filescan" -> filescanKey.value = trimmed
            "bazaar", "malwarebazaar", "abusech" -> bazaarKey.value = trimmed
        }
    }

    fun exportApiKeys(): String {
        return ApiKeyVault.exportKeysJson(getApplication())
    }

    fun importApiKeys(jsonStr: String): Pair<Int, String> {
        val result = ApiKeyVault.importKeysJson(getApplication(), jsonStr)
        if (result.first > 0) {
            reloadKeysFromPrefs()
        }
        return result
    }

    fun reloadKeysFromPrefs() {
        openAiKey.value = prefs.getString("openai_key", "") ?: ""
        claudeKey.value = prefs.getString("claude_key", "") ?: ""
        geminiKey.value = prefs.getString("gemini_key", "") ?: ""
        groqKey.value = prefs.getString("groq_key", "") ?: ""
        vtKey.value = prefs.getString("vt_key", "") ?: ""
        haKey.value = prefs.getString("ha_key", "") ?: ""
        kasperskyKey.value = prefs.getString("kaspersky_key", "") ?: ""
        metaDefenderKey.value = prefs.getString("metadefender_key", "") ?: ""
        filescanKey.value = prefs.getString("filescan_key", "") ?: ""
        bazaarKey.value = prefs.getString("bazaar_key", "") ?: ""
    }

    private fun syncKeysToCoordinator() {
        ApiKeyVault.syncToCoordinator(getApplication())
    }
}

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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val prefs = application.getSharedPreferences("threatlens_prefs", Context.MODE_PRIVATE)

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
        syncKeysToCoordinator()

        viewModelScope.launch {
            RealtimeScanCoordinator.scanReports.collect { newReport ->
                val current = _scansList.value.toMutableList()
                current.removeAll { it.sha256 == newReport.sha256 }
                current.add(0, newReport)
                _scansList.value = current
            }
        }

        startShieldService()
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
        prefs.edit()
            .putString("openai_key", openai.trim())
            .putString("claude_key", claude.trim())
            .putString("gemini_key", gemini.trim())
            .putString("groq_key", groq.trim())
            .putString("vt_key", vt.trim())
            .putString("ha_key", ha.trim())
            .putString("kaspersky_key", kaspersky.trim())
            .putString("metadefender_key", metaDefender.trim())
            .putString("filescan_key", filescan.trim())
            .putString("bazaar_key", bazaar.trim())
            .apply()

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

        syncKeysToCoordinator()
    }

    fun saveSingleApiKey(provider: String, key: String) {
        val trimmed = key.trim()
        val prefKey = when (provider.lowercase()) {
            "openai" -> "openai_key"
            "claude" -> "claude_key"
            "gemini" -> "gemini_key"
            "groq" -> "groq_key"
            "vt", "virustotal" -> "vt_key"
            "ha", "hybridanalysis" -> "ha_key"
            "kaspersky" -> "kaspersky_key"
            "metadefender" -> "metadefender_key"
            "filescan" -> "filescan_key"
            "bazaar", "malwarebazaar", "abusech" -> "bazaar_key"
            else -> return
        }

        prefs.edit().putString(prefKey, trimmed).apply()

        when (provider.lowercase()) {
            "openai" -> { openAiKey.value = trimmed; RealtimeScanCoordinator.openAiKey = trimmed }
            "claude" -> { claudeKey.value = trimmed; RealtimeScanCoordinator.claudeKey = trimmed }
            "gemini" -> { geminiKey.value = trimmed; RealtimeScanCoordinator.geminiKey = trimmed }
            "groq" -> { groqKey.value = trimmed; RealtimeScanCoordinator.groqKey = trimmed }
            "vt", "virustotal" -> { vtKey.value = trimmed; RealtimeScanCoordinator.virusTotalKey = trimmed }
            "ha", "hybridanalysis" -> { haKey.value = trimmed; RealtimeScanCoordinator.hybridAnalysisKey = trimmed }
            "kaspersky" -> { kasperskyKey.value = trimmed; RealtimeScanCoordinator.kasperskyKey = trimmed }
            "metadefender" -> { metaDefenderKey.value = trimmed; RealtimeScanCoordinator.metaDefenderKey = trimmed }
            "filescan" -> { filescanKey.value = trimmed; RealtimeScanCoordinator.filescanKey = trimmed }
            "bazaar", "malwarebazaar", "abusech" -> { bazaarKey.value = trimmed; RealtimeScanCoordinator.bazaarKey = trimmed }
        }
    }

    private fun syncKeysToCoordinator() {
        RealtimeScanCoordinator.openAiKey = openAiKey.value
        RealtimeScanCoordinator.claudeKey = claudeKey.value
        RealtimeScanCoordinator.geminiKey = geminiKey.value
        RealtimeScanCoordinator.groqKey = groqKey.value
        RealtimeScanCoordinator.virusTotalKey = vtKey.value
        RealtimeScanCoordinator.hybridAnalysisKey = haKey.value
        RealtimeScanCoordinator.kasperskyKey = kasperskyKey.value
        RealtimeScanCoordinator.metaDefenderKey = metaDefenderKey.value
        RealtimeScanCoordinator.filescanKey = filescanKey.value
        RealtimeScanCoordinator.bazaarKey = bazaarKey.value
    }
}

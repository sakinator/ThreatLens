package io.threatlens.ui.viewmodel

import android.app.Application
import android.content.Context
import android.content.Intent
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

    fun deleteFile(path: String) {
        viewModelScope.launch(Dispatchers.IO) {
            val file = File(path)
            if (file.exists()) {
                file.delete()
            }
            val current = _scansList.value.toMutableList()
            current.removeAll { it.targetPath == path }
            _scansList.value = current
            _selectedReport.value = null
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
        filescan: String
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

        syncKeysToCoordinator()
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
    }
}

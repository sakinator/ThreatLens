package io.threatlens.ui.viewmodel

import android.app.Application
import android.content.Context
import android.content.Intent
import android.os.Environment
import androidx.core.content.ContextCompat
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.threatlens.core.model.ThreatReport
import io.threatlens.core.model.ThreatSeverity
import io.threatlens.core.realtime.RealtimeDownloadShieldService
import io.threatlens.core.realtime.RealtimeScanCoordinator
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

    private val _isScanning = MutableStateFlow(false)
    val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()

    // API Keys state
    val geminiKey = MutableStateFlow(prefs.getString("gemini_key", "") ?: "")
    val groqKey = MutableStateFlow(prefs.getString("groq_key", "") ?: "")
    val vtKey = MutableStateFlow(prefs.getString("vt_key", "") ?: "")
    val haKey = MutableStateFlow(prefs.getString("ha_key", "") ?: "")
    val kasperskyKey = MutableStateFlow(prefs.getString("kaspersky_key", "") ?: "")

    init {
        // Hydrate API keys into RealtimeScanCoordinator
        syncKeysToCoordinator()

        // Listen for live background scan events
        viewModelScope.launch {
            RealtimeScanCoordinator.scanReports.collect { newReport ->
                val current = _scansList.value.toMutableList()
                current.removeAll { it.sha256 == newReport.sha256 }
                current.add(0, newReport)
                _scansList.value = current
            }
        }

        // Start shield service by default
        startShieldService()
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

    fun scanDownloadFolder() {
        viewModelScope.launch(Dispatchers.IO) {
            _isScanning.value = true
            val downloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            if (downloads.exists() && downloads.isDirectory) {
                val files = downloads.listFiles { f ->
                    val ext = f.extension.lowercase()
                    ext in listOf("apk", "dex", "jar", "bin")
                } ?: emptyArray()

                for (file in files) {
                    RealtimeScanCoordinator.scanFileAsync(getApplication(), file)
                }
            }
            _isScanning.value = false
        }
    }

    fun simulateMalwareIntercept() {
        viewModelScope.launch(Dispatchers.IO) {
            val dummyReport = ThreatReport(
                targetName = "Free_Crypto_Miner_Mod.apk",
                targetPath = "/sdcard/Download/Free_Crypto_Miner_Mod.apk",
                sha256 = "3a6f44d8c6b75f9227181c009bdc8c1873130d2105aa0a6c085fc5794a37b089",
                fileSize = 14200000L,
                localScore = 85,
                cloudScore = 100,
                finalScore = 95,
                severity = ThreatSeverity.MALICIOUS,
                threatFamily = "Trojan-Banker.AndroidOS.Cerberus",
                detectedBehaviors = listOf(
                    "Injects malicious overlay screens over banking & wallet apps",
                    "Monitors and steals 2-Factor Authentication SMS codes",
                    "Requests Accessibility Service to capture screen touches & keystrokes"
                ),
                dangerousPermissions = listOf(
                    "BIND_ACCESSIBILITY_SERVICE",
                    "SYSTEM_ALERT_WINDOW",
                    "RECEIVE_SMS",
                    "INTERNET"
                ),
                cloudEnginesFlagged = 42,
                cloudEnginesTotal = 71,
                cloudSources = listOf("MalwareBazaar (Abuse.ch)", "VirusTotal (42/71)"),
                aiExplanation = "🚨 **What is this?** This is Cerberus, a notorious Android banking trojan that disguises itself as a legit utility.\n\n⚠️ **What can it cause?**\n• Steals bank login credentials and credit card numbers.\n• Intercepts one-time SMS verification passwords (OTPs).\n• Can remotely control your screen.\n\n🛡️ **What to do:** Delete and uninstall this application immediately!"
            )
            val current = _scansList.value.toMutableList()
            current.add(0, dummyReport)
            _scansList.value = current
            _selectedReport.value = dummyReport
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

    fun saveApiKeys(gemini: String, groq: String, vt: String, ha: String, kaspersky: String) {
        prefs.edit()
            .putString("gemini_key", gemini.trim())
            .putString("groq_key", groq.trim())
            .putString("vt_key", vt.trim())
            .putString("ha_key", ha.trim())
            .putString("kaspersky_key", kaspersky.trim())
            .apply()

        geminiKey.value = gemini.trim()
        groqKey.value = groq.trim()
        vtKey.value = vt.trim()
        haKey.value = ha.trim()
        kasperskyKey.value = kaspersky.trim()

        syncKeysToCoordinator()
    }

    private fun syncKeysToCoordinator() {
        RealtimeScanCoordinator.geminiKey = geminiKey.value
        RealtimeScanCoordinator.groqKey = groqKey.value
        RealtimeScanCoordinator.virusTotalKey = vtKey.value
        RealtimeScanCoordinator.hybridAnalysisKey = haKey.value
        RealtimeScanCoordinator.kasperskyKey = kasperskyKey.value
    }
}

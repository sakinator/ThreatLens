package io.threatlens.core.realtime

import android.content.Context
import io.threatlens.core.ai.ThreatAiExplainer
import io.threatlens.core.cloud.CloudAggregatedVerdict
import io.threatlens.core.cloud.CloudThreatAggregator
import io.threatlens.core.local.HashUtil
import io.threatlens.core.local.LocalSignatureDatabase
import io.threatlens.core.local.ManifestHeuristicEngine
import io.threatlens.core.model.ThreatReport
import io.threatlens.core.model.ThreatSeverity
import io.threatlens.core.scoring.HybridThreatScorer
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import java.io.File

object RealtimeScanCoordinator {

    private val scanScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private val _scanReports = MutableSharedFlow<ThreatReport>(replay = 50)
    val scanReports = _scanReports.asSharedFlow()

    // Configurable API keys
    var virusTotalKey: String? = null
    var hybridAnalysisKey: String? = null
    var kasperskyKey: String? = null
    var metaDefenderKey: String? = null
    var filescanKey: String? = null
    var geminiKey: String? = null
    var groqKey: String? = null

    fun scanFileAsync(context: Context, file: File, onComplete: ((ThreatReport) -> Unit)? = null) {
        if (!file.exists() || !file.canRead()) return

        val extension = file.extension
        if (!ScanThrottleManager.shouldScanFile(file.absolutePath, extension)) {
            return
        }

        scanScope.launch {
            val report = performScan(context, file)
            _scanReports.emit(report)

            if (report.severity == ThreatSeverity.MALICIOUS || report.severity == ThreatSeverity.HIGH_RISK || report.severity == ThreatSeverity.SUSPICIOUS) {
                ThreatNotificationManager.showThreatAlert(context, report)
            }

            withContext(Dispatchers.Main) {
                onComplete?.invoke(report)
            }
        }
    }

    suspend fun performScan(context: Context, file: File): ThreatReport = withContext(Dispatchers.IO) {
        // 1. Calculate SHA-256
        val sha256 = HashUtil.sha256(file)

        // 2. Check LRU deduplication cache (Zero battery / Zero CPU)
        ScanThrottleManager.getCachedReport(sha256)?.let { return@withContext it }

        // 3. Local Signature Check (Offline instant lookup)
        val localSig = LocalSignatureDatabase.lookup(sha256)

        // 4. Manifest & Permission Heuristics (if APK)
        val isApk = file.extension.equals("apk", ignoreCase = true)
        val heuristicResult = if (isApk) {
            ManifestHeuristicEngine.analyzeApk(context, file)
        } else null

        // 5. Cloud Intelligence Aggregation (MalwareBazaar + VT + HA + Kaspersky + MetaDefender + Filescan)
        val cloudAggregator = CloudThreatAggregator(
            vtApiKey = virusTotalKey,
            haApiKey = hybridAnalysisKey,
            kasperskyKey = kasperskyKey,
            metaDefenderKey = metaDefenderKey,
            filescanKey = filescanKey
        )
        val cloudVerdict = cloudAggregator.inspectHash(sha256)

        // 6. Compute Hybrid Weighted Threat Score (0 - 100)
        val scoreBreakdown = HybridThreatScorer.calculate(
            sha256 = sha256,
            localSig = localSig,
            heuristic = heuristicResult,
            cloudVerdict = cloudVerdict
        )

        // 7. Free AI Threat Explainer (Gemini / Groq / Fallback)
        var aiExplanation: String? = null
        if (scoreBreakdown.severity != ThreatSeverity.SAFE) {
            val explainer = ThreatAiExplainer(
                geminiApiKey = geminiKey,
                groqApiKey = groqKey
            )
            aiExplanation = explainer.getExplanation(
                targetName = file.name,
                threatFamily = scoreBreakdown.primaryFamily,
                behaviors = scoreBreakdown.reasons,
                permissions = heuristicResult?.dangerousPermissions ?: emptyList()
            )
        }

        val finalReport = ThreatReport(
            targetName = file.name,
            targetPath = file.absolutePath,
            sha256 = sha256,
            fileSize = file.length(),
            isApk = isApk,
            localScore = heuristicResult?.score ?: 0,
            cloudScore = cloudVerdict.cloudScore,
            finalScore = scoreBreakdown.finalScore,
            severity = scoreBreakdown.severity,
            threatFamily = scoreBreakdown.primaryFamily,
            detectedBehaviors = scoreBreakdown.reasons,
            dangerousPermissions = heuristicResult?.dangerousPermissions ?: emptyList(),
            cloudEnginesFlagged = cloudVerdict.enginesFlagged,
            cloudEnginesTotal = cloudVerdict.totalEngines,
            cloudSources = cloudVerdict.sources,
            aiExplanation = aiExplanation
        )

        ScanThrottleManager.cacheReport(finalReport)
        finalReport
    }
}

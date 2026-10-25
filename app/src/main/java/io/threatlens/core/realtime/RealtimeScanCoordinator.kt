package io.threatlens.core.realtime

import android.content.Context
import io.threatlens.core.ai.ThreatAiExplainer
import io.threatlens.core.cloud.*
import io.threatlens.core.local.HashUtil
import io.threatlens.core.local.LocalSignatureDatabase
import io.threatlens.core.local.ManifestHeuristicEngine
import io.threatlens.core.model.ThreatReport
import io.threatlens.core.model.ThreatSeverity
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
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
    
    // AI Explainer keys
    var openAiKey: String? = null
    var claudeKey: String? = null
    var geminiKey: String? = null
    var groqKey: String? = null

    fun scanFileAsync(context: Context, file: File) {
        if (!file.exists() || !file.canRead()) return

        val extension = file.extension
        if (!ScanThrottleManager.shouldScanFile(file.absolutePath, extension)) {
            return
        }

        scanScope.launch {
            streamScan(context, file)
        }
    }

    suspend fun streamScan(context: Context, file: File) = withContext(Dispatchers.IO) {
        // 1. Calculate SHA-256
        val sha256 = HashUtil.sha256(file)

        // 2. Check LRU Cache (Instant 0ms hit)
        ScanThrottleManager.getCachedReport(sha256)?.let { cached ->
            _scanReports.emit(cached)
            return@withContext
        }

        val isApk = file.extension.equals("apk", ignoreCase = true)

        // 3. Local Phase (Instant on-device analysis)
        val localSig = LocalSignatureDatabase.lookup(sha256)
        val heuristicResult = if (isApk) {
            ManifestHeuristicEngine.analyzeApk(context, file)
        } else null

        // Determine list of pending cloud engines based on configuration
        val pendingEngines = mutableListOf<String>("MalwareBazaar")
        if (!virusTotalKey.isNullOrBlank()) pendingEngines.add("VirusTotal")
        if (!metaDefenderKey.isNullOrBlank()) pendingEngines.add("MetaDefender")
        if (!hybridAnalysisKey.isNullOrBlank()) pendingEngines.add("Hybrid Analysis")
        if (!kasperskyKey.isNullOrBlank()) pendingEngines.add("Kaspersky OpenTIP")
        if (!filescanKey.isNullOrBlank()) pendingEngines.add("Filescan.io")

        // Initial running calculation from local signals
        var runningLocalScore = heuristicResult?.score ?: 0
        var runningCloudScore = 0
        var highestSeverity = when {
            localSig != null -> ThreatSeverity.MALICIOUS
            runningLocalScore >= 75 -> ThreatSeverity.MALICIOUS
            runningLocalScore >= 50 -> ThreatSeverity.HIGH_RISK
            runningLocalScore >= 25 -> ThreatSeverity.SUSPICIOUS
            else -> ThreatSeverity.SAFE
        }
        var runningFamily = localSig?.family ?: if (runningLocalScore >= 25) "Heuristic.Suspicious" else "Clean"
        val runningSources = mutableListOf<String>()
        var flaggedEnginesCount = 0
        var totalEnginesCount = 0

        var currentReport = ThreatReport(
            targetName = file.name,
            targetPath = file.absolutePath,
            sha256 = sha256,
            fileSize = file.length(),
            isApk = isApk,
            localScore = runningLocalScore,
            cloudScore = 0,
            currentScore = if (localSig != null) 100 else runningLocalScore,
            severity = highestSeverity,
            threatFamily = runningFamily,
            detectedBehaviors = heuristicResult?.suspiciousBehaviors ?: emptyList(),
            dangerousPermissions = heuristicResult?.dangerousPermissions ?: emptyList(),
            cloudSources = emptyList(),
            isFinal = false,
            pendingEngines = pendingEngines.toList(),
            statusMessage = "⚡ Local analysis complete (${runningLocalScore}/100). Querying ${pendingEngines.size} cloud engines..."
        )

        // EMIT IMMEDIATE RESULT (UI updates in <20ms!)
        _scanReports.emit(currentReport)

        if (localSig != null) {
            ThreatNotificationManager.showThreatAlert(context, currentReport)
        }

        // 4. Progressive Cloud Engine Querying
        val reportMutex = Mutex()
        val engineJobs = mutableListOf<Job>()

        suspend fun onEngineFinished(
            engineName: String,
            score: Int,
            flagged: Int,
            total: Int,
            sourceLabel: String,
            family: String?
        ) {
            reportMutex.withLock {
                pendingEngines.remove(engineName)
                if (score > runningCloudScore) {
                    runningCloudScore = score
                }
                flaggedEnginesCount += flagged
                totalEnginesCount += total
                runningSources.add(sourceLabel)
                if (family != null && (runningFamily == "Clean" || runningFamily.startsWith("Heuristic."))) {
                    runningFamily = family
                }

                val weighted = if (localSig != null) 100 else {
                    ((runningLocalScore * 0.45) + (runningCloudScore * 0.55)).toInt().coerceIn(0, 100)
                }

                highestSeverity = when {
                    weighted >= 75 -> ThreatSeverity.MALICIOUS
                    weighted >= 50 -> ThreatSeverity.HIGH_RISK
                    weighted >= 25 -> ThreatSeverity.SUSPICIOUS
                    else -> ThreatSeverity.SAFE
                }

                val status = if (pendingEngines.isEmpty()) {
                    "✓ Cloud inspection complete."
                } else {
                    "Pending (${pendingEngines.size}): ${pendingEngines.joinToString(", ")}"
                }

                currentReport = currentReport.copy(
                    cloudScore = runningCloudScore,
                    currentScore = weighted,
                    severity = highestSeverity,
                    threatFamily = runningFamily,
                    cloudEnginesFlagged = flaggedEnginesCount,
                    cloudEnginesTotal = totalEnginesCount,
                    cloudSources = runningSources.toList(),
                    pendingEngines = pendingEngines.toList(),
                    statusMessage = status
                )

                _scanReports.emit(currentReport)
            }
        }

        // Launch MalwareBazaar
        engineJobs.add(scanScope.launch {
            val bazaar = MalwareBazaarProvider.queryHash(sha256)
            if (bazaar != null && bazaar.isMalicious) {
                onEngineFinished(
                    "MalwareBazaar",
                    score = 95,
                    flagged = 1,
                    total = 1,
                    sourceLabel = "MalwareBazaar (Abuse.ch)",
                    family = bazaar.signature
                )
            } else {
                reportMutex.withLock { pendingEngines.remove("MalwareBazaar") }
            }
        })

        // Launch VirusTotal
        if (!virusTotalKey.isNullOrBlank()) {
            engineJobs.add(scanScope.launch {
                val vt = VirusTotalProvider.queryHash(sha256, virusTotalKey!!)
                if (vt != null && vt.totalEngines > 0) {
                    val score = if (vt.maliciousCount >= 4) 100 else if (vt.maliciousCount >= 1) 45 else 0
                    onEngineFinished(
                        "VirusTotal",
                        score = score,
                        flagged = vt.maliciousCount,
                        total = vt.totalEngines,
                        sourceLabel = "VirusTotal (${vt.maliciousCount}/${vt.totalEngines})",
                        family = vt.suggestedThreatLabel
                    )
                } else {
                    reportMutex.withLock { pendingEngines.remove("VirusTotal") }
                }
            })
        }

        // Launch MetaDefender
        if (!metaDefenderKey.isNullOrBlank()) {
            engineJobs.add(scanScope.launch {
                val md = MetaDefenderProvider.queryHash(sha256, metaDefenderKey!!)
                if (md != null && md.totalEngines > 0) {
                    val score = if (md.enginesFlagged >= 3) 95 else if (md.threatFound) 40 else 0
                    onEngineFinished(
                        "MetaDefender",
                        score = score,
                        flagged = md.enginesFlagged,
                        total = md.totalEngines,
                        sourceLabel = "MetaDefender (${md.enginesFlagged}/${md.totalEngines})",
                        family = md.threatName
                    )
                } else {
                    reportMutex.withLock { pendingEngines.remove("MetaDefender") }
                }
            })
        }

        // Launch Hybrid Analysis
        if (!hybridAnalysisKey.isNullOrBlank()) {
            engineJobs.add(scanScope.launch {
                val ha = HybridAnalysisProvider.queryHash(sha256, hybridAnalysisKey!!)
                if (ha != null) {
                    onEngineFinished(
                        "Hybrid Analysis",
                        score = ha.threatScore,
                        flagged = if (ha.threatScore >= 50) 1 else 0,
                        total = 1,
                        sourceLabel = "Hybrid Analysis (${ha.threatScore}/100)",
                        family = ha.vxFamily
                    )
                } else {
                    reportMutex.withLock { pendingEngines.remove("Hybrid Analysis") }
                }
            })
        }

        // Launch Kaspersky OpenTIP
        if (!kasperskyKey.isNullOrBlank()) {
            engineJobs.add(scanScope.launch {
                val kas = KasperskyOpenTipProvider.queryHash(sha256, kasperskyKey!!)
                if (kas != null) {
                    val score = if (kas.zone.equals("Red", ignoreCase = true)) 100 else if (kas.zone.equals("Yellow", ignoreCase = true)) 60 else 0
                    onEngineFinished(
                        "Kaspersky OpenTIP",
                        score = score,
                        flagged = if (score > 0) 1 else 0,
                        total = 1,
                        sourceLabel = "Kaspersky (${kas.zone})",
                        family = kas.threatFamily
                    )
                } else {
                    reportMutex.withLock { pendingEngines.remove("Kaspersky OpenTIP") }
                }
            })
        }

        // Launch Filescan.io
        if (!filescanKey.isNullOrBlank()) {
            engineJobs.add(scanScope.launch {
                val fs = FilescanProvider.queryHash(sha256, filescanKey!!)
                if (fs != null) {
                    onEngineFinished(
                        "Filescan.io",
                        score = fs.threatScore,
                        flagged = if (fs.threatScore >= 50) 1 else 0,
                        total = 1,
                        sourceLabel = "Filescan.io (${fs.verdict})",
                        family = null
                    )
                } else {
                    reportMutex.withLock { pendingEngines.remove("Filescan.io") }
                }
            })
        }

        // Wait for cloud engines with 6 second timeout
        withTimeoutOrNull(6000L) {
            engineJobs.joinAll()
        }

        // 5. AI Threat Explainer (OpenAI / Claude / Gemini / Groq)
        var aiExplanation: String? = null
        if (currentReport.severity != ThreatSeverity.SAFE) {
            val aiProviderName = when {
                !openAiKey.isNullOrBlank() -> "ChatGPT (GPT-4o-mini)"
                !claudeKey.isNullOrBlank() -> "Claude 3.5 Haiku"
                !geminiKey.isNullOrBlank() -> "Google Gemini Flash"
                !groqKey.isNullOrBlank() -> "Groq (Llama-3)"
                else -> "ThreatLens AI Engine"
            }
            currentReport = currentReport.copy(statusMessage = "🤖 Generating threat brief with $aiProviderName...")
            _scanReports.emit(currentReport)

            val explainer = ThreatAiExplainer(
                openAiKey = openAiKey,
                claudeKey = claudeKey,
                geminiApiKey = geminiKey,
                groqApiKey = groqKey
            )
            aiExplanation = explainer.getExplanation(
                targetName = file.name,
                threatFamily = currentReport.threatFamily,
                behaviors = currentReport.detectedBehaviors,
                permissions = currentReport.dangerousPermissions
            )
        }

        // 6. Final Result
        val finalReport = currentReport.copy(
            isFinal = true,
            pendingEngines = emptyList(),
            aiExplanation = aiExplanation,
            statusMessage = "✓ Scan Complete • Final Score: ${currentReport.currentScore}/100"
        )

        ScanThrottleManager.cacheReport(finalReport)
        _scanReports.emit(finalReport)

        if (finalReport.severity == ThreatSeverity.MALICIOUS || finalReport.severity == ThreatSeverity.HIGH_RISK) {
            ThreatNotificationManager.showThreatAlert(context, finalReport)
        }
        return@withContext finalReport
    }

    suspend fun performScan(context: Context, file: File): ThreatReport {
        return streamScan(context, file)
    }
}

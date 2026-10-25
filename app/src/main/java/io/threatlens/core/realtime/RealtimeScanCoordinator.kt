package io.threatlens.core.realtime

import android.content.Context
import io.threatlens.core.ai.ThreatAiExplainer
import io.threatlens.core.cloud.*
import io.threatlens.core.local.HashUtil
import io.threatlens.core.local.LocalAntivirusEngine
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

        // Check if file path is explicitly excluded in Antivirus Exclusions
        if (io.threatlens.core.exclusions.ExclusionManager.isPathExcluded(file.absolutePath)) {
            return
        }

        scanScope.launch {
            streamScan(context, file)
        }
    }

    suspend fun streamScan(
        context: Context,
        file: File,
        customAppName: String? = null,
        customPackageName: String? = null
    ): ThreatReport = withContext(Dispatchers.IO) {
        // Resolve application name and package identity
        var appName = customAppName
        var packageName = customPackageName

        if (appName.isNullOrBlank() || packageName.isNullOrBlank()) {
            if (file.extension.equals("apk", ignoreCase = true)) {
                try {
                    val pkgInfo = context.packageManager.getPackageArchiveInfo(file.absolutePath, 0)
                    if (pkgInfo != null) {
                        if (packageName.isNullOrBlank()) {
                            packageName = pkgInfo.packageName
                        }
                        pkgInfo.applicationInfo.sourceDir = file.absolutePath
                        pkgInfo.applicationInfo.publicSourceDir = file.absolutePath
                        val label = context.packageManager.getApplicationLabel(pkgInfo.applicationInfo).toString()
                        if (appName.isNullOrBlank() && label.isNotBlank()) {
                            appName = label
                        }
                    }
                } catch (_: Exception) {}
            }
        }

        if ((appName.isNullOrBlank() || packageName.isNullOrBlank()) && file.name.equals("base.apk", ignoreCase = true)) {
            try {
                val installed = context.packageManager.getInstalledApplications(0)
                val match = installed.firstOrNull { it.publicSourceDir == file.absolutePath || it.sourceDir == file.absolutePath }
                if (match != null) {
                    if (packageName.isNullOrBlank()) packageName = match.packageName
                    if (appName.isNullOrBlank()) appName = context.packageManager.getApplicationLabel(match).toString()
                }
            } catch (_: Exception) {}
        }

        val resolvedAppName = if (!appName.isNullOrBlank()) appName else if (!packageName.isNullOrBlank()) packageName else file.name

        // 1. Calculate SHA-256
        val sha256 = HashUtil.sha256(file)

        // Check if SHA-256 hash is explicitly whitelisted in Antivirus Exclusions
        if (io.threatlens.core.exclusions.ExclusionManager.isHashExcluded(sha256)) {
            val safeReport = ThreatReport(
                targetName = file.name,
                targetPath = file.absolutePath,
                appName = resolvedAppName,
                packageName = packageName,
                sha256 = sha256,
                severity = ThreatSeverity.SAFE,
                currentScore = 0,
                threatScore = 0,
                threatFamily = "Whitelisted Clean",
                aiExplanation = "This file is explicitly whitelisted in ThreatLens Antivirus Exclusions.",
                contributingEngines = listOf("ThreatLens Exclusions"),
                engineVerdictMap = mapOf("Exclusions" to "Whitelisted")
            )
            _scanReports.emit(safeReport)
            return@withContext safeReport
        }

        // 2. Check LRU Cache (Instant 0ms hit)
        ScanThrottleManager.getCachedReport(sha256)?.let { cached ->
            _scanReports.emit(cached)
            return@withContext cached
        }

        val isApk = file.extension.equals("apk", ignoreCase = true)

        // 3. Local Phase: 100% Free Autonomous On-Device Engine (0ms latency, zero internet required)
        val localVerdict = LocalAntivirusEngine.scan(context, file, sha256)
        val runningLocalScore = localVerdict.localScore
        var runningFamily = localVerdict.threatFamily
        val runningSources = mutableListOf<String>().apply { addAll(localVerdict.engineSources) }
        val successfulEngines = mutableListOf<String>()
        val failedEngines = mutableListOf<String>()

        var runningCloudScore = 0
        var highestSeverity = when {
            localVerdict.isMalicious || runningLocalScore >= 75 -> ThreatSeverity.MALICIOUS
            runningLocalScore >= 50 -> ThreatSeverity.HIGH_RISK
            runningLocalScore >= 25 -> ThreatSeverity.SUSPICIOUS
            else -> ThreatSeverity.SAFE
        }

        // Determine list of pending cloud engines based on configuration
        val pendingEngines = mutableListOf<String>("MalwareBazaar")
        if (!virusTotalKey.isNullOrBlank()) pendingEngines.add("VirusTotal")
        if (!metaDefenderKey.isNullOrBlank()) pendingEngines.add("MetaDefender")
        if (!hybridAnalysisKey.isNullOrBlank()) pendingEngines.add("Hybrid Analysis")
        if (!kasperskyKey.isNullOrBlank()) pendingEngines.add("Kaspersky OpenTIP")
        if (!filescanKey.isNullOrBlank()) pendingEngines.add("Filescan.io")

        val engineVerdictMap = mutableMapOf<String, String>()
        engineVerdictMap["ThreatLens Local Engine"] = if (localVerdict.isMalicious) {
            "Flagged: ${localVerdict.threatFamily} (${localVerdict.detectedBehaviors.size} patterns)"
        } else if (runningLocalScore > 0) {
            "Suspicious: Score $runningLocalScore/100"
        } else {
            "Clean: 0 malicious patterns detected"
        }

        if (virusTotalKey.isNullOrBlank()) engineVerdictMap["VirusTotal"] = "Key Not Configured (Optional)"
        if (metaDefenderKey.isNullOrBlank()) engineVerdictMap["MetaDefender"] = "Key Not Configured (Optional)"
        if (hybridAnalysisKey.isNullOrBlank()) engineVerdictMap["Hybrid Analysis"] = "Key Not Configured (Optional)"
        if (kasperskyKey.isNullOrBlank()) engineVerdictMap["Kaspersky OpenTIP"] = "Key Not Configured (Optional)"
        if (filescanKey.isNullOrBlank()) engineVerdictMap["Filescan.io"] = "Key Not Configured (Optional)"

        var flaggedEnginesCount = 0
        var totalEnginesCount = 0

        var currentReport = ThreatReport(
            targetName = file.name,
            targetPath = file.absolutePath,
            appName = resolvedAppName,
            packageName = packageName,
            sha256 = sha256,
            fileSize = file.length(),
            isApk = isApk,
            localScore = runningLocalScore,
            cloudScore = 0,
            currentScore = runningLocalScore,
            severity = highestSeverity,
            threatFamily = runningFamily,
            detectedBehaviors = localVerdict.detectedBehaviors,
            dangerousPermissions = localVerdict.dangerousPermissions,
            cloudSources = emptyList(),
            failedEngines = emptyList(),
            successfulEngines = emptyList(),
            engineVerdictMap = engineVerdictMap.toMap(),
            isOfflineMode = false,
            isFinal = false,
            pendingEngines = pendingEngines.toList(),
            statusMessage = if (pendingEngines.isNotEmpty()) "⚡ Querying ${pendingEngines.size} threat intelligence engines..." else "🛡️ Analyzed via ThreatLens On-Device Security Engine"
        )

        // EMIT IMMEDIATE LOCAL RESULT (UI updates in <20ms!)
        _scanReports.emit(currentReport)

        if (localVerdict.isMalicious) {
            ThreatNotificationManager.showThreatAlert(context, currentReport)
        }

        // 4. Progressive Cloud Engine Querying with API Failure Mitigation
        val reportMutex = Mutex()
        val engineJobs = mutableListOf<Job>()

        suspend fun updateVerdict(statusText: String) {
            val weighted = if (localVerdict.isMalicious || runningLocalScore >= 75) {
                // Severe on-device finding: NEVER diluted or crushed by cloud errors
                maxOf(runningLocalScore, runningCloudScore)
            } else if (successfulEngines.isEmpty()) {
                // When offline or all cloud APIs fail: Local engine is 100% authoritative!
                runningLocalScore
            } else if (totalEnginesCount >= 25 && flaggedEnginesCount == 0 && runningLocalScore < 60) {
                // Cloud verified safe: mitigates mild false positive heuristic noise
                (runningLocalScore * 0.35).toInt()
            } else {
                // Balanced hybrid fusion between local signals and successful cloud engines
                maxOf(runningLocalScore, ((runningLocalScore * 0.40) + (runningCloudScore * 0.60)).toInt())
            }.coerceIn(0, 100)

            highestSeverity = when {
                weighted >= 75 -> ThreatSeverity.MALICIOUS
                weighted >= 50 -> ThreatSeverity.HIGH_RISK
                weighted >= 25 -> ThreatSeverity.SUSPICIOUS
                else -> ThreatSeverity.SAFE
            }

            currentReport = currentReport.copy(
                cloudScore = runningCloudScore,
                currentScore = weighted,
                severity = highestSeverity,
                threatFamily = runningFamily,
                cloudEnginesFlagged = flaggedEnginesCount,
                cloudEnginesTotal = totalEnginesCount,
                cloudSources = runningSources.toList(),
                failedEngines = failedEngines.toList(),
                successfulEngines = successfulEngines.toList(),
                engineVerdictMap = engineVerdictMap.toMap(),
                isOfflineMode = successfulEngines.isEmpty(),
                pendingEngines = pendingEngines.toList(),
                statusMessage = statusText
            )
            _scanReports.emit(currentReport)
        }

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
                successfulEngines.add(engineName)
                engineVerdictMap[engineName] = if (flagged > 0) {
                    "Flagged: ${family ?: "$flagged/$total detections"}"
                } else if (total > 0) {
                    "Clean (0/$total engines flagged)"
                } else {
                    "Clean (Verified safe)"
                }

                if (score > runningCloudScore) {
                    runningCloudScore = score
                }
                flaggedEnginesCount += flagged
                totalEnginesCount += total
                runningSources.add(sourceLabel)
                if (family != null && (runningFamily == "Clean" || runningFamily.startsWith("Heuristic."))) {
                    runningFamily = family
                }

                val status = if (pendingEngines.isEmpty()) {
                    "✓ Cloud inspection complete."
                } else {
                    "Pending (${pendingEngines.size}): ${pendingEngines.joinToString(", ")}"
                }

                updateVerdict(status)
            }
        }

        suspend fun onEngineFailed(engineName: String) {
            reportMutex.withLock {
                pendingEngines.remove(engineName)
                failedEngines.add(engineName)
                engineVerdictMap[engineName] = "Unreachable (Timeout / Offline)"

                val status = if (pendingEngines.isEmpty()) {
                    if (successfulEngines.isEmpty()) {
                        "🛡️ Protected by On-Device Local Engine (Cloud APIs unreachable)"
                    } else {
                        "✓ Inspection complete (${failedEngines.size} cloud engines offline)"
                    }
                } else {
                    "Pending (${pendingEngines.size}): ${pendingEngines.joinToString(", ")}"
                }

                updateVerdict(status)
            }
        }

        // Launch MalwareBazaar (Free Abuse.ch lookup)
        engineJobs.add(scanScope.launch {
            try {
                val bazaar = MalwareBazaarProvider.queryHash(sha256)
                if (bazaar != null) {
                    if (bazaar.isMalicious) {
                        onEngineFinished(
                            "MalwareBazaar",
                            score = 95,
                            flagged = 1,
                            total = 1,
                            sourceLabel = "MalwareBazaar (Abuse.ch)",
                            family = bazaar.signature
                        )
                    } else {
                        onEngineFinished(
                            "MalwareBazaar",
                            score = 0,
                            flagged = 0,
                            total = 1,
                            sourceLabel = "MalwareBazaar (Clean)",
                            family = null
                        )
                    }
                } else {
                    onEngineFailed("MalwareBazaar")
                }
            } catch (_: Exception) {
                onEngineFailed("MalwareBazaar")
            }
        })

        // Launch VirusTotal
        if (!virusTotalKey.isNullOrBlank()) {
            engineJobs.add(scanScope.launch {
                try {
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
                    } else if (vt != null) {
                        onEngineFinished(
                            "VirusTotal",
                            score = 0,
                            flagged = 0,
                            total = 0,
                            sourceLabel = "VirusTotal (Unindexed)",
                            family = null
                        )
                    } else {
                        onEngineFailed("VirusTotal")
                    }
                } catch (_: Exception) {
                    onEngineFailed("VirusTotal")
                }
            })
        }

        // Launch MetaDefender
        if (!metaDefenderKey.isNullOrBlank()) {
            engineJobs.add(scanScope.launch {
                try {
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
                    } else if (md != null) {
                        onEngineFinished(
                            "MetaDefender",
                            score = 0,
                            flagged = 0,
                            total = 0,
                            sourceLabel = "MetaDefender (Clean)",
                            family = null
                        )
                    } else {
                        onEngineFailed("MetaDefender")
                    }
                } catch (_: Exception) {
                    onEngineFailed("MetaDefender")
                }
            })
        }

        // Launch Hybrid Analysis
        if (!hybridAnalysisKey.isNullOrBlank()) {
            engineJobs.add(scanScope.launch {
                try {
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
                        onEngineFailed("Hybrid Analysis")
                    }
                } catch (_: Exception) {
                    onEngineFailed("Hybrid Analysis")
                }
            })
        }

        // Launch Kaspersky OpenTIP
        if (!kasperskyKey.isNullOrBlank()) {
            engineJobs.add(scanScope.launch {
                try {
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
                        onEngineFailed("Kaspersky OpenTIP")
                    }
                } catch (_: Exception) {
                    onEngineFailed("Kaspersky OpenTIP")
                }
            })
        }

        // Launch Filescan.io
        if (!filescanKey.isNullOrBlank()) {
            engineJobs.add(scanScope.launch {
                try {
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
                        onEngineFailed("Filescan.io")
                    }
                } catch (_: Exception) {
                    onEngineFailed("Filescan.io")
                }
            })
        }

        // Wait for cloud engines with 5 second timeout
        withTimeoutOrNull(5000L) {
            engineJobs.joinAll()
        }

        // Handle any pending engines that timed out
        reportMutex.withLock {
            if (pendingEngines.isNotEmpty()) {
                failedEngines.addAll(pendingEngines)
                pendingEngines.clear()
            }
        }

        // 5. AI Threat Explainer (with Instant Offline Fallback)
        var aiExplanation: String? = null
        if (currentReport.severity != ThreatSeverity.SAFE) {
            val hasCustomKey = !openAiKey.isNullOrBlank() || !claudeKey.isNullOrBlank() || !geminiKey.isNullOrBlank() || !groqKey.isNullOrBlank()
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

        // 6. Final Result Formulation
        val finalStatus = when {
            successfulEngines.isNotEmpty() ->
                "✓ Multi-Engine Scan Complete (${successfulEngines.joinToString(", ")}) • Score: ${currentReport.currentScore}/100"
            failedEngines.isNotEmpty() ->
                "🛡️ On-Device Analysis Complete (Cloud APIs unreachable) • Score: ${currentReport.currentScore}/100"
            pendingEngines.isNotEmpty() ->
                "✓ Multi-Engine Cloud & On-Device Scan Complete • Score: ${currentReport.currentScore}/100"
            else ->
                "🛡️ On-Device Security Scan Complete • Score: ${currentReport.currentScore}/100"
        }

        val finalReport = currentReport.copy(
            isFinal = true,
            pendingEngines = emptyList(),
            aiExplanation = aiExplanation,
            engineVerdictMap = engineVerdictMap.toMap(),
            statusMessage = finalStatus
        )

        ScanThrottleManager.cacheReport(finalReport)
        _scanReports.emit(finalReport)

        if (finalReport.severity == ThreatSeverity.MALICIOUS || finalReport.severity == ThreatSeverity.HIGH_RISK) {
            ThreatNotificationManager.showThreatAlert(context, finalReport)
        }
        return@withContext finalReport
    }

    suspend fun performScan(
        context: Context,
        file: File,
        customAppName: String? = null,
        customPackageName: String? = null
    ): ThreatReport {
        return streamScan(context, file, customAppName, customPackageName)
    }
}
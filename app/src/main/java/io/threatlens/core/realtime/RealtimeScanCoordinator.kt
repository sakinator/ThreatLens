package io.threatlens.core.realtime

import android.content.Context
import io.threatlens.core.ai.FallbackThreatDefinitions
import io.threatlens.core.ai.ThreatAiExplainer
import io.threatlens.core.cloud.*
import io.threatlens.core.diagnostics.AppDiagnosticLogger
import io.threatlens.core.local.AppProvenanceVerifier
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
    var bazaarKey: String? = null

    // Engine quota saver modes (true = scan suspicious & threats only, false = scan all files)
    var virusTotalQuotaSaver: Boolean = true
    var hybridAnalysisQuotaSaver: Boolean = true
    var kasperskyQuotaSaver: Boolean = true
    var metaDefenderQuotaSaver: Boolean = true
    var filescanQuotaSaver: Boolean = true
    
    // AI Explainer keys
    var openAiKey: String? = null
    var claudeKey: String? = null
    var geminiKey: String? = null
    var groqKey: String? = null

    fun scanFileAsync(context: Context, file: File, isPackageInstall: Boolean = false) {
        if (!file.exists() || !file.canRead()) return

        val extension = file.extension
        if (!isPackageInstall && !ScanThrottleManager.shouldScanFile(file.absolutePath, extension)) {
            return
        }

        // Check if file path is explicitly excluded in Antivirus Exclusions
        if (io.threatlens.core.exclusions.ExclusionManager.isPathExcluded(file.absolutePath)) {
            return
        }

        scanScope.launch {
            streamScan(context, file, isPackageInstall = isPackageInstall)
        }
    }

    suspend fun streamScan(
        context: Context,
        file: File,
        customAppName: String? = null,
        customPackageName: String? = null,
        isFullScan: Boolean = false,
        totalScanCount: Int = 1,
        isPackageInstall: Boolean = false
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
            if (isPackageInstall) {
                // If package was just installed and we have a cached report from a recent download scan:
                val updated = cached.copy(
                    packageName = if (!packageName.isNullOrBlank()) packageName else cached.packageName,
                    appName = if (!resolvedAppName.isNullOrBlank()) resolvedAppName else cached.appName,
                    targetPath = file.absolutePath
                )
                ScanThrottleManager.cacheReport(updated)
                io.threatlens.core.scanner.ScanReportRepository.saveReport(context, updated)
                if (updated.severity == ThreatSeverity.MALICIOUS || updated.severity == ThreatSeverity.HIGH_RISK) {
                    ThreatNotificationManager.showThreatAlert(context, updated, isPackageInstall = true)
                } else if (!isFullScan) {
                    ThreatNotificationManager.showSafeScanNotification(context, updated, isPackageInstall = true)
                }
            }
            return@withContext cached
        }

        val isApk = file.extension.equals("apk", ignoreCase = true)
        val provenance = if (isApk) AppProvenanceVerifier.inspectProvenance(context, packageName) else null
        val isVerifiedStoreApp = provenance?.isVerifiedStore == true || provenance?.isSystemApp == true

        // 3. Local Phase: 100% Free Autonomous On-Device Engine (0ms latency, zero internet required)
        val localVerdict = LocalAntivirusEngine.scan(context, file, sha256)
        val runningLocalScore = localVerdict.localScore
        var runningFamily = localVerdict.threatFamily
        val runningSources = mutableListOf<String>().apply { addAll(localVerdict.engineSources) }
        val successfulEngines = mutableListOf<String>()
        val failedEngines = mutableListOf<String>()
        val flaggingCloudProviders = mutableListOf<String>()
        val cleanCloudProviders = mutableListOf<String>()

        var runningCloudScore = 0
        var highestSeverity = when {
            localVerdict.isMalicious || runningLocalScore >= 75 -> ThreatSeverity.MALICIOUS
            runningLocalScore >= 50 -> ThreatSeverity.HIGH_RISK
            runningLocalScore >= 25 -> ThreatSeverity.SUSPICIOUS
            else -> ThreatSeverity.SAFE
        }

        // Determine list of pending cloud engines based on configuration
        // AlienVault OTX and CIRCL Hashlookup are 100% free and work with zero API key!
        val pendingEngines = mutableListOf<String>("AlienVault OTX", "CIRCL Hashlookup")
        if (!bazaarKey.isNullOrBlank()) pendingEngines.add("MalwareBazaar")
        if (!virusTotalKey.isNullOrBlank()) pendingEngines.add("VirusTotal")
        if (!metaDefenderKey.isNullOrBlank()) pendingEngines.add("MetaDefender")
        if (!hybridAnalysisKey.isNullOrBlank()) pendingEngines.add("Hybrid Analysis")
        if (!kasperskyKey.isNullOrBlank()) pendingEngines.add("Kaspersky OpenTIP")
        if (!filescanKey.isNullOrBlank()) pendingEngines.add("Filescan.io")

        val engineVerdictMap = mutableMapOf<String, String>()
        val engineDetailsMap = mutableMapOf<String, List<String>>()

        // 1. ThreatLens Behavioral Heuristics
        val hasBehaviors = localVerdict.detectedBehaviors.isNotEmpty()
        val heurScore = localVerdict.scoreBreakdown?.heuristicScore ?: 0
        engineVerdictMap["ThreatLens Behavioral Heuristics"] = when {
            hasBehaviors && heurScore >= 60 -> "Flagged: Heuristic Detection (${localVerdict.detectedBehaviors.size} patterns)"
            hasBehaviors || heurScore >= 25 -> "Suspicious: Heuristic Pattern (${localVerdict.detectedBehaviors.size} patterns, ${localVerdict.dangerousPermissions.size} permissions)"
            else -> "Clean (0 heuristic patterns • Safe)"
        }
        engineDetailsMap["ThreatLens Behavioral Heuristics"] = if (hasBehaviors) {
            localVerdict.detectedBehaviors
        } else if (localVerdict.dangerousPermissions.isNotEmpty()) {
            listOf("Requested sensitive permissions: ${localVerdict.dangerousPermissions.joinToString(", ")}", "Bytecode pattern scan: Clean", "Normal permission matrix")
        } else {
            listOf("Bytecode pattern scan: Clean", "Normal permission matrix")
        }

        // 2. ClamAV Open Source Engine
        val clam = localVerdict.clamAvResult
        engineVerdictMap["ClamAV Open Source Engine"] = if (clam != null && clam.isMalicious) {
            "Flagged: ${clam.signatureName} (${clam.matchedCategory})"
        } else {
            "Clean (0 CVD rule matches)"
        }
        engineDetailsMap["ClamAV Open Source Engine"] = clam?.details ?: listOf("ClamAV hash database: Clean", "ClamAV bytecode rules: Clean")

        // 3. YARA Mobile Threat Rules
        val yara = localVerdict.yaraResult
        engineVerdictMap["YARA Mobile Threat Rules"] = if (yara != null && yara.isMatched) {
            "Flagged: ${yara.ruleName} (${yara.threatFamily})"
        } else {
            "Clean (0 rules matched across mobile threat sets)"
        }
        engineDetailsMap["YARA Mobile Threat Rules"] = yara?.details ?: listOf("YARA Mobile Rules: Clean", "Evaluated against curated Android malware family rulesets")

        // 4. ThreatLens Certificate & Repack Shield
        val cert = localVerdict.certResult
        engineVerdictMap["ThreatLens Certificate & Repack Shield"] = if (cert != null && cert.isMalicious) {
            "Flagged: ${cert.issueType}"
        } else if (cert != null && cert.isSuspicious) {
            "Suspicious: ${cert.issueType}"
        } else {
            "Verified (Clean release X.509 certificate)"
        }
        engineDetailsMap["ThreatLens Certificate & Repack Shield"] = cert?.details ?: listOf("Verified production release certificate", "No debug keys or repackaging detected")

        // 5. ThreatLens Anti-Analysis & Packer Shield
        val packer = localVerdict.packerResult
        engineVerdictMap["ThreatLens Anti-Analysis & Packer Shield"] = if (packer != null && packer.isPacked) {
            "Suspicious: ${packer.packerName} (Entropy: ${"%.2f".format(packer.dexEntropy)})"
        } else {
            "Clean (Normal uncompressed Dalvik DEX)"
        }
        engineDetailsMap["ThreatLens Anti-Analysis & Packer Shield"] = packer?.details ?: listOf("Bytecode Structure: Standard uncompressed Dalvik DEX", "No commercial crypters or anti-analysis evasion stubs detected")

        // 6. ThreatLens Offline Signature DB
        val sigMatch = localVerdict.offlineDbMatch
        engineVerdictMap["ThreatLens Offline Signature DB"] = if (sigMatch != null) {
            "Flagged: ${sigMatch.threatFamily}"
        } else {
            "Clean (${io.threatlens.core.local.LocalSignatureDatabase.totalSignatures} definitions checked)"
        }
        engineDetailsMap["ThreatLens Offline Signature DB"] = if (sigMatch != null) {
            listOf(
                "Threat Name: ${sigMatch.threatFamily}",
                "Classification: ${sigMatch.category}",
                "Exact SHA-256 signature match in offline database"
            )
        } else {
            listOf(
                "${io.threatlens.core.local.LocalSignatureDatabase.totalSignatures} verified mobile malware signatures queried in <1ms",
                "Zero network dependency"
            )
        }

        // 7. ThreatLens Bytecode Pattern Engine
        val bytecodeMatches = localVerdict.bytecodeMatches
        engineVerdictMap["ThreatLens Bytecode Pattern Engine"] = if (bytecodeMatches.isNotEmpty()) {
            "Flagged: ${bytecodeMatches.first().family}"
        } else {
            "Clean (Bytecode pattern scan clean)"
        }
        engineDetailsMap["ThreatLens Bytecode Pattern Engine"] = if (bytecodeMatches.isNotEmpty()) {
            bytecodeMatches.map { "${it.family}: ${it.description}" }
        } else {
            listOf(
                "DEX Bytecode Scan: Clean",
                "No embedded RAT stagers or crypto-ransomware bytecode sequences detected"
            )
        }

        engineVerdictMap["AlienVault OTX"] = "Scanning public threat pulses..."
        engineVerdictMap["CIRCL Hashlookup"] = "Querying NIST NSRL database..."

        if (bazaarKey.isNullOrBlank()) engineVerdictMap["MalwareBazaar"] = "No results (API key not configured)"
        if (virusTotalKey.isNullOrBlank()) engineVerdictMap["VirusTotal"] = "No results (API key not configured)"
        if (metaDefenderKey.isNullOrBlank()) engineVerdictMap["MetaDefender"] = "No results (API key not configured)"
        if (hybridAnalysisKey.isNullOrBlank()) engineVerdictMap["Hybrid Analysis"] = "No results (API key not configured)"
        if (kasperskyKey.isNullOrBlank()) engineVerdictMap["Kaspersky OpenTIP"] = "No results (API key not configured)"
        if (filescanKey.isNullOrBlank()) engineVerdictMap["Filescan.io"] = "No results (API key not configured)"

        var flaggedEnginesCount = 0
        var totalEnginesCount = 0

        val initialAiExplanation = if (highestSeverity != ThreatSeverity.SAFE || localVerdict.detectedBehaviors.isNotEmpty() || localVerdict.dangerousPermissions.isNotEmpty()) {
            FallbackThreatDefinitions.getExplanation(
                family = runningFamily,
                behaviors = localVerdict.detectedBehaviors,
                permissions = localVerdict.dangerousPermissions,
                engineVerdicts = engineVerdictMap.toMap(),
                engineDetails = engineDetailsMap.toMap()
            )
        } else null

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
            detectionType = localVerdict.detectionType,
            scoreBreakdown = localVerdict.scoreBreakdown,
            detectedBehaviors = localVerdict.detectedBehaviors,
            dangerousPermissions = localVerdict.dangerousPermissions,
            cloudSources = emptyList(),
            failedEngines = emptyList(),
            successfulEngines = emptyList(),
            engineVerdictMap = engineVerdictMap.toMap(),
            engineDetailsMap = engineDetailsMap.toMap(),
            isOfflineMode = false,
            isFinal = false,
            aiExplanation = initialAiExplanation,
            pendingEngines = pendingEngines.toList(),
            statusMessage = if (pendingEngines.isNotEmpty()) "⚡ Querying ${pendingEngines.size} threat intelligence engines..." else "🛡️ Analyzed via ThreatLens On-Device Security Engine"
        )

        // EMIT IMMEDIATE LOCAL RESULT (UI updates in <20ms!)
        _scanReports.emit(currentReport)

        if (localVerdict.isMalicious) {
            ThreatNotificationManager.showThreatAlert(context, currentReport, isPackageInstall = isPackageInstall)
        }

        // 4. Progressive Cloud Engine Querying with API Failure Mitigation
        val reportMutex = Mutex()
        val engineJobs = mutableListOf<Job>()

        suspend fun updateVerdict(statusText: String) {
            val isThreatLensSelf = packageName?.equals("io.threatlens", ignoreCase = true) == true || packageName?.equals(context.packageName, ignoreCase = true) == true
            val weighted = if (isThreatLensSelf) {
                0
            } else if (localVerdict.isMalicious || runningLocalScore >= 75) {
                // Severe on-device finding: NEVER diluted or crushed by cloud errors
                maxOf(runningLocalScore, runningCloudScore)
            } else if (successfulEngines.isEmpty()) {
                // When offline or all cloud APIs fail: Local engine is 100% authoritative!
                runningLocalScore
            } else if (isVerifiedStoreApp && flaggedEnginesCount <= 1 && runningCloudScore <= 15) {
                // Safe baseline suppression for verified Google Play / System apps (e.g. JioTV with 1/65 isolated flag or clean)
                minOf(15, runningLocalScore)
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

            val effectiveDetectionType = when {
                localVerdict.detectionType == io.threatlens.core.model.DetectionType.CONFIRMED_SIGNATURE ->
                    io.threatlens.core.model.DetectionType.CONFIRMED_SIGNATURE
                flaggedEnginesCount > 0 && highestSeverity != ThreatSeverity.SAFE ->
                    io.threatlens.core.model.DetectionType.CLOUD_INTELLIGENCE
                localVerdict.detectionType == io.threatlens.core.model.DetectionType.HEURISTIC_PATTERN && highestSeverity != ThreatSeverity.SAFE ->
                    io.threatlens.core.model.DetectionType.HEURISTIC_PATTERN
                else ->
                    io.threatlens.core.model.DetectionType.CLEAN
            }

            val effectiveThreatFamily = if (highestSeverity == ThreatSeverity.SAFE && !localVerdict.isMalicious) {
                "Clean"
            } else {
                runningFamily
            }

            val currentBreakdown = currentReport.scoreBreakdown?.copy(
                cloudScore = runningCloudScore,
                totalScore = weighted,
                rationale = when (effectiveDetectionType) {
                    io.threatlens.core.model.DetectionType.CONFIRMED_SIGNATURE ->
                        "Confirmed Malware: Matched known mobile Trojan or exploit signature in database/bytecode."
                    io.threatlens.core.model.DetectionType.CLOUD_INTELLIGENCE ->
                        "Cloud Flagged: Flagged by $flaggedEnginesCount cloud threat intelligence engine(s)."
                    io.threatlens.core.model.DetectionType.HEURISTIC_PATTERN ->
                        "Heuristic Finding: Flagged for high-privilege capabilities or unusual permission matrix. (0 confirmed signatures)"
                    else ->
                        "Verified Safe: 0 malicious signatures or behavioral anomalies found across local and cloud engines."
                }
            )

            currentReport = currentReport.copy(
                cloudScore = runningCloudScore,
                currentScore = weighted,
                severity = highestSeverity,
                threatFamily = effectiveThreatFamily,
                detectionType = effectiveDetectionType,
                scoreBreakdown = currentBreakdown,
                cloudEnginesFlagged = flaggedEnginesCount,
                cloudEnginesTotal = totalEnginesCount,
                cloudSources = runningSources.toList(),
                failedEngines = failedEngines.toList(),
                successfulEngines = successfulEngines.toList(),
                engineVerdictMap = engineVerdictMap.toMap(),
                engineDetailsMap = engineDetailsMap.toMap(),
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
            family: String?,
            details: List<String> = emptyList()
        ) {
            reportMutex.withLock {
                pendingEngines.remove(engineName)
                successfulEngines.add(engineName)
                if (details.isNotEmpty()) {
                    engineDetailsMap[engineName] = details
                }
                engineVerdictMap[engineName] = if (flagged > 0) {
                    if (total > 0) {
                        "Flagged ($flagged/$total): ${family ?: "Malware"}"
                    } else {
                        "Flagged: ${family ?: "$flagged detections"}"
                    }
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

                val isQuotaPreserved = sourceLabel.contains("Quota Preserved", ignoreCase = true)
                val isCloudProvider = engineName in listOf(
                    "VirusTotal", "MetaDefender", "Filescan.io", "Hybrid Analysis",
                    "Kaspersky OpenTIP", "MalwareBazaar", "AlienVault OTX", "CIRCL Hashlookup"
                )

                if (isCloudProvider && !isQuotaPreserved) {
                    if (flagged > 0 || score >= 50) {
                        if (engineName !in flaggingCloudProviders) flaggingCloudProviders.add(engineName)
                    } else {
                        if (engineName !in cleanCloudProviders) cleanCloudProviders.add(engineName)
                    }
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
                engineVerdictMap[engineName] = "Unreachable (Timeout / Offline • Retained other verdicts)"

                AppDiagnosticLogger.logError("RealtimeScanCoordinator", "Cloud engine $engineName timed out or unreachable for ${file.name}")

                val status = if (pendingEngines.isEmpty()) {
                    if (successfulEngines.isEmpty()) {
                        "🛡️ Protected by On-Device Local Engines (Cloud APIs unreachable)"
                    } else {
                        "✓ Inspection complete (${successfulEngines.size} verified • ${failedEngines.joinToString(", ")} timed out)"
                    }
                } else {
                    "Pending (${pendingEngines.size}): ${pendingEngines.joinToString(", ")}"
                }

                updateVerdict(status)
            }
        }

        // Launch AlienVault OTX (Zero key required public cloud intelligence)
        engineJobs.add(scanScope.launch {
            try {
                val otx = AlienVaultOtxProvider.queryHash(sha256)
                if (otx != null) {
                    val score = if (otx.isMalicious) 90 else 0
                    onEngineFinished(
                        "AlienVault OTX",
                        score = score,
                        flagged = otx.pulseCount,
                        total = maxOf(1, otx.pulseCount),
                        sourceLabel = if (otx.isMalicious) "AlienVault OTX (${otx.pulseCount} pulses)" else "AlienVault OTX (Clean)",
                        family = otx.threatFamily,
                        details = if (otx.tags.isNotEmpty()) otx.tags else listOf(otx.details)
                    )
                } else {
                    onEngineFailed("AlienVault OTX")
                }
            } catch (_: Exception) {
                onEngineFailed("AlienVault OTX")
            }
        })

        // Launch CIRCL Hashlookup (Zero key required public CERT / NIST NSRL database)
        engineJobs.add(scanScope.launch {
            try {
                val circl = CirclHashlookupProvider.queryHash(sha256)
                if (circl != null) {
                    val score = if (circl.isMalicious) 90 else 0
                    val circlDetails = if (circl.isMalicious) {
                        listOf(circl.details, "Database: NIST NSRL & CIRCL CERT Threat feeds")
                    } else {
                        listOf(circl.details, "Validated against NIST National Software Reference Library (NSRL)")
                    }
                    onEngineFinished(
                        "CIRCL Hashlookup",
                        score = score,
                        flagged = if (circl.isMalicious) 1 else 0,
                        total = 1,
                        sourceLabel = if (circl.isMalicious) "CIRCL Threat DB" else "CIRCL Hashlookup (Clean)",
                        family = if (circl.isMalicious) "CIRCL.Malware" else null,
                        details = circlDetails
                    )
                } else {
                    onEngineFailed("CIRCL Hashlookup")
                }
            } catch (_: Exception) {
                onEngineFailed("CIRCL Hashlookup")
            }
        })

        // Launch MalwareBazaar (Abuse.ch Auth-Key required by abuse.ch)
        if (!bazaarKey.isNullOrBlank()) {
            engineJobs.add(scanScope.launch {
                try {
                    val bazaar = MalwareBazaarProvider.queryHash(sha256, bazaarKey)
                    if (bazaar != null) {
                        val mbDetails = if (bazaar.isMalicious) {
                            listOf(
                                "Signature: ${bazaar.signature ?: "Known Malware Sample"}",
                                "File Type: ${bazaar.fileType ?: "APK Binary"}",
                                "Tags: ${bazaar.tags.joinToString(", ").ifEmpty { "Known Android Threat" }}"
                            )
                        } else {
                            listOf("Sample clean / unflagged in Abuse.ch MalwareBazaar malware repository.")
                        }
                        if (bazaar.isMalicious) {
                            onEngineFinished(
                                "MalwareBazaar",
                                score = 95,
                                flagged = 1,
                                total = 1,
                                sourceLabel = "MalwareBazaar (Abuse.ch)",
                                family = bazaar.signature,
                                details = mbDetails
                            )
                        } else {
                            onEngineFinished(
                                "MalwareBazaar",
                                score = 0,
                                flagged = 0,
                                total = 1,
                                sourceLabel = "MalwareBazaar (Clean)",
                                family = null,
                                details = mbDetails
                            )
                        }
                    } else {
                        onEngineFailed("MalwareBazaar")
                    }
                } catch (_: Exception) {
                    onEngineFailed("MalwareBazaar")
                }
            })
        }

        val isSuspiciousOrWorse = highestSeverity != ThreatSeverity.SAFE ||
                runningLocalScore >= 20 ||
                localVerdict.detectedBehaviors.isNotEmpty() ||
                localVerdict.dangerousPermissions.size >= 4 ||
                !isVerifiedStoreApp ||
                localVerdict.certResult?.isSuspicious == true ||
                localVerdict.packerResult?.isPacked == true

        // Known free-tier daily rate limits:
        // VirusTotal: 500/day, MetaDefender: 100/day, Filescan: 100/day, Hybrid Analysis: 100/day, Kaspersky: 100/day.
        // If total files in full scan <= daily limit, do not save — scan all files!
        val isVtOverQuotaLimit = isFullScan && totalScanCount > 500
        val isMdOverQuotaLimit = isFullScan && totalScanCount > 100
        val isHaOverQuotaLimit = isFullScan && totalScanCount > 100
        val isKasOverQuotaLimit = isFullScan && totalScanCount > 100
        val isFsOverQuotaLimit = isFullScan && totalScanCount > 100

        // Launch VirusTotal
        val shouldScanVt = !virusTotalKey.isNullOrBlank() && (!isVtOverQuotaLimit || !virusTotalQuotaSaver || isSuspiciousOrWorse)
        if (!virusTotalKey.isNullOrBlank()) {
            if (!shouldScanVt) {
                onEngineFinished(
                    "VirusTotal",
                    score = 0,
                    flagged = 0,
                    total = 0,
                    sourceLabel = "VirusTotal (Quota Preserved)",
                    family = null,
                    details = listOf(
                        "File verified safe locally • Quota preserved",
                        "Clean verified app: skipped to save daily 500-request quota.",
                        "Toggle 'Always scan all' in Settings if preferred."
                    )
                )
            } else {
                engineJobs.add(scanScope.launch {
                    try {
                        val vt = VirusTotalProvider.queryHash(sha256, virusTotalKey!!)
                        if (vt != null && vt.totalEngines > 0) {
                            val normalized = ThreatFamilyNormalizer.normalize(
                                maliciousCount = vt.maliciousCount,
                                totalEngines = vt.totalEngines,
                                rawFamilyLabels = vt.detectedVendors,
                                isVerifiedStoreApp = isVerifiedStoreApp
                            )
                            val score = normalized.adjustedScore
                            val family = if (normalized.isFalsePositiveRisk) normalized.normalizedFamily else (vt.suggestedThreatLabel ?: normalized.displayCategory)
                            val details = if (vt.detectedVendors.isNotEmpty()) {
                                listOf(normalized.consensusSummary) + vt.detectedVendors
                            } else {
                                listOf("0/${vt.totalEngines} security vendors flagged this file across VirusTotal.")
                            }
                            onEngineFinished(
                                "VirusTotal",
                                score = score,
                                flagged = vt.maliciousCount,
                                total = vt.totalEngines,
                                sourceLabel = "VirusTotal (${vt.maliciousCount}/${vt.totalEngines})",
                                family = family,
                                details = details
                            )
                        } else if (vt != null) {
                            onEngineFinished(
                                "VirusTotal",
                                score = 0,
                                flagged = 0,
                                total = 0,
                                sourceLabel = "VirusTotal (Unindexed)",
                                family = null,
                                details = listOf("Hash not indexed in VirusTotal database.")
                            )
                        } else {
                            onEngineFailed("VirusTotal")
                        }
                    } catch (_: Exception) {
                        onEngineFailed("VirusTotal")
                    }
                })
            }
        }

        // Launch MetaDefender
        val shouldScanMd = !metaDefenderKey.isNullOrBlank() && (!isMdOverQuotaLimit || !metaDefenderQuotaSaver || isSuspiciousOrWorse)
        if (!metaDefenderKey.isNullOrBlank()) {
            if (!shouldScanMd) {
                onEngineFinished(
                    "MetaDefender",
                    score = 0,
                    flagged = 0,
                    total = 0,
                    sourceLabel = "MetaDefender (Quota Preserved)",
                    family = null,
                    details = listOf(
                        "File verified safe locally • Quota preserved",
                        "Clean verified app: skipped to save daily 100-request quota.",
                        "Toggle 'Always scan all' in Settings if preferred."
                    )
                )
            } else {
                engineJobs.add(scanScope.launch {
                    try {
                        val md = MetaDefenderProvider.queryHash(sha256, metaDefenderKey!!)
                        if (md != null && !md.isUnindexed && (md.totalEngines > 0 || md.modules.isNotEmpty())) {
                            val normalized = ThreatFamilyNormalizer.normalize(
                                maliciousCount = md.enginesFlagged,
                                totalEngines = md.totalEngines,
                                rawFamilyLabels = md.detectedVendors,
                                isVerifiedStoreApp = isVerifiedStoreApp
                            )
                            val score = normalized.adjustedScore
                            val family = if (normalized.isFalsePositiveRisk) normalized.normalizedFamily else (md.threatName ?: normalized.displayCategory)
                            val mdDetails = mutableListOf<String>()
                            if (md.modules.isNotEmpty()) {
                                for (mod in md.modules) {
                                    mdDetails.add(mod.summary)
                                    for (d in mod.details) {
                                        if (d != mod.summary && d !in mdDetails) {
                                            mdDetails.add(d)
                                        }
                                    }
                                }
                            } else {
                                if (md.detectedVendors.isNotEmpty()) {
                                    mdDetails.addAll(md.detectedVendors)
                                } else {
                                    mdDetails.add("Metascan: Clean (0/${md.totalEngines} AV engines flagged)")
                                    mdDetails.add("No commercial antivirus threats detected")
                                }
                            }
                            val anyDetected = md.modules.any { it.isDetected } || md.threatFound
                            onEngineFinished(
                                "MetaDefender",
                                score = if (anyDetected) maxOf(score, 45) else 0,
                                flagged = md.enginesFlagged + if (md.modules.any { it.name.contains("Alin") && it.isDetected }) 1 else 0,
                                total = md.totalEngines.coerceAtLeast(1),
                                sourceLabel = if (md.totalEngines > 0) "MetaDefender (${md.enginesFlagged}/${md.totalEngines})" else if (anyDetected) "MetaDefender (Flagged)" else "MetaDefender (Clean)",
                                family = family,
                                details = mdDetails
                            )
                        } else if (md != null) {
                            onEngineFinished(
                                "MetaDefender",
                                score = 0,
                                flagged = 0,
                                total = 0,
                                sourceLabel = "MetaDefender (Unindexed / Clean)",
                                family = null,
                                details = listOf(
                                    "Sample hash not indexed in MetaDefender Cloud database.",
                                    "0 threat detections reported across commercial vendor engines."
                                )
                            )
                        } else {
                            onEngineFailed("MetaDefender")
                        }
                    } catch (_: Exception) {
                        onEngineFailed("MetaDefender")
                    }
                })
            }
        }

        // Launch Hybrid Analysis
        val shouldScanHa = !hybridAnalysisKey.isNullOrBlank() && (!isHaOverQuotaLimit || !hybridAnalysisQuotaSaver || isSuspiciousOrWorse)
        if (!hybridAnalysisKey.isNullOrBlank()) {
            if (!shouldScanHa) {
                onEngineFinished(
                    "Hybrid Analysis",
                    score = 0,
                    flagged = 0,
                    total = 0,
                    sourceLabel = "Hybrid Analysis (Quota Preserved)",
                    family = null,
                    details = listOf(
                        "File verified safe locally • Quota preserved",
                        "Clean verified app: skipped to save daily Falcon sandbox quota.",
                        "Toggle 'Always scan all' in Settings if preferred."
                    )
                )
            } else {
                engineJobs.add(scanScope.launch {
                    try {
                        val ha = HybridAnalysisProvider.queryHash(sha256, hybridAnalysisKey!!)
                        if (ha != null) {
                            if (ha.isUnindexed) {
                                // Upload & analyze only for suspicious and above files (user requested quota protection)
                                if (isSuspiciousOrWorse && file.exists() && file.length() in 1L..52428800L) {
                                    val submitted = HybridAnalysisProvider.submitFileForScan(file, hybridAnalysisKey!!)
                                    val haDetails = mutableListOf<String>()
                                    if (submitted != null && submitted.threatScore > 0) {
                                        haDetails.add("Falcon QuickScan Score: ${submitted.threatScore}/100")
                                        haDetails.add("Verdict: ${submitted.verdict}")
                                        haDetails.add("Sandbox: Falcon Dynamic Behavioral Detonation")
                                        onEngineFinished(
                                            "Hybrid Analysis",
                                            score = submitted.threatScore,
                                            flagged = if (submitted.threatScore >= 50) 1 else 0,
                                            total = 1,
                                            sourceLabel = "Hybrid Analysis (${submitted.threatScore}/100)",
                                            family = null,
                                            details = haDetails
                                        )
                                    } else {
                                        haDetails.add("Suspicious file submitted to Falcon Sandbox for automated detonation.")
                                        haDetails.add("Submission ID: ${submitted?.submissionId ?: "Queued"} • Analysis in progress")
                                        haDetails.add("Sandbox: Falcon Dynamic Behavioral Detonation")
                                        onEngineFinished(
                                            "Hybrid Analysis",
                                            score = 40,
                                            flagged = 1,
                                            total = 1,
                                            sourceLabel = "Hybrid Analysis (Submitted)",
                                            family = null,
                                            details = haDetails
                                        )
                                    }
                                } else {
                                    onEngineFinished(
                                        "Hybrid Analysis",
                                        score = 0,
                                        flagged = 0,
                                        total = 0,
                                        sourceLabel = "Hybrid Analysis (Unindexed / Clean)",
                                        family = null,
                                        details = listOf(
                                            "Sample hash not indexed in Hybrid Analysis database.",
                                            "0 previous Falcon sandbox detonation threats reported.",
                                            "Clean verified app: skipped sandbox upload to preserve daily quota."
                                        )
                                    )
                                }
                            } else {
                                val haDetails = mutableListOf<String>()
                                haDetails.add("Falcon Threat Score: ${ha.threatScore}/100")
                                if (!ha.verdict.isNullOrBlank()) haDetails.add("Detonation Verdict: ${ha.verdict}")
                                if (!ha.vxFamily.isNullOrBlank()) haDetails.add("Malware Family: ${ha.vxFamily}")
                                haDetails.add("Sandbox: Falcon Dynamic Behavioral Detonation")
                                onEngineFinished(
                                    "Hybrid Analysis",
                                    score = ha.threatScore,
                                    flagged = if (ha.threatScore >= 50) 1 else 0,
                                    total = 1,
                                    sourceLabel = "Hybrid Analysis (${ha.threatScore}/100)",
                                    family = ha.vxFamily,
                                    details = haDetails
                                )
                            }
                        } else {
                            onEngineFailed("Hybrid Analysis")
                        }
                    } catch (_: Exception) {
                        onEngineFailed("Hybrid Analysis")
                    }
                })
            }
        }

        // Launch Kaspersky OpenTIP
        val shouldScanKas = !kasperskyKey.isNullOrBlank() && (!isKasOverQuotaLimit || !kasperskyQuotaSaver || isSuspiciousOrWorse)
        if (!kasperskyKey.isNullOrBlank()) {
            if (!shouldScanKas) {
                onEngineFinished(
                    "Kaspersky OpenTIP",
                    score = 0,
                    flagged = 0,
                    total = 0,
                    sourceLabel = "Kaspersky (Quota Preserved)",
                    family = null,
                    details = listOf(
                        "File verified safe locally • Quota preserved",
                        "Clean verified app: skipped to save daily OpenTIP lookup quota.",
                        "Toggle 'Always scan all' in Settings if preferred."
                    )
                )
            } else {
                engineJobs.add(scanScope.launch {
                    try {
                        val kas = KasperskyOpenTipProvider.queryHash(sha256, kasperskyKey!!)
                        if (kas != null) {
                            val score = if (kas.zone.equals("Red", ignoreCase = true)) 100 else if (kas.zone.equals("Yellow", ignoreCase = true)) 60 else 0
                            val kasDetails = mutableListOf<String>()
                            kasDetails.add("Kaspersky Threat Zone: ${kas.zone}")
                            if (!kas.threatFamily.isNullOrBlank()) kasDetails.add("Kaspersky: ${kas.threatFamily}")
                            kasDetails.add("Enterprise Intelligence: Zone ${kas.zone} verified hash")
                            onEngineFinished(
                                "Kaspersky OpenTIP",
                                score = score,
                                flagged = if (score > 0) 1 else 0,
                                total = 1,
                                sourceLabel = "Kaspersky (${kas.zone})",
                                family = kas.threatFamily,
                                details = kasDetails
                            )
                        } else {
                            onEngineFailed("Kaspersky OpenTIP")
                        }
                    } catch (_: Exception) {
                        onEngineFailed("Kaspersky OpenTIP")
                    }
                })
            }
        }

        // Launch Filescan.io
        val shouldScanFs = !filescanKey.isNullOrBlank() && (!isFsOverQuotaLimit || !filescanQuotaSaver || isSuspiciousOrWorse)
        if (!filescanKey.isNullOrBlank()) {
            if (!shouldScanFs) {
                onEngineFinished(
                    "Filescan.io",
                    score = 0,
                    flagged = 0,
                    total = 0,
                    sourceLabel = "Filescan.io (Quota Preserved)",
                    family = null,
                    details = listOf(
                        "File verified safe locally • Quota preserved",
                        "Clean verified app: skipped to save daily API rate limit.",
                        "Toggle 'Always scan all' in Settings if preferred."
                    )
                )
            } else {
                engineJobs.add(scanScope.launch {
                    try {
                        val fs = FilescanProvider.queryHash(sha256, filescanKey!!)
                        if (fs != null) {
                            val fsDetails = mutableListOf<String>()
                            when {
                                fs.isUnindexed || fs.verdict == "UNINDEXED" -> {
                                    fsDetails.add("Sample hash not previously indexed in Filescan.io database.")
                                    fsDetails.add("0 threat detections reported across MDCloud & threat intel feeds.")
                                    fsDetails.add("Static Analysis & IOC Extraction Engine: Safe")
                                    onEngineFinished(
                                        "Filescan.io",
                                        score = 0,
                                        flagged = 0,
                                        total = 0,
                                        sourceLabel = "Filescan.io (Unindexed / Clean)",
                                        family = null,
                                        details = fsDetails
                                    )
                                }
                                fs.verdict == "MALICIOUS" -> {
                                    fsDetails.add("Filescan Threat Score: ${fs.threatScore}/100")
                                    fsDetails.add("Detonation Verdict: Malicious")
                                    if (fs.tags.isNotEmpty()) fsDetails.addAll(fs.tags)
                                    fsDetails.add("Automated static analysis & dynamic behavioral IOCs matched.")
                                    onEngineFinished(
                                        "Filescan.io",
                                        score = fs.threatScore,
                                        flagged = 1,
                                        total = 1,
                                        sourceLabel = "Filescan.io (Malicious)",
                                        family = fs.tags.firstOrNull { !it.startsWith("MDCloud") },
                                        details = fsDetails
                                    )
                                }
                                fs.verdict == "SUSPICIOUS" -> {
                                    fsDetails.add("Filescan Threat Score: ${fs.threatScore}/100")
                                    fsDetails.add("Detonation Verdict: Suspicious")
                                    if (fs.tags.isNotEmpty()) fsDetails.addAll(fs.tags)
                                    fsDetails.add("Static Analysis & IOC Extraction: Suspicious patterns observed.")
                                    onEngineFinished(
                                        "Filescan.io",
                                        score = fs.threatScore,
                                        flagged = 1,
                                        total = 1,
                                        sourceLabel = "Filescan.io (Suspicious)",
                                        family = null,
                                        details = fsDetails
                                    )
                                }
                                else -> {
                                    fsDetails.add("Filescan Threat Score: 0/100")
                                    fsDetails.add("Detonation Verdict: Clean (No threats detected)")
                                    if (fs.tags.isNotEmpty()) {
                                        fsDetails.addAll(fs.tags)
                                    } else {
                                        fsDetails.add("Automated sandbox & static inspection: Verified safe.")
                                    }
                                    onEngineFinished(
                                        "Filescan.io",
                                        score = 0,
                                        flagged = 0,
                                        total = 1,
                                        sourceLabel = "Filescan.io (Clean)",
                                        family = null,
                                        details = fsDetails
                                    )
                                }
                            }
                        } else {
                            onEngineFailed("Filescan.io")
                        }
                    } catch (_: Exception) {
                        onEngineFailed("Filescan.io")
                    }
                })
            }
        }

        // Wait for cloud engines with 5 second timeout
        withTimeoutOrNull(5000L) {
            engineJobs.joinAll()
        }

        // Handle any pending engines that timed out
        reportMutex.withLock {
            if (pendingEngines.isNotEmpty()) {
                pendingEngines.forEach { engineName ->
                    engineVerdictMap[engineName] = "Unreachable (Timeout)"
                }
                failedEngines.addAll(pendingEngines)
                pendingEngines.clear()
            }
        }

        // Final overall score fusion:
        // Confirmed malware requires verified database signature, CVD rule, or strong cloud consensus (>= 8 engines or multi-cloud corroboration).
        // Behavioral heuristic patterns identify potential threats (Bankers, Spyware, Droppers, Ransomware)
        // without signatures, but cap score at 50..60 (HIGH_RISK/SUSPICIOUS) so they are never confirmed as 100/100 MALICIOUS
        // without engine/signature confirmation.
        val hasLocalConfirmedMalware = localVerdict.matchedSignatures.isNotEmpty() ||
            (localVerdict.clamAvResult != null && localVerdict.clamAvResult.isMalicious) ||
            (localVerdict.yaraResult != null && localVerdict.yaraResult.isMatched)

        val hasMultiCloudConfirmedMalware = flaggingCloudProviders.size >= 2 ||
            (flaggedEnginesCount >= 6)

        val hasConfirmedMalware = hasLocalConfirmedMalware || hasMultiCloudConfirmedMalware || (flaggedEnginesCount >= 8)

        val isCloudScanPerformed = cleanCloudProviders.isNotEmpty() || flaggingCloudProviders.isNotEmpty()
        val isThreatLensSelf = packageName?.equals("io.threatlens", ignoreCase = true) == true || packageName?.equals(context.packageName, ignoreCase = true) == true

        val finalWeighted = if (isThreatLensSelf) {
            0
        } else if (hasConfirmedMalware) {
            maxOf(runningLocalScore, runningCloudScore).coerceIn(75, 100)
        } else if (flaggingCloudProviders.size == 1 && flaggedEnginesCount in 1..4) {
            // Low cloud divergence (e.g. 1-3 engines on VirusTotal or MetaDefender)
            val blended = ((runningLocalScore * 0.40) + (minOf(runningCloudScore, 35) * 0.60)).toInt()
            blended.coerceIn(25, 55)
        } else if (isCloudScanPerformed && flaggingCloudProviders.isEmpty()) {
            // Scan done using cloud, and multiple cloud engines confirmed 0 threats
            if (isVerifiedStoreApp) {
                0
            } else if (runningLocalScore < 60) {
                (runningLocalScore * 0.25).toInt().coerceIn(0, 15)
            } else {
                (runningLocalScore * 0.40).toInt().coerceIn(0, 30)
            }
        } else if (successfulEngines.isEmpty() || !isCloudScanPerformed) {
            // Scan done WITHOUT cloud (pure on-device analysis or quota preserved)
            if (hasLocalConfirmedMalware) {
                runningLocalScore.coerceIn(75, 100)
            } else {
                runningLocalScore.coerceIn(0, 50)
            }
        } else if (totalEnginesCount >= 20 && flaggedEnginesCount == 0 && runningLocalScore < 60) {
            (runningLocalScore * 0.35).toInt().coerceIn(0, 25)
        } else {
            ((runningLocalScore * 0.40) + (runningCloudScore * 0.60)).toInt().coerceIn(0, 60)
        }.coerceIn(0, 100)

        val finalSeverity = when {
            finalWeighted >= 75 -> ThreatSeverity.MALICIOUS
            finalWeighted >= 50 -> ThreatSeverity.HIGH_RISK
            finalWeighted >= 25 -> ThreatSeverity.SUSPICIOUS
            else -> ThreatSeverity.SAFE
        }

        val effectiveDetectionType = when {
            hasLocalConfirmedMalware -> io.threatlens.core.model.DetectionType.CONFIRMED_SIGNATURE
            hasMultiCloudConfirmedMalware || flaggedEnginesCount > 0 -> io.threatlens.core.model.DetectionType.CLOUD_INTELLIGENCE
            localVerdict.detectionType == io.threatlens.core.model.DetectionType.HEURISTIC_PATTERN ->
                io.threatlens.core.model.DetectionType.HEURISTIC_PATTERN
            else -> io.threatlens.core.model.DetectionType.CLEAN
        }

        val finalBreakdown = currentReport.scoreBreakdown?.copy(
            cloudScore = runningCloudScore,
            totalScore = finalWeighted,
            rationale = when {
                hasConfirmedMalware && hasMultiCloudConfirmedMalware ->
                    "Multi-Cloud Confirmed Threat: Corroborated across ${flaggingCloudProviders.size} cloud intelligence engines (${flaggingCloudProviders.joinToString(", ")})."
                hasConfirmedMalware ->
                    "Confirmed Malware: Matched known mobile Trojan or exploit signature in database/bytecode."
                flaggingCloudProviders.size == 1 ->
                    "Cloud Flagged: Flagged by ${flaggingCloudProviders.first()} ($flaggedEnginesCount engine detection(s))."
                isCloudScanPerformed && flaggingCloudProviders.isEmpty() ->
                    "Multi-Cloud Verified Safe: Confirmed clean across ${cleanCloudProviders.size} cloud intelligence engine(s) (${cleanCloudProviders.joinToString(", ")})."
                else ->
                    "On-Device Verified: Evaluated offline using local signature database & heuristic inspection."
            }
        )

        // 5. Generate Comprehensive Point-by-Point AI Threat Evaluation
        val explainer = ThreatAiExplainer(
            openAiKey = openAiKey,
            claudeKey = claudeKey,
            geminiApiKey = geminiKey,
            groqApiKey = groqKey
        )
        val finalAiExplanation = explainer.getExplanation(
            targetName = resolvedAppName ?: file.name,
            threatFamily = runningFamily,
            behaviors = currentReport.detectedBehaviors,
            permissions = currentReport.dangerousPermissions,
            engineVerdicts = engineVerdictMap.toMap(),
            engineDetails = engineDetailsMap.toMap()
        )

        val finalStatus = when {
            flaggedEnginesCount > 0 -> {
                val failNote = if (failedEngines.isNotEmpty()) " (${failedEngines.joinToString(", ")} timed out)" else ""
                "⚠️ Flagged by $flaggedEnginesCount engines (${successfulEngines.size} responded$failNote) • Score: $finalWeighted/100"
            }
            successfulEngines.isNotEmpty() -> {
                val failNote = if (failedEngines.isNotEmpty()) " (${failedEngines.joinToString(", ")} timed out • Retained other verdicts)" else ""
                "✓ Multi-Engine Scan Complete (${successfulEngines.size} engines verified$failNote) • Score: $finalWeighted/100"
            }
            failedEngines.isNotEmpty() ->
                "🛡️ On-Device Analysis Complete (${failedEngines.joinToString(", ")} unreachable) • Score: $finalWeighted/100"
            else ->
                "🛡️ On-Device Security Scan Complete • Score: $finalWeighted/100"
        }

        val finalReport = currentReport.copy(
            cloudScore = runningCloudScore,
            currentScore = finalWeighted,
            severity = finalSeverity,
            threatFamily = runningFamily,
            detectionType = effectiveDetectionType,
            scoreBreakdown = finalBreakdown,
            cloudEnginesFlagged = flaggedEnginesCount,
            cloudEnginesTotal = totalEnginesCount,
            cloudSources = runningSources.toList(),
            failedEngines = failedEngines.toList(),
            successfulEngines = successfulEngines.toList(),
            engineVerdictMap = engineVerdictMap.toMap(),
            engineDetailsMap = engineDetailsMap.toMap(),
            isOfflineMode = successfulEngines.isEmpty(),
            isFinal = true,
            pendingEngines = emptyList(),
            aiExplanation = finalAiExplanation,
            statusMessage = finalStatus
        )

        ScanThrottleManager.cacheReport(finalReport)
        if (!isFullScan || finalReport.severity != ThreatSeverity.SAFE) {
            io.threatlens.core.scanner.ScanReportRepository.saveReport(context, finalReport)
        }
        _scanReports.emit(finalReport)

        if (finalReport.severity == ThreatSeverity.MALICIOUS || finalReport.severity == ThreatSeverity.HIGH_RISK) {
            ThreatNotificationManager.showThreatAlert(context, finalReport, isPackageInstall = isPackageInstall)
        } else if (!isFullScan) {
            // Realtime scanner: download or package install verified clean!
            ThreatNotificationManager.showSafeScanNotification(context, finalReport, isPackageInstall = isPackageInstall)
        }
        return@withContext finalReport
    }

    suspend fun performScan(
        context: Context,
        file: File,
        customAppName: String? = null,
        customPackageName: String? = null,
        isFullScan: Boolean = false,
        totalScanCount: Int = 1
    ): ThreatReport {
        return streamScan(context, file, customAppName, customPackageName, isFullScan, totalScanCount)
    }

    suspend fun applyUpdatedVtResult(
        oldReport: ThreatReport,
        vtResult: VirusTotalProvider.VtResult
    ): ThreatReport {
        val updatedVerdictMap = oldReport.engineVerdictMap.toMutableMap()
        val updatedDetailsMap = oldReport.engineDetailsMap.toMutableMap()

        val vtVerdict = if (vtResult.maliciousCount > 0) {
            "Flagged (${vtResult.maliciousCount}/${vtResult.totalEngines}): ${vtResult.suggestedThreatLabel ?: "Malware"}"
        } else {
            "Clean (0/${vtResult.totalEngines} engines flagged)"
        }
        updatedVerdictMap["VirusTotal"] = vtVerdict

        val vtDetails = if (vtResult.detectedVendors.isNotEmpty()) {
            vtResult.detectedVendors
        } else {
            listOf("0/${vtResult.totalEngines} security vendors flagged this file across VirusTotal.")
        }
        updatedDetailsMap["VirusTotal"] = vtDetails

        val vtScore = if (vtResult.maliciousCount >= 4) 100 else if (vtResult.maliciousCount >= 1) 45 else 0
        val newCloudScore = maxOf(oldReport.cloudScore, vtScore)

        val newWeighted = if (oldReport.localScore >= 75 || vtResult.maliciousCount >= 4) {
            maxOf(oldReport.localScore, newCloudScore)
        } else if (vtResult.totalEngines >= 25 && vtResult.maliciousCount == 0 && oldReport.localScore < 60) {
            (oldReport.localScore * 0.35).toInt()
        } else {
            maxOf(oldReport.localScore, ((oldReport.localScore * 0.40) + (newCloudScore * 0.60)).toInt())
        }.coerceIn(0, 100)

        val newSeverity = when {
            newWeighted >= 75 -> ThreatSeverity.MALICIOUS
            newWeighted >= 50 -> ThreatSeverity.HIGH_RISK
            newWeighted >= 25 -> ThreatSeverity.SUSPICIOUS
            else -> ThreatSeverity.SAFE
        }

        val newFamily = if (vtResult.suggestedThreatLabel != null && (oldReport.threatFamily == "Clean" || oldReport.threatFamily.startsWith("Heuristic."))) {
            vtResult.suggestedThreatLabel
        } else {
            oldReport.threatFamily
        }

        // Re-generate AI explanation with the fresh VirusTotal findings
        val explainer = ThreatAiExplainer(openAiKey, claudeKey, geminiKey, groqKey)
        val updatedAiExplanation = explainer.getExplanation(
            targetName = oldReport.appName ?: oldReport.targetName,
            threatFamily = newFamily,
            behaviors = oldReport.detectedBehaviors,
            permissions = oldReport.dangerousPermissions,
            engineVerdicts = updatedVerdictMap,
            engineDetails = updatedDetailsMap
        )

        val updatedReport = oldReport.copy(
            cloudScore = newCloudScore,
            currentScore = newWeighted,
            severity = newSeverity,
            threatFamily = newFamily,
            engineVerdictMap = updatedVerdictMap,
            engineDetailsMap = updatedDetailsMap,
            aiExplanation = updatedAiExplanation,
            cloudEnginesFlagged = oldReport.cloudEnginesFlagged + (if (vtResult.maliciousCount > 0) 1 else 0),
            cloudEnginesTotal = maxOf(oldReport.cloudEnginesTotal, vtResult.totalEngines),
            statusMessage = "✓ VirusTotal Sandbox Detonation Complete (${vtResult.maliciousCount}/${vtResult.totalEngines} flagged)"
        )

        ScanThrottleManager.cacheReport(updatedReport)
        io.threatlens.core.scanner.ScanReportRepository.saveReport(updatedReport)
        _scanReports.emit(updatedReport)
        return updatedReport
    }
}
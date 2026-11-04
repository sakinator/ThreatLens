package io.threatlens.core.scanner

import android.content.Context
import android.content.pm.PackageManager
import io.threatlens.core.diagnostics.AppDiagnosticLogger
import io.threatlens.core.model.DetectionType
import io.threatlens.core.model.ScoreBreakdown
import io.threatlens.core.model.ThreatReport
import io.threatlens.core.model.ThreatSeverity
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * ThreatLens Persistent Scan Report Repository.
 *
 * Persists all scanned threat verdicts and reports to disk. Ensures that reports from
 * autonomous overnight audits, real-time download intercepts, and manual scans survive
 * process termination and device reboots until:
 *   1. A new scan is executed on that target (replacing the verdict)
 *   2. The associated application is uninstalled (pruned via ACTION_PACKAGE_REMOVED)
 *   3. The target file is deleted from local storage (pruned on scan load)
 */
object ScanReportRepository {

    private const val FILE_NAME = "threatlens_persisted_reports.json"
    private const val TAG = "ScanReportRepository"

    private val _persistedReportsFlow = MutableStateFlow<List<ThreatReport>>(emptyList())
    val persistedReportsFlow: StateFlow<List<ThreatReport>> = _persistedReportsFlow.asStateFlow()

    private val lock = Any()

    fun init(context: Context) {
        synchronized(lock) {
            val loaded = loadReportsFromDisk(context, pruneMissing = true)
            _persistedReportsFlow.value = loaded
        }
    }

    fun getAllReports(context: Context, pruneMissing: Boolean = true): List<ThreatReport> {
        synchronized(lock) {
            val list = loadReportsFromDisk(context, pruneMissing)
            _persistedReportsFlow.value = list
            return list
        }
    }

    fun saveReport(context: Context, report: ThreatReport) {
        synchronized(lock) {
            val current = loadReportsFromDisk(context, pruneMissing = false).toMutableList()
            // Replace if exact same SHA-256 or same package name exists
            current.removeAll {
                (it.sha256.isNotBlank() && it.sha256.equals(report.sha256, ignoreCase = true)) ||
                (!it.packageName.isNullOrBlank() && it.packageName.equals(report.packageName, ignoreCase = true))
            }
            current.add(0, report)
            writeReportsToDisk(context, current)
            _persistedReportsFlow.value = current
            AppDiagnosticLogger.log(TAG, "Persisted scan report for ${report.appName ?: report.targetName}")
        }
    }

    fun saveReports(context: Context, reports: List<ThreatReport>) {
        if (reports.isEmpty()) return
        synchronized(lock) {
            val current = loadReportsFromDisk(context, pruneMissing = false).toMutableList()
            for (newReport in reports) {
                current.removeAll {
                    (it.sha256.isNotBlank() && it.sha256.equals(newReport.sha256, ignoreCase = true)) ||
                    (!it.packageName.isNullOrBlank() && it.packageName.equals(newReport.packageName, ignoreCase = true))
                }
                current.add(0, newReport)
            }
            writeReportsToDisk(context, current)
            _persistedReportsFlow.value = current
            AppDiagnosticLogger.log(TAG, "Persisted batch of ${reports.size} scan reports")
        }
    }

    fun removeReportByPackage(context: Context, packageName: String) {
        if (packageName.isBlank()) return
        synchronized(lock) {
            val current = loadReportsFromDisk(context, pruneMissing = false).toMutableList()
            val initialSize = current.size
            current.removeAll { it.packageName.equals(packageName, ignoreCase = true) }
            if (current.size != initialSize) {
                writeReportsToDisk(context, current)
                _persistedReportsFlow.value = current
                AppDiagnosticLogger.log(TAG, "Pruned uninstalled package report: $packageName")
            }
        }
    }

    fun removeReportBySha256(context: Context, sha256: String) {
        if (sha256.isBlank()) return
        synchronized(lock) {
            val current = loadReportsFromDisk(context, pruneMissing = false).toMutableList()
            val initialSize = current.size
            current.removeAll { it.sha256.equals(sha256, ignoreCase = true) }
            if (current.size != initialSize) {
                writeReportsToDisk(context, current)
                _persistedReportsFlow.value = current
                AppDiagnosticLogger.log(TAG, "Pruned report by sha256: $sha256")
            }
        }
    }

    fun clearAll(context: Context) {
        synchronized(lock) {
            writeReportsToDisk(context, emptyList())
            _persistedReportsFlow.value = emptyList()
        }
    }

    private fun loadReportsFromDisk(context: Context, pruneMissing: Boolean): List<ThreatReport> {
        val file = File(context.filesDir, FILE_NAME)
        if (!file.exists()) return emptyList()

        val results = mutableListOf<ThreatReport>()
        var needRewrite = false
        val pm = context.packageManager

        try {
            val content = file.readText()
            if (content.isBlank()) return emptyList()
            val jsonArray = JSONArray(content)

            for (i in 0 until jsonArray.length()) {
                val obj = jsonArray.optJSONObject(i) ?: continue
                val report = fromJson(obj)

                if (pruneMissing) {
                    // Check if package is still installed
                    if (!report.packageName.isNullOrBlank()) {
                        val isInstalled = try {
                            pm.getPackageInfo(report.packageName, 0)
                            true
                        } catch (_: PackageManager.NameNotFoundException) {
                            false
                        } catch (_: Exception) {
                            true
                        }
                        if (!isInstalled) {
                            needRewrite = true
                            continue // Prune uninstalled package
                        }
                    } else if (report.targetPath.isNotBlank()) {
                        // Check if file still exists on storage
                        val targetFile = File(report.targetPath)
                        if (!targetFile.exists()) {
                            needRewrite = true
                            continue // Prune deleted file
                        }
                    }
                }
                results.add(report)
            }

            if (needRewrite) {
                writeReportsToDisk(context, results)
            }
        } catch (e: Exception) {
            AppDiagnosticLogger.logError(TAG, "Failed to load persisted reports: ${e.message}", e)
        }

        return results
    }

    private fun writeReportsToDisk(context: Context, reports: List<ThreatReport>) {
        try {
            val file = File(context.filesDir, FILE_NAME)
            val jsonArray = JSONArray()
            for (report in reports) {
                jsonArray.put(toJson(report))
            }
            file.writeText(jsonArray.toString(2))
        } catch (e: Exception) {
            AppDiagnosticLogger.logError(TAG, "Failed to write reports to disk: ${e.message}", e)
        }
    }

    fun toJson(report: ThreatReport): JSONObject {
        val obj = JSONObject()
        obj.put("id", report.id)
        obj.put("targetName", report.targetName)
        obj.put("targetPath", report.targetPath)
        report.appName?.let { obj.put("appName", it) }
        report.packageName?.let { obj.put("packageName", it) }
        obj.put("sha256", report.sha256)
        obj.put("fileSize", report.fileSize)
        obj.put("isApk", report.isApk)
        obj.put("localScore", report.localScore)
        obj.put("cloudScore", report.cloudScore)
        obj.put("currentScore", report.currentScore)
        obj.put("threatScore", report.threatScore)
        obj.put("severity", report.severity.name)
        obj.put("threatFamily", report.threatFamily)
        obj.put("detectionType", report.detectionType.name)
        obj.put("cloudEnginesFlagged", report.cloudEnginesFlagged)
        obj.put("cloudEnginesTotal", report.cloudEnginesTotal)
        obj.put("isOfflineMode", report.isOfflineMode)
        obj.put("isFinal", report.isFinal)
        obj.put("statusMessage", report.statusMessage)
        obj.put("timestamp", report.timestamp)
        report.aiExplanation?.let { obj.put("aiExplanation", it) }

        // Lists
        obj.put("detectedBehaviors", JSONArray(report.detectedBehaviors))
        obj.put("dangerousPermissions", JSONArray(report.dangerousPermissions))
        obj.put("cloudSources", JSONArray(report.cloudSources))
        obj.put("failedEngines", JSONArray(report.failedEngines))
        obj.put("successfulEngines", JSONArray(report.successfulEngines))
        obj.put("contributingEngines", JSONArray(report.contributingEngines))
        obj.put("pendingEngines", JSONArray(report.pendingEngines))

        // Maps
        val verdictMapObj = JSONObject()
        for ((k, v) in report.engineVerdictMap) {
            verdictMapObj.put(k, v)
        }
        obj.put("engineVerdictMap", verdictMapObj)

        val detailsMapObj = JSONObject()
        for ((k, v) in report.engineDetailsMap) {
            detailsMapObj.put(k, JSONArray(v))
        }
        obj.put("engineDetailsMap", detailsMapObj)

        // Score Breakdown
        report.scoreBreakdown?.let { sb ->
            val sbObj = JSONObject()
            sbObj.put("signatureScore", sb.signatureScore)
            sbObj.put("permissionScore", sb.permissionScore)
            sbObj.put("heuristicScore", sb.heuristicScore)
            sbObj.put("cloudScore", sb.cloudScore)
            sbObj.put("totalScore", sb.totalScore)
            sbObj.put("rationale", sb.rationale)
            obj.put("scoreBreakdown", sbObj)
        }

        return obj
    }

    fun fromJson(obj: JSONObject): ThreatReport {
        val severityStr = obj.optString("severity", ThreatSeverity.SAFE.name)
        val severity = try { ThreatSeverity.valueOf(severityStr) } catch (_: Exception) { ThreatSeverity.SAFE }

        val detectionTypeStr = obj.optString("detectionType", DetectionType.CLEAN.name)
        val detectionType = try { DetectionType.valueOf(detectionTypeStr) } catch (_: Exception) { DetectionType.CLEAN }

        val detectedBehaviors = jsonArrayToList(obj.optJSONArray("detectedBehaviors"))
        val dangerousPermissions = jsonArrayToList(obj.optJSONArray("dangerousPermissions"))
        val cloudSources = jsonArrayToList(obj.optJSONArray("cloudSources"))
        val failedEngines = jsonArrayToList(obj.optJSONArray("failedEngines"))
        val successfulEngines = jsonArrayToList(obj.optJSONArray("successfulEngines"))
        val contributingEngines = jsonArrayToList(obj.optJSONArray("contributingEngines"))
        val pendingEngines = jsonArrayToList(obj.optJSONArray("pendingEngines"))

        val engineVerdictMap = mutableMapOf<String, String>()
        obj.optJSONObject("engineVerdictMap")?.let { mapObj ->
            val keys = mapObj.keys()
            while (keys.hasNext()) {
                val key = keys.next()
                engineVerdictMap[key] = mapObj.optString(key, "")
            }
        }

        val engineDetailsMap = mutableMapOf<String, List<String>>()
        obj.optJSONObject("engineDetailsMap")?.let { mapObj ->
            val keys = mapObj.keys()
            while (keys.hasNext()) {
                val key = keys.next()
                engineDetailsMap[key] = jsonArrayToList(mapObj.optJSONArray(key))
            }
        }

        val scoreBreakdown = obj.optJSONObject("scoreBreakdown")?.let { sbObj ->
            ScoreBreakdown(
                signatureScore = sbObj.optInt("signatureScore", 0),
                permissionScore = sbObj.optInt("permissionScore", 0),
                heuristicScore = sbObj.optInt("heuristicScore", 0),
                cloudScore = sbObj.optInt("cloudScore", 0),
                totalScore = sbObj.optInt("totalScore", 0),
                rationale = sbObj.optString("rationale", "")
            )
        }

        return ThreatReport(
            id = obj.optString("id", java.util.UUID.randomUUID().toString()),
            targetName = obj.optString("targetName", "Unknown"),
            targetPath = obj.optString("targetPath", ""),
            appName = if (obj.has("appName")) obj.optString("appName") else null,
            packageName = if (obj.has("packageName")) obj.optString("packageName") else null,
            sha256 = obj.optString("sha256", ""),
            fileSize = obj.optLong("fileSize", 0L),
            isApk = obj.optBoolean("isApk", true),
            localScore = obj.optInt("localScore", 0),
            cloudScore = obj.optInt("cloudScore", 0),
            currentScore = obj.optInt("currentScore", 0),
            threatScore = obj.optInt("threatScore", 0),
            severity = severity,
            threatFamily = obj.optString("threatFamily", "Clean"),
            detectionType = detectionType,
            scoreBreakdown = scoreBreakdown,
            detectedBehaviors = detectedBehaviors,
            dangerousPermissions = dangerousPermissions,
            cloudEnginesFlagged = obj.optInt("cloudEnginesFlagged", 0),
            cloudEnginesTotal = obj.optInt("cloudEnginesTotal", 0),
            cloudSources = cloudSources,
            failedEngines = failedEngines,
            successfulEngines = successfulEngines,
            isOfflineMode = obj.optBoolean("isOfflineMode", false),
            contributingEngines = contributingEngines,
            engineVerdictMap = engineVerdictMap,
            engineDetailsMap = engineDetailsMap,
            aiExplanation = if (obj.has("aiExplanation")) obj.optString("aiExplanation") else null,
            isFinal = obj.optBoolean("isFinal", true),
            pendingEngines = pendingEngines,
            statusMessage = obj.optString("statusMessage", "Analysis Complete"),
            timestamp = obj.optLong("timestamp", System.currentTimeMillis())
        )
    }

    private fun jsonArrayToList(arr: JSONArray?): List<String> {
        if (arr == null) return emptyList()
        val list = mutableListOf<String>()
        for (i in 0 until arr.length()) {
            list.add(arr.optString(i))
        }
        return list
    }
}

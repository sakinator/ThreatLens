package io.threatlens.core.export

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Environment
import android.widget.Toast
import androidx.core.content.FileProvider
import io.threatlens.core.model.ThreatReport
import io.threatlens.core.scanner.FullScanState
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.*

/**
 * Scan Report Exporter for ThreatLens.
 * Generates comprehensive machine-parseable JSON and text reports
 * for deep forensic analysis, archiving, or sharing with security teams.
 */
object ScanReportExporter {

    private val dateFormat = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US)
    private val isoFormat = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).apply {
        timeZone = TimeZone.getTimeZone("UTC")
    }

    /**
     * Exports the entire on-demand scan session results to a structured JSON file.
     */
    fun exportScanReport(
        context: Context,
        scanState: FullScanState,
        allScannedReports: List<ThreatReport>
    ): File? {
        return try {
            val timestamp = dateFormat.format(Date())
            val root = JSONObject()

            // 1. Export Metadata
            val meta = JSONObject().apply {
                put("exporter", "ThreatLens Autonomous Mobile EDR")
                put("formatVersion", "1.0")
                put("exportedAt", isoFormat.format(Date()))
                put("deviceManufacturer", Build.MANUFACTURER)
                put("deviceModel", Build.MODEL)
                put("androidRelease", Build.VERSION.RELEASE)
                put("sdkInt", Build.VERSION.SDK_INT)
            }
            root.put("metadata", meta)

            // 2. Scan Summary
            val summary = JSONObject().apply {
                put("status", scanState.status.name)
                put("totalItemsScanned", scanState.totalCount)
                put("verifiedCleanCount", scanState.cleanCount)
                put("threatsFlaggedCount", scanState.threatsFound.size)
                put("scanDurationSeconds", scanState.durationMs / 1000.0)
                put("overallPosture", if (scanState.threatsFound.isEmpty()) "CLEAN" else "DEVICE_AT_RISK")
            }
            root.put("summary", summary)

            // 3. Threats Array
            val threatsArray = JSONArray()
            for (threat in scanState.threatsFound) {
                threatsArray.put(serializeReport(threat))
            }
            root.put("threats", threatsArray)

            // 4. All Scanned Items (Clean + Flagged)
            val allItemsArray = JSONArray()
            for (item in allScannedReports) {
                allItemsArray.put(serializeReport(item))
            }
            root.put("allScannedItems", allItemsArray)

            // 5. Persist to Downloads / ThreatLens / Reports
            val targetDir = getExportDirectory(context)
            if (!targetDir.exists()) targetDir.mkdirs()

            val fileName = "ThreatLens_Scan_Report_$timestamp.json"
            val reportFile = File(targetDir, fileName)
            reportFile.writeText(root.toString(2))

            Toast.makeText(context, "Exported: ${reportFile.name}", Toast.LENGTH_LONG).show()
            reportFile
        } catch (e: Exception) {
            Toast.makeText(context, "Export failed: ${e.message}", Toast.LENGTH_SHORT).show()
            null
        }
    }

    /**
     * Exports an individual threat inspection report to JSON.
     */
    fun exportSingleThreatReport(context: Context, report: ThreatReport): File? {
        return try {
            val timestamp = dateFormat.format(Date())
            val root = JSONObject()

            val meta = JSONObject().apply {
                put("exporter", "ThreatLens Threat Assessment Exporter")
                put("exportedAt", isoFormat.format(Date()))
                put("deviceModel", "${Build.MANUFACTURER} ${Build.MODEL}")
            }
            root.put("metadata", meta)
            root.put("threat", serializeReport(report))

            val targetDir = getExportDirectory(context)
            if (!targetDir.exists()) targetDir.mkdirs()

            val safeName = (report.packageName ?: report.appName ?: "Threat").replace("[^a-zA-Z0-9._-]".toRegex(), "_")
            val fileName = "ThreatLens_${safeName}_$timestamp.json"
            val reportFile = File(targetDir, fileName)
            reportFile.writeText(root.toString(2))

            Toast.makeText(context, "Exported: ${reportFile.name}", Toast.LENGTH_LONG).show()
            reportFile
        } catch (e: Exception) {
            Toast.makeText(context, "Export failed: ${e.message}", Toast.LENGTH_SHORT).show()
            null
        }
    }

    /**
     * Dispatches an Android Share Intent with the generated JSON file.
     */
    fun shareReportFile(context: Context, file: File) {
        try {
            val authority = "${context.packageName}.fileprovider"
            val uri = FileProvider.getUriForFile(context, authority, file)

            val shareIntent = Intent(Intent.ACTION_SEND).apply {
                type = "application/json"
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_SUBJECT, "ThreatLens Security Scan Report - ${file.name}")
                putExtra(Intent.EXTRA_TEXT, "ThreatLens autonomous security inspection report attached.")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
            }

            val chooser = Intent.createChooser(shareIntent, "Export ThreatLens Scan Report").apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(chooser)
        } catch (e: Exception) {
            Toast.makeText(context, "Unable to launch share sheet: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }

    private fun serializeReport(report: ThreatReport): JSONObject {
        return JSONObject().apply {
            put("appName", report.appName ?: report.targetName)
            put("packageName", report.packageName ?: "N/A")
            put("filePath", report.targetPath)
            put("fileSizeBytes", report.fileSize)
            put("sha256", report.sha256)
            put("score", report.currentScore)
            put("severity", report.severity.name)
            put("detectionType", report.detectionType.name)
            put("threatFamily", report.threatFamily)
            put("storeProvenance", report.storeProvenance?.name ?: "UNKNOWN")

            // Score breakdown
            report.scoreBreakdown?.let { sb ->
                val sbObj = JSONObject().apply {
                    put("signatureScore", sb.signatureScore)
                    put("permissionScore", sb.permissionScore)
                    put("heuristicScore", sb.heuristicScore)
                    put("cloudScore", sb.cloudScore)
                    put("rationale", sb.rationale)
                }
                put("scoreBreakdown", sbObj)
            }

            // AI Executive Assessment
            report.aiExplanation?.let { ai ->
                val aiObj = JSONObject().apply {
                    put("executiveAssessment", ai.executiveAssessment)
                    put("confidenceLevel", ai.confidenceLevel)
                    put("recommendedAction", ai.recommendedAction)
                }
                put("aiAssessment", aiObj)
            }

            // Engine Verdicts
            val verdictsObj = JSONObject()
            report.engineVerdictMap.forEach { (engine, verdict) ->
                verdictsObj.put(engine, verdict)
            }
            put("engineVerdicts", verdictsObj)

            // Engine Details
            val detailsObj = JSONObject()
            report.engineDetailsMap.forEach { (engine, details) ->
                val arr = JSONArray()
                details.forEach { arr.put(it) }
                detailsObj.put(engine, arr)
            }
            put("engineDetails", detailsObj)

            // Behaviors & Permissions
            val behaviorsArr = JSONArray()
            report.detectedBehaviors.forEach { behaviorsArr.put(it) }
            put("detectedBehaviors", behaviorsArr)

            val permissionsArr = JSONArray()
            report.dangerousPermissions.forEach { permissionsArr.put(it) }
            put("dangerousPermissions", permissionsArr)
        }
    }

    private fun getExportDirectory(context: Context): File {
        return try {
            val pub = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            if (pub != null && pub.exists()) {
                File(pub, "ThreatLens_Reports")
            } else {
                File(context.cacheDir, "ThreatLens_Reports")
            }
        } catch (_: Exception) {
            File(context.cacheDir, "ThreatLens_Reports")
        }
    }
}

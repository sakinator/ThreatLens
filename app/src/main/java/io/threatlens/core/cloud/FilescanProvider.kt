package io.threatlens.core.cloud

import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.TimeUnit

object FilescanProvider {

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    data class FilescanResult(
        val verdict: String, // "MALICIOUS", "SUSPICIOUS", "BENIGN", "UNINDEXED"
        val threatScore: Int,
        val tags: List<String> = emptyList(),
        val reportId: String? = null,
        val isUnindexed: Boolean = (verdict == "UNINDEXED"),
        val detectedAvEngines: Int = 0,
        val totalAvEngines: Int = 0
    )

    fun queryHash(sha256: String, apiKey: String): FilescanResult? {
        if (apiKey.isBlank()) return null
        val cleanHash = sha256.trim()
        val cleanKey = apiKey.trim()

        return try {
            // 1. Check primary reputation endpoint
            val repRequest = Request.Builder()
                .url("https://www.filescan.io/api/reputation/hash?sha256=$cleanHash")
                .addHeader("X-Api-Key", cleanKey)
                .addHeader("Authorization", "Bearer $cleanKey")
                .addHeader("User-Agent", "ThreatLens-Security/1.5.5")
                .get()
                .build()

            client.newCall(repRequest).execute().use { response ->
                if (response.code == 404) {
                    return FilescanResult("BENIGN", 0, emptyList(), isUnindexed = true)
                }
                if (response.code == 401 || response.code == 403) {
                    return null
                }
                if (response.isSuccessful) {
                    val raw = response.body?.string() ?: return null
                    val root = JSONObject(raw)

                    val respHash = root.optString("sha256", "")
                    if (respHash.isNotBlank() && !respHash.equals(cleanHash, ignoreCase = true)) {
                        return FilescanResult("BENIGN", 0, emptyList(), isUnindexed = true)
                    }

                    val overallVerdict = root.optString("overall_verdict", "unknown").uppercase()
                    val mdcloud = root.optJSONObject("mdcloud")
                    val detectedAv = mdcloud?.optInt("detected_av_engines", 0) ?: 0
                    val totalAv = mdcloud?.optInt("total_av_engines", 0) ?: 0

                    val tagList = mutableListOf<String>()
                    val reports = root.optJSONArray("filescan_reports")
                    var reportVerdict = ""
                    var reportId: String? = null
                    if (reports != null && reports.length() > 0) {
                        val latest = reports.getJSONObject(0)
                        reportVerdict = latest.optString("verdict", "").uppercase()
                        reportId = latest.optString("report_id", "").ifBlank { null }

                        val tagsArray = latest.optJSONArray("tags") ?: latest.optJSONArray("all_tags")
                        if (tagsArray != null) {
                            for (i in 0 until tagsArray.length()) {
                                val item = tagsArray.opt(i)
                                if (item is JSONObject) {
                                    val tagName = item.optJSONObject("tag")?.optString("name") ?: item.optString("name")
                                    if (!tagName.isNullOrBlank() && tagName !in tagList) tagList.add(tagName)
                                } else if (item is String && item.isNotBlank() && item !in tagList) {
                                    tagList.add(item)
                                }
                            }
                        }
                    }

                    if (detectedAv > 0) {
                        tagList.add(0, "MDCloud: $detectedAv/$totalAv AV engines flagged")
                    }

                    val isUnindexed = (overallVerdict == "UNKNOWN" || overallVerdict.isBlank()) && (reports == null || reports.length() == 0) && detectedAv == 0

                    val finalVerdict = when {
                        detectedAv > 0 || overallVerdict == "MALICIOUS" || reportVerdict == "MALICIOUS" -> "MALICIOUS"
                        overallVerdict == "SUSPICIOUS" || reportVerdict == "SUSPICIOUS" -> "SUSPICIOUS"
                        overallVerdict in listOf("BENIGN", "NO_THREAT") || reportVerdict in listOf("BENIGN", "NO_THREAT") -> "BENIGN"
                        isUnindexed -> "UNINDEXED"
                        else -> "BENIGN"
                    }

                    val threatScore = when (finalVerdict) {
                        "MALICIOUS" -> if (detectedAv > 0) maxOf(85, minOf(100, 70 + (detectedAv * 5))) else 90
                        "SUSPICIOUS" -> 60
                        else -> 0
                    }

                    return FilescanResult(
                        verdict = finalVerdict,
                        threatScore = threatScore,
                        tags = tagList,
                        reportId = reportId,
                        isUnindexed = isUnindexed,
                        detectedAvEngines = detectedAv,
                        totalAvEngines = totalAv
                    )
                }
            }

            // 2. Fallback to reports/search if reputation endpoint had unexpected response
            val searchRequest = Request.Builder()
                .url("https://www.filescan.io/api/reports/search?query=$cleanHash")
                .addHeader("X-Api-Key", cleanKey)
                .addHeader("Authorization", "Bearer $cleanKey")
                .addHeader("User-Agent", "ThreatLens-Security/1.5.5")
                .get()
                .build()

            client.newCall(searchRequest).execute().use { response ->
                if (response.code == 404) return FilescanResult("BENIGN", 0, emptyList(), isUnindexed = true)
                if (!response.isSuccessful) return null
                val raw = response.body?.string() ?: return null
                val root = JSONObject(raw)
                val items = root.optJSONArray("items") ?: root.optJSONArray("reports") ?: return FilescanResult("BENIGN", 0, emptyList(), isUnindexed = true)
                if (items.length() == 0) return FilescanResult("BENIGN", 0, emptyList(), isUnindexed = true)

                // CRITICAL SECURITY FIX: Find the specific report matching the target cleanHash.
                // Filescan's search endpoint without matching returns global public detonations!
                var matchedReport: JSONObject? = null
                for (i in 0 until items.length()) {
                    val candidate = items.optJSONObject(i) ?: continue
                    val fileObj = candidate.optJSONObject("file")
                    val candidateHash = fileObj?.optString("sha256")
                        ?: fileObj?.optString("hash")
                        ?: candidate.optString("sha256")
                        ?: candidate.optString("hash")
                    if (candidateHash.isNotBlank() && candidateHash.equals(cleanHash, ignoreCase = true)) {
                        matchedReport = candidate
                        break
                    }
                }

                if (matchedReport == null) {
                    // No report found for this specific hash
                    return FilescanResult("BENIGN", 0, emptyList(), isUnindexed = true)
                }

                val verdict = matchedReport.optString("verdict", "UNKNOWN").uppercase()
                val reportId = matchedReport.optString("report_id", "").ifBlank { matchedReport.optString("id", "").ifBlank { null } }
                val isUnindexed = verdict == "UNKNOWN" || verdict.isBlank()
                val finalVerdict = if (isUnindexed) "UNINDEXED" else verdict
                val threatScore = when (finalVerdict) {
                    "MALICIOUS" -> 90
                    "SUSPICIOUS" -> 60
                    else -> 0
                }
                val tagList = mutableListOf<String>()
                val tagsArray = matchedReport.optJSONArray("tags")
                if (tagsArray != null) {
                    for (i in 0 until tagsArray.length()) {
                        val item = tagsArray.opt(i)
                        if (item is JSONObject) {
                            val tagName = item.optJSONObject("tag")?.optString("name") ?: item.optString("name")
                            if (!tagName.isNullOrBlank() && tagName !in tagList) tagList.add(tagName)
                        } else if (item is String && item.isNotBlank() && item !in tagList) {
                            tagList.add(item)
                        }
                    }
                }
                FilescanResult(
                    verdict = finalVerdict,
                    threatScore = threatScore,
                    tags = tagList,
                    reportId = reportId,
                    isUnindexed = isUnindexed
                )
            }
        } catch (e: Exception) {
            null
        }
    }
}

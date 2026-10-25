package io.threatlens.core.cloud

import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.TimeUnit

object VirusTotalProvider {

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    data class VtResult(
        val maliciousCount: Int,
        val suspiciousCount: Int,
        val totalEngines: Int,
        val suggestedThreatLabel: String?,
        val detectedVendors: List<String>
    )

    fun queryHash(sha256: String, apiKey: String): VtResult? {
        if (apiKey.isBlank()) return null
        return try {
            val request = Request.Builder()
                .url("https://www.virustotal.com/api/v3/files/$sha256")
                .addHeader("x-apikey", apiKey.trim())
                .addHeader("Accept", "application/json")
                .get()
                .build()

            client.newCall(request).execute().use { response ->
                if (response.code == 404) {
                    // Unknown to VirusTotal - not necessarily malicious
                    return VtResult(0, 0, 0, null, emptyList())
                }
                if (!response.isSuccessful) return null
                val raw = response.body?.string() ?: return null
                val root = JSONObject(raw)
                val attributes = root.getJSONObject("data").getJSONObject("attributes")
                val stats = attributes.getJSONObject("last_analysis_stats")

                val malicious = stats.optInt("malicious", 0)
                val suspicious = stats.optInt("suspicious", 0)
                val harmless = stats.optInt("harmless", 0)
                val undetected = stats.optInt("undetected", 0)
                val total = malicious + suspicious + harmless + undetected

                val label = attributes.optJSONObject("popular_threat_classification")
                    ?.optString("suggested_threat_label")

                val flaggedVendors = mutableListOf<String>()
                val resultsObj = attributes.optJSONObject("last_analysis_results")
                if (resultsObj != null) {
                    val keys = resultsObj.keys()
                    while (keys.hasNext()) {
                        val engineName = keys.next()
                        val engineResult = resultsObj.getJSONObject(engineName)
                        val category = engineResult.optString("category")
                        if (category == "malicious" || category == "suspicious") {
                            flaggedVendors.add("$engineName: ${engineResult.optString("result", "threat")}")
                        }
                    }
                }

                VtResult(
                    maliciousCount = malicious,
                    suspiciousCount = suspicious,
                    totalEngines = total,
                    suggestedThreatLabel = label,
                    detectedVendors = flaggedVendors
                )
            }
        } catch (e: Exception) {
            null
        }
    }
}

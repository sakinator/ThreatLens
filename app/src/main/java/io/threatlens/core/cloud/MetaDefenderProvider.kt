package io.threatlens.core.cloud

import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.TimeUnit

object MetaDefenderProvider {

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    data class MetaDefenderResult(
        val threatFound: Boolean,
        val enginesFlagged: Int,
        val totalEngines: Int,
        val threatName: String?,
        val detectedVendors: List<String> = emptyList()
    )

    fun queryHash(sha256: String, apiKey: String): MetaDefenderResult? {
        if (apiKey.isBlank()) return null
        return try {
            val request = Request.Builder()
                .url("https://api.metadefender.com/v4/hash/$sha256")
                .addHeader("apikey", apiKey.trim())
                .get()
                .build()

            client.newCall(request).execute().use { response ->
                if (response.code == 404) {
                    return MetaDefenderResult(false, 0, 0, null, emptyList())
                }
                if (!response.isSuccessful) return null
                val raw = response.body?.string() ?: return null
                val root = JSONObject(raw)
                val scanResults = root.optJSONObject("scan_results") ?: return null

                val totalEngines = scanResults.optInt("total_avs", 0)
                val detectedEngines = scanResults.optInt("total_detected_avs", 0)
                val scanDetails = scanResults.optJSONObject("scan_details")

                var topThreatName: String? = null
                val flaggedVendors = mutableListOf<String>()
                if (scanDetails != null && detectedEngines > 0) {
                    val keys = scanDetails.keys()
                    while (keys.hasNext()) {
                        val engine = keys.next()
                        val result = scanDetails.getJSONObject(engine)
                        val threat = result.optString("threat_found")
                        if (!threat.isNullOrBlank()) {
                            if (topThreatName == null) topThreatName = threat
                            flaggedVendors.add("$engine: $threat")
                        }
                    }
                }

                MetaDefenderResult(
                    threatFound = detectedEngines > 0,
                    enginesFlagged = detectedEngines,
                    totalEngines = totalEngines,
                    threatName = topThreatName,
                    detectedVendors = flaggedVendors
                )
            }
        } catch (e: Exception) {
            null
        }
    }
}

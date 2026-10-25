package io.threatlens.core.cloud

import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.TimeUnit

object AlienVaultOtxProvider {

    private val client = OkHttpClient.Builder()
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(8, TimeUnit.SECONDS)
        .build()

    data class OtxResult(
        val isMalicious: Boolean,
        val pulseCount: Int,
        val threatFamily: String?,
        val tags: List<String>,
        val details: String
    )

    fun queryHash(sha256: String): OtxResult? {
        return try {
            val url = "https://otx.alienvault.com/api/v1/indicators/file/$sha256/general"
            val request = Request.Builder()
                .url(url)
                .header("User-Agent", "ThreatLens-Android-Security/1.3.1")
                .header("Accept", "application/json")
                .get()
                .build()

            client.newCall(request).execute().use { response ->
                if (response.code == 404) {
                    // Not indexed in OTX pulses -> clean / unflagged
                    return OtxResult(
                        isMalicious = false,
                        pulseCount = 0,
                        threatFamily = null,
                        tags = emptyList(),
                        details = "Clean (0 threat pulses)"
                    )
                }
                if (!response.isSuccessful) return null
                val raw = response.body?.string() ?: return null
                val json = JSONObject(raw)

                val pulseInfo = json.optJSONObject("pulse_info")
                val pulseCount = pulseInfo?.optInt("count", 0) ?: 0
                val pulses = pulseInfo?.optJSONArray("pulses")

                val tags = mutableListOf<String>()
                var detectedFamily: String? = null

                if (pulses != null && pulses.length() > 0) {
                    for (i in 0 until minOf(pulses.length(), 5)) {
                        val p = pulses.optJSONObject(i) ?: continue
                        val name = p.optString("name")
                        if (detectedFamily == null && name.isNotBlank()) {
                            detectedFamily = name
                        }
                        val pTags = p.optJSONArray("tags")
                        if (pTags != null) {
                            for (t in 0 until pTags.length()) {
                                val tag = pTags.optString(t)
                                if (tag.isNotBlank() && !tags.contains(tag)) {
                                    tags.add(tag)
                                }
                            }
                        }
                    }
                }

                val isMalicious = pulseCount > 0
                val details = if (isMalicious) {
                    "Flagged in $pulseCount AlienVault threat pulse(s)"
                } else {
                    "Clean (0 AlienVault threat pulses)"
                }

                OtxResult(
                    isMalicious = isMalicious,
                    pulseCount = pulseCount,
                    threatFamily = detectedFamily,
                    tags = tags,
                    details = details
                )
            }
        } catch (_: Exception) {
            null
        }
    }
}

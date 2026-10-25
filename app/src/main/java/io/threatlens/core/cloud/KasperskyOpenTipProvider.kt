package io.threatlens.core.cloud

import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.TimeUnit

object KasperskyOpenTipProvider {

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    data class OpenTipResult(
        val zone: String, // "Red", "Yellow", "Green", "Grey"
        val threatFamily: String?
    )

    fun queryHash(sha256: String, apiKey: String): OpenTipResult? {
        if (apiKey.isBlank()) return null
        return try {
            val request = Request.Builder()
                .url("https://opentip.kaspersky.com/api/v1/search/hash?request=$sha256")
                .addHeader("x-api-key", apiKey.trim())
                .get()
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return null
                val raw = response.body?.string() ?: return null
                val root = JSONObject(raw)
                val zone = root.optString("Zone", "Grey")
                val threat = root.optJSONArray("Threats")?.optJSONObject(0)?.optString("Threat")

                OpenTipResult(zone, threat)
            }
        } catch (e: Exception) {
            null
        }
    }
}

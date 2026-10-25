package io.threatlens.core.cloud

import okhttp3.*
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.TimeUnit

object HybridAnalysisProvider {

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    data class HaResult(
        val threatScore: Int,
        val verdict: String,
        val vxFamily: String?
    )

    fun queryHash(sha256: String, apiKey: String): HaResult? {
        if (apiKey.isBlank()) return null
        return try {
            val body = FormBody.Builder()
                .add("hash", sha256)
                .build()

            val request = Request.Builder()
                .url("https://www.hybrid-analysis.com/api/v2/search/hash")
                .addHeader("api-key", apiKey.trim())
                .addHeader("User-Agent", "Falcon Sandbox")
                .post(body)
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return null
                val raw = response.body?.string() ?: return null
                val array = JSONArray(raw)
                if (array.length() == 0) return null

                val item = array.getJSONObject(0)
                val threatScore = item.optInt("threat_score", 0)
                val verdict = item.optString("verdict", "unknown")
                val vxFamily = item.optString("vx_family", null)

                HaResult(threatScore, verdict, vxFamily)
            }
        } catch (e: Exception) {
            null
        }
    }
}

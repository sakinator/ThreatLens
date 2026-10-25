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
        val verdict: String, // "MALICIOUS", "SUSPICIOUS", "BENIGN", "UNKNOWN"
        val threatScore: Int,
        val tags: List<String>
    )

    fun queryHash(sha256: String, apiKey: String): FilescanResult? {
        if (apiKey.isBlank()) return null
        return try {
            val request = Request.Builder()
                .url("https://www.filescan.io/api/reports/search?value=$sha256")
                .addHeader("Authorization", "Bearer ${apiKey.trim()}")
                .get()
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return null
                val raw = response.body?.string() ?: return null
                val root = JSONObject(raw)
                val reports = root.optJSONArray("reports") ?: return null
                if (reports.length() == 0) return null

                val latest = reports.getJSONObject(0)
                val verdict = latest.optString("verdict", "UNKNOWN")
                val threatScore = latest.optInt("threat_score", 0)
                val tagList = mutableListOf<String>()

                val tagsArray = latest.optJSONArray("tags")
                if (tagsArray != null) {
                    for (i in 0 until tagsArray.length()) {
                        tagList.add(tagsArray.getString(i))
                    }
                }

                FilescanResult(verdict, threatScore, tagList)
            }
        } catch (e: Exception) {
            null
        }
    }
}

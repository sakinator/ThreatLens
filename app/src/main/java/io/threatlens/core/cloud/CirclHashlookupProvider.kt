package io.threatlens.core.cloud

import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.TimeUnit

object CirclHashlookupProvider {

    private val client = OkHttpClient.Builder()
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(8, TimeUnit.SECONDS)
        .build()

    data class CirclResult(
        val isIndexed: Boolean,
        val isMalicious: Boolean,
        val fileName: String?,
        val details: String
    )

    fun queryHash(sha256: String): CirclResult? {
        return try {
            val url = "https://hashlookup.circl.lu/lookup/sha256/$sha256"
            val request = Request.Builder()
                .url(url)
                .header("User-Agent", "ThreatLens-Android-Security/1.3.1")
                .header("Accept", "application/json")
                .get()
                .build()

            client.newCall(request).execute().use { response ->
                if (response.code == 404) {
                    return CirclResult(
                        isIndexed = false,
                        isMalicious = false,
                        fileName = null,
                        details = "Clean (Unindexed in CIRCL database)"
                    )
                }
                if (!response.isSuccessful) return null
                val raw = response.body?.string() ?: return null
                val json = JSONObject(raw)

                val fileName = json.optString("FileName")
                val isKnownMalicious = json.optBoolean("malicious", false) || json.has("threat")

                val details = when {
                    isKnownMalicious -> "Flagged as known threat in CIRCL CERT database"
                    fileName.isNotBlank() -> "Verified in NIST NSRL Reference Library"
                    else -> "Indexed in CIRCL global database"
                }

                CirclResult(
                    isIndexed = true,
                    isMalicious = isKnownMalicious,
                    fileName = fileName.takeIf { it.isNotBlank() },
                    details = details
                )
            }
        } catch (_: Exception) {
            null
        }
    }
}

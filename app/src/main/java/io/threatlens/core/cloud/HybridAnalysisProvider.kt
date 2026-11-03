package io.threatlens.core.cloud

import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.asRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.TimeUnit

object HybridAnalysisProvider {

    private val client = OkHttpClient.Builder()
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .build()

    data class HaResult(
        val threatScore: Int,
        val verdict: String,
        val vxFamily: String?,
        val isUnindexed: Boolean = (verdict == "UNINDEXED"),
        val submissionId: String? = null
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
                if (array.length() == 0) {
                    return HaResult(threatScore = 0, verdict = "UNINDEXED", vxFamily = null, isUnindexed = true)
                }

                val item = array.getJSONObject(0)
                val threatScore = item.optInt("threat_score", 0)
                val verdict = item.optString("verdict", "unknown")
                val vxFamily = item.optString("vx_family", null)

                HaResult(threatScore, verdict, vxFamily, isUnindexed = false)
            }
        } catch (e: Exception) {
            null
        }
    }

    fun submitFileForScan(file: File, apiKey: String): HaResult? {
        if (apiKey.isBlank() || !file.exists() || file.length() == 0L) return null
        return try {
            val mediaType = "application/vnd.android.package-archive".toMediaTypeOrNull() ?: "application/octet-stream".toMediaType()
            val fileBody = file.asRequestBody(mediaType)
            val requestBody = MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart("file", file.name, fileBody)
                .addFormDataPart("scan_type", "all")
                .build()

            val request = Request.Builder()
                .url("https://www.hybrid-analysis.com/api/v2/quick-scan/file")
                .addHeader("api-key", apiKey.trim())
                .addHeader("User-Agent", "Falcon Sandbox")
                .post(requestBody)
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return null
                val raw = response.body?.string() ?: return null
                val root = JSONObject(raw)
                val id = root.optString("id", root.optString("sha256", "Submitted"))
                val score = root.optInt("threat_score", 0)
                val verdict = root.optString("verdict", "QUEUED")
                HaResult(score, verdict, null, isUnindexed = false, submissionId = id)
            }
        } catch (e: Exception) {
            null
        }
    }
}

package io.threatlens.core.cloud

import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.asRequestBody
import okio.Buffer
import okio.BufferedSink
import okio.ForwardingSink
import okio.buffer
import org.json.JSONObject
import java.io.File
import java.util.concurrent.TimeUnit

object VirusTotalProvider {

    private val client = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(60, TimeUnit.SECONDS)
        .writeTimeout(60, TimeUnit.SECONDS)
        .build()

    data class VtResult(
        val maliciousCount: Int,
        val suspiciousCount: Int,
        val totalEngines: Int,
        val suggestedThreatLabel: String?,
        val detectedVendors: List<String>
    )

    sealed class UploadProgress {
        object Idle : UploadProgress()
        data class Uploading(val bytesSent: Long, val totalBytes: Long, val percentage: Int) : UploadProgress()
        data class Queued(val analysisId: String) : UploadProgress()
        data class InProgress(val completedEngines: Int, val totalEngines: Int) : UploadProgress()
        data class Completed(val result: VtResult) : UploadProgress()
        data class Error(val message: String) : UploadProgress()
    }

    private class CountingRequestBody(
        private val delegate: RequestBody,
        private val onProgress: (bytesWritten: Long, totalBytes: Long) -> Unit
    ) : RequestBody() {
        override fun contentType() = delegate.contentType()
        override fun contentLength() = delegate.contentLength()

        override fun writeTo(sink: BufferedSink) {
            val countingSink = object : ForwardingSink(sink) {
                private var bytesWritten = 0L
                private val totalBytes = contentLength()

                override fun write(source: Buffer, byteCount: Long) {
                    super.write(source, byteCount)
                    bytesWritten += byteCount
                    onProgress(bytesWritten, totalBytes)
                }
            }
            val buffered = countingSink.buffer()
            delegate.writeTo(buffered)
            buffered.flush()
        }
    }

    private fun parseVtAttributes(attributes: JSONObject): VtResult {
        val stats = attributes.optJSONObject("last_analysis_stats")
            ?: attributes.optJSONObject("stats")
            ?: JSONObject()

        val malicious = stats.optInt("malicious", 0)
        val suspicious = stats.optInt("suspicious", 0)
        val harmless = stats.optInt("harmless", 0)
        val undetected = stats.optInt("undetected", 0)
        val total = malicious + suspicious + harmless + undetected

        val rawLabel = attributes.optJSONObject("popular_threat_classification")
            ?.optString("suggested_threat_label")?.trim()

        val flaggedVendors = mutableListOf<String>()
        val resultsObj = attributes.optJSONObject("last_analysis_results")
            ?: attributes.optJSONObject("results")

        if (resultsObj != null) {
            val keys = resultsObj.keys()
            while (keys.hasNext()) {
                val engineName = keys.next()
                val engineResult = resultsObj.getJSONObject(engineName)
                val category = engineResult.optString("category")
                if (category == "malicious" || category == "suspicious") {
                    val res = engineResult.optString("result", "Flagged")
                    flaggedVendors.add("$engineName: $res")
                }
            }
        }

        val resolvedLabel = if (!rawLabel.isNullOrBlank() && rawLabel.length > 5 && !rawLabel.equals("malct", ignoreCase = true)) {
            rawLabel
        } else {
            val topHit = flaggedVendors.firstOrNull { vendor ->
                vendor.startsWith("Kaspersky", ignoreCase = true) ||
                vendor.startsWith("Microsoft", ignoreCase = true) ||
                vendor.startsWith("Avast", ignoreCase = true) ||
                vendor.startsWith("ESET", ignoreCase = true) ||
                vendor.startsWith("Sophos", ignoreCase = true) ||
                vendor.startsWith("Google", ignoreCase = true)
            }?.substringAfter(": ")?.trim()

            topHit ?: flaggedVendors.firstOrNull()?.substringAfter(": ")?.trim() ?: rawLabel?.ifBlank { null }
        }

        return VtResult(
            maliciousCount = malicious,
            suspiciousCount = suspicious,
            totalEngines = total,
            suggestedThreatLabel = resolvedLabel,
            detectedVendors = flaggedVendors
        )
    }

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
                    return VtResult(0, 0, 0, null, emptyList())
                }
                if (!response.isSuccessful) return null
                val raw = response.body?.string() ?: return null
                val root = JSONObject(raw)
                val attributes = root.getJSONObject("data").getJSONObject("attributes")
                parseVtAttributes(attributes)
            }
        } catch (e: Exception) {
            null
        }
    }

    fun uploadFileForDeepAnalysis(
        file: File,
        apiKey: String
    ): Flow<UploadProgress> = channelFlow {
        if (apiKey.isBlank()) {
            send(UploadProgress.Error("VirusTotal API Key is missing. Please configure in Settings."))
            return@channelFlow
        }
        if (!file.exists() || file.length() == 0L) {
            send(UploadProgress.Error("Target APK file could not be accessed on storage."))
            return@channelFlow
        }

        try {
            // Step 1: Resolve Upload URL (Files > 32MB require a special upload URL)
            val uploadUrl = if (file.length() > 32 * 1024 * 1024) {
                val urlReq = Request.Builder()
                    .url("https://www.virustotal.com/api/v3/files/upload_url")
                    .addHeader("x-apikey", apiKey.trim())
                    .get()
                    .build()
                client.newCall(urlReq).execute().use { res ->
                    if (!res.isSuccessful) {
                        send(UploadProgress.Error("VirusTotal rejected upload URL request (HTTP ${res.code})"))
                        return@channelFlow
                    }
                    val json = JSONObject(res.body?.string() ?: "{}")
                    json.optString("data", "https://www.virustotal.com/api/v3/files")
                }
            } else {
                "https://www.virustotal.com/api/v3/files"
            }

            // Step 2: Stream multipart upload with progressive byte counter
            val rawBody = file.asRequestBody("application/vnd.android.package-archive".toMediaType())
            val countingBody = CountingRequestBody(rawBody) { bytesWritten, totalBytes ->
                val pct = if (totalBytes > 0) ((bytesWritten * 100) / totalBytes).toInt().coerceIn(0, 100) else 0
                trySend(UploadProgress.Uploading(bytesWritten, totalBytes, pct))
            }

            val multipartBody = MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart("file", file.name, countingBody)
                .build()

            val uploadRequest = Request.Builder()
                .url(uploadUrl)
                .addHeader("x-apikey", apiKey.trim())
                .post(multipartBody)
                .build()

            val analysisId = client.newCall(uploadRequest).execute().use { response ->
                if (!response.isSuccessful) {
                    send(UploadProgress.Error("Upload failed (HTTP ${response.code}: ${response.message})"))
                    return@channelFlow
                }
                val raw = response.body?.string() ?: "{}"
                val json = JSONObject(raw)
                json.getJSONObject("data").getString("id")
            }

            send(UploadProgress.Queued(analysisId))

            // Step 3: Progressive Polling Feedback Loop (Polls every 3s up to 15 times = 45s)
            var pollCount = 0
            val maxPolls = 15

            while (pollCount < maxPolls) {
                delay(3000)
                pollCount++

                val pollReq = Request.Builder()
                    .url("https://www.virustotal.com/api/v3/analyses/$analysisId")
                    .addHeader("x-apikey", apiKey.trim())
                    .get()
                    .build()

                val isDone = client.newCall(pollReq).execute().use { pollRes ->
                    if (!pollRes.isSuccessful) return@use false
                    val pollRaw = pollRes.body?.string() ?: return@use false
                    val pollRoot = JSONObject(pollRaw)
                    val attrs = pollRoot.getJSONObject("data").getJSONObject("attributes")
                    val status = attrs.optString("status")

                    val resultsObj = attrs.optJSONObject("results")
                    val completedCount = resultsObj?.length() ?: 0

                    if (status.equals("completed", ignoreCase = true)) {
                        val finalResult = parseVtAttributes(attrs)
                        send(UploadProgress.Completed(finalResult))
                        true
                    } else {
                        send(UploadProgress.InProgress(completedEngines = maxOf(completedCount, 1), totalEngines = 72))
                        false
                    }
                }

                if (isDone) return@channelFlow
            }

            // If timeout in analysis queue, check if hash report is ready
            send(UploadProgress.InProgress(completedEngines = 70, totalEngines = 72))
            val hash = io.threatlens.core.local.HashUtil.sha256(file)
            val fallbackResult = queryHash(hash, apiKey)
            if (fallbackResult != null && fallbackResult.totalEngines > 0) {
                send(UploadProgress.Completed(fallbackResult))
            } else {
                send(UploadProgress.Error("Detonation queued on VirusTotal. Results will appear once sandbox processing completes."))
            }

        } catch (e: Exception) {
            send(UploadProgress.Error("Upload error: ${e.message ?: "Network failure"}"))
        }
    }
}

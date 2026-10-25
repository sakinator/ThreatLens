package io.threatlens.core.vpn

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

object DohResolver {

    private val _isDohEnabled = MutableStateFlow(true) // Enabled by default for encrypted privacy!
    val isDohEnabled: StateFlow<Boolean> = _isDohEnabled.asStateFlow()

    private val dnsMediaType = "application/dns-message".toMediaType()

    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(3, TimeUnit.SECONDS)
        .readTimeout(3, TimeUnit.SECONDS)
        .writeTimeout(3, TimeUnit.SECONDS)
        .retryOnConnectionFailure(true)
        .build()

    fun setDohEnabled(enabled: Boolean) {
        _isDohEnabled.value = enabled
    }

    suspend fun resolveQuery(dohUrl: String, rawDnsQuery: ByteArray): ByteArray? = withContext(Dispatchers.IO) {
        try {
            val body = rawDnsQuery.toRequestBody(dnsMediaType)
            val request = Request.Builder()
                .url(dohUrl)
                .post(body)
                .header("Content-Type", "application/dns-message")
                .header("Accept", "application/dns-message")
                .build()

            val response = httpClient.newCall(request).execute()
            if (response.isSuccessful) {
                val bytes = response.body?.bytes()
                if (bytes != null && bytes.isNotEmpty()) {
                    return@withContext bytes
                }
            }
            null
        } catch (_: Exception) {
            null
        }
    }
}

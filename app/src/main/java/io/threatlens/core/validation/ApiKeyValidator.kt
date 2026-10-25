package io.threatlens.core.validation

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

sealed class ValidationStatus {
    object Idle : ValidationStatus()
    object Validating : ValidationStatus()
    data class Valid(val message: String = "Key Verified & Active") : ValidationStatus()
    data class Invalid(val error: String) : ValidationStatus()
}

object ApiKeyValidator {
    private val client = OkHttpClient.Builder()
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(8, TimeUnit.SECONDS)
        .build()

    suspend fun validate(provider: String, key: String): ValidationStatus = withContext(Dispatchers.IO) {
        val trimmed = key.trim()
        if (trimmed.isBlank()) {
            return@withContext ValidationStatus.Invalid("Key cannot be empty")
        }

        try {
            when (provider.lowercase()) {
                "openai" -> {
                    val request = Request.Builder()
                        .url("https://api.openai.com/v1/models")
                        .addHeader("Authorization", "Bearer $trimmed")
                        .build()
                    client.newCall(request).execute().use { resp ->
                        when {
                            resp.isSuccessful -> ValidationStatus.Valid("OpenAI API Connected (HTTP ${resp.code})")
                            resp.code == 401 -> ValidationStatus.Invalid("Invalid API Key (HTTP 401 Unauthorized)")
                            resp.code == 429 -> ValidationStatus.Valid("Key verified (HTTP 429: Rate limit / Quota)")
                            else -> ValidationStatus.Invalid("HTTP Error ${resp.code}")
                        }
                    }
                }
                "claude" -> {
                    val body = """{"model":"claude-3-haiku-20240307","max_tokens":1,"messages":[{"role":"user","content":"ping"}]}"""
                        .toRequestBody("application/json".toMediaType())
                    val request = Request.Builder()
                        .url("https://api.anthropic.com/v1/messages")
                        .addHeader("x-api-key", trimmed)
                        .addHeader("anthropic-version", "2023-06-01")
                        .post(body)
                        .build()
                    client.newCall(request).execute().use { resp ->
                        when {
                            resp.isSuccessful || resp.code == 400 || resp.code == 429 -> {
                                if (resp.code == 401) ValidationStatus.Invalid("Invalid API Key (HTTP 401 Unauthorized)")
                                else ValidationStatus.Valid("Claude API Connected (HTTP ${resp.code})")
                            }
                            resp.code == 401 -> ValidationStatus.Invalid("Invalid API Key (HTTP 401 Unauthorized)")
                            else -> ValidationStatus.Invalid("HTTP Error ${resp.code}")
                        }
                    }
                }
                "gemini" -> {
                    val request = Request.Builder()
                        .url("https://generativelanguage.googleapis.com/v1beta/models?key=$trimmed")
                        .build()
                    client.newCall(request).execute().use { resp ->
                        if (resp.isSuccessful) {
                            ValidationStatus.Valid("Google Gemini Connected (HTTP ${resp.code})")
                        } else {
                            ValidationStatus.Invalid("Invalid Gemini Key (HTTP ${resp.code})")
                        }
                    }
                }
                "groq" -> {
                    val request = Request.Builder()
                        .url("https://api.groq.com/openai/v1/models")
                        .addHeader("Authorization", "Bearer $trimmed")
                        .build()
                    client.newCall(request).execute().use { resp ->
                        if (resp.isSuccessful) {
                            ValidationStatus.Valid("Groq API Connected (HTTP ${resp.code})")
                        } else {
                            ValidationStatus.Invalid("Invalid Groq Key (HTTP ${resp.code})")
                        }
                    }
                }
                "vt", "virustotal" -> {
                    val request = Request.Builder()
                        .url("https://www.virustotal.com/api/v3/metadata")
                        .addHeader("x-apikey", trimmed)
                        .build()
                    client.newCall(request).execute().use { resp ->
                        if (resp.isSuccessful) {
                            ValidationStatus.Valid("VirusTotal Connected (HTTP ${resp.code})")
                        } else {
                            ValidationStatus.Invalid("Invalid VirusTotal Key (HTTP ${resp.code})")
                        }
                    }
                }
                "metadefender" -> {
                    val request = Request.Builder()
                        .url("https://api.metadefender.com/v4/stat/limits")
                        .addHeader("apikey", trimmed)
                        .build()
                    client.newCall(request).execute().use { resp ->
                        if (resp.isSuccessful) {
                            ValidationStatus.Valid("MetaDefender Connected (HTTP ${resp.code})")
                        } else {
                            ValidationStatus.Invalid("Invalid MetaDefender Key (HTTP ${resp.code})")
                        }
                    }
                }
                "ha", "hybridanalysis" -> {
                    val request = Request.Builder()
                        .url("https://www.hybrid-analysis.com/api/v2/key/current")
                        .addHeader("api-key", trimmed)
                        .addHeader("User-Agent", "Falcon Sandbox")
                        .build()
                    client.newCall(request).execute().use { resp ->
                        if (resp.isSuccessful) {
                            ValidationStatus.Valid("Hybrid Analysis Connected (HTTP ${resp.code})")
                        } else {
                            ValidationStatus.Invalid("Invalid Hybrid Analysis Key (HTTP ${resp.code})")
                        }
                    }
                }
                "kaspersky" -> {
                    val request = Request.Builder()
                        .url("https://opentip.kaspersky.com/api/v1/limits")
                        .addHeader("x-api-key", trimmed)
                        .build()
                    client.newCall(request).execute().use { resp ->
                        if (resp.isSuccessful) {
                            ValidationStatus.Valid("Kaspersky OpenTIP Connected (HTTP ${resp.code})")
                        } else {
                            ValidationStatus.Invalid("Invalid Kaspersky Key (HTTP ${resp.code})")
                        }
                    }
                }
                "filescan" -> {
                    val request = Request.Builder()
                        .url("https://www.filescan.io/api/v1/users/me")
                        .addHeader("Authorization", "Bearer $trimmed")
                        .build()
                    client.newCall(request).execute().use { resp ->
                        if (resp.isSuccessful) {
                            ValidationStatus.Valid("Filescan.io Connected (HTTP ${resp.code})")
                        } else {
                            ValidationStatus.Invalid("Invalid Filescan Key (HTTP ${resp.code})")
                        }
                    }
                }
                "bazaar", "malwarebazaar", "abusech" -> {
                    val body = okhttp3.FormBody.Builder()
                        .add("query", "get_info")
                        .add("hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                        .build()
                    val request = Request.Builder()
                        .url("https://mb-api.abuse.ch/api/v1/")
                        .addHeader("Auth-Key", trimmed)
                        .post(body)
                        .build()
                    client.newCall(request).execute().use { resp ->
                        if (resp.isSuccessful || resp.code == 200) {
                            ValidationStatus.Valid("MalwareBazaar Auth-Key Verified (HTTP 200)")
                        } else if (resp.code == 401) {
                            ValidationStatus.Invalid("Invalid Auth-Key (HTTP 401 Unauthorized)")
                        } else {
                            ValidationStatus.Invalid("HTTP Error ${resp.code}")
                        }
                    }
                }
                else -> ValidationStatus.Invalid("Unknown provider")
            }
        } catch (e: Exception) {
            ValidationStatus.Invalid("Network error: ${e.message ?: "Connection failed"}")
        }
    }
}

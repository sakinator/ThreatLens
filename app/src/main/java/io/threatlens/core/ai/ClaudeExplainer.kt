package io.threatlens.core.ai

import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.TimeUnit

object ClaudeExplainer {

    private val client = OkHttpClient.Builder()
        .connectTimeout(12, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()

    fun explain(
        apiKey: String,
        targetName: String,
        threatFamily: String,
        behaviors: List<String>,
        permissions: List<String>,
        engineVerdicts: Map<String, String> = emptyMap(),
        engineDetails: Map<String, List<String>> = emptyMap()
    ): String? {
        if (apiKey.isBlank()) return null

        val systemPrompt = ThreatAiPromptBuilder.SYSTEM_PROMPT
        val userPrompt = ThreatAiPromptBuilder.buildUserPrompt(
            targetName = targetName,
            threatFamily = threatFamily,
            behaviors = behaviors,
            permissions = permissions,
            engineVerdicts = engineVerdicts,
            engineDetails = engineDetails
        )

        return try {
            val json = JSONObject().apply {
                put("model", "claude-3-5-haiku-20241022")
                put("max_tokens", 800)
                put("system", systemPrompt)
                put("messages", JSONArray().put(
                    JSONObject().put("role", "user").put("content", userPrompt)
                ))
            }

            val request = Request.Builder()
                .url("https://api.anthropic.com/v1/messages")
                .addHeader("x-api-key", apiKey.trim())
                .addHeader("anthropic-version", "2023-06-01")
                .post(json.toString().toRequestBody("application/json".toMediaType()))
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return null
                val raw = response.body?.string() ?: return null
                val root = JSONObject(raw)
                val contentArray = root.optJSONArray("content") ?: return null
                if (contentArray.length() == 0) return null
                contentArray.getJSONObject(0).getString("text").trim()
            }
        } catch (e: Exception) {
            null
        }
    }
}

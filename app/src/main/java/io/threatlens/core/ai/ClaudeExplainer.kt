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
        permissions: List<String>
    ): String? {
        if (apiKey.isBlank()) return null

        val systemPrompt = "You are a cybersecurity expert on ThreatLens mobile security team. Explain Android malware and APK threats to a regular smartphone user in clear, non-technical plain English."
        val userPrompt = """
            File Name: $targetName
            Identified Threat: $threatFamily
            Observed Behaviors: ${behaviors.joinToString("; ")}
            Dangerous Permissions: ${permissions.joinToString(", ")}
            
            Structure your response strictly in 3 short sections:
            1. What is this? (1-2 simple sentences)
            2. What can it cause? (2-3 bullet points: e.g. bank theft, privacy snooping, screen lockout)
            3. Recommended Action: (1 direct directive)
            
            Keep total response under 100 words.
        """.trimIndent()

        return try {
            val json = JSONObject().apply {
                put("model", "claude-3-5-haiku-20241022")
                put("max_tokens", 250)
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

package io.threatlens.core.ai

import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.TimeUnit

object OpenAiExplainer {

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
                put("model", "gpt-4o-mini")
                put("messages", JSONArray().apply {
                    put(JSONObject().put("role", "system").put("content", systemPrompt))
                    put(JSONObject().put("role", "user").put("content", userPrompt))
                })
                put("temperature", 0.3)
                put("max_tokens", 250)
            }

            val request = Request.Builder()
                .url("https://api.openai.com/v1/chat/completions")
                .addHeader("Authorization", "Bearer ${apiKey.trim()}")
                .post(json.toString().toRequestBody("application/json".toMediaType()))
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return null
                val raw = response.body?.string() ?: return null
                val root = JSONObject(raw)
                val choices = root.optJSONArray("choices") ?: return null
                if (choices.length() == 0) return null
                choices.getJSONObject(0)
                    .getJSONObject("message")
                    .getString("content")
                    .trim()
            }
        } catch (e: Exception) {
            null
        }
    }
}

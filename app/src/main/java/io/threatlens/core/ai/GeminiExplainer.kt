package io.threatlens.core.ai

import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.TimeUnit

object GeminiExplainer {

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

        val prompt = """
            You are a cybersecurity expert on ThreatLens mobile security team.
            Explain the following threat to a regular smartphone user in clear, plain, non-technical language:
            
            File Name: $targetName
            Identified Threat: $threatFamily
            Observed Behaviors: ${if (behaviors.isEmpty()) "Suspicious signature match" else behaviors.joinToString("; ")}
            Dangerous Permissions: ${permissions.joinToString(", ")}
            
            Structure your response strictly in 3 short sections:
            1. What is this? (1-2 simple sentences)
            2. What can it cause? (2-3 bullet points: e.g. bank account drainage, privacy theft, screen lockout)
            3. What to do now: (1 clear, actionable directive)
            
            Keep the total response under 110 words.
        """.trimIndent()

        return try {
            val json = JSONObject().apply {
                put("contents", JSONArray().put(
                    JSONObject().put("parts", JSONArray().put(
                        JSONObject().put("text", prompt)
                    ))
                ))
            }

            val request = Request.Builder()
                .url("https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey.trim()}")
                .post(json.toString().toRequestBody("application/json".toMediaType()))
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return null
                val raw = response.body?.string() ?: return null
                val root = JSONObject(raw)
                val candidates = root.optJSONArray("candidates") ?: return null
                if (candidates.length() == 0) return null
                candidates.getJSONObject(0)
                    .getJSONObject("content")
                    .getJSONArray("parts")
                    .getJSONObject(0)
                    .getString("text")
                    .trim()
            }
        } catch (e: Exception) {
            null
        }
    }
}

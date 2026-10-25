package io.threatlens.core.ai

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class ThreatAiExplainer(
    private val openAiKey: String? = null,
    private val claudeKey: String? = null,
    private val geminiApiKey: String? = null,
    private val groqApiKey: String? = null
) {

    suspend fun getExplanation(
        targetName: String,
        threatFamily: String,
        behaviors: List<String>,
        permissions: List<String>
    ): String = withContext(Dispatchers.IO) {
        // 1. OpenAI ChatGPT (if key provided)
        if (!openAiKey.isNullOrBlank()) {
            val result = OpenAiExplainer.explain(openAiKey, targetName, threatFamily, behaviors, permissions)
            if (!result.isNullOrBlank()) return@withContext result
        }

        // 2. Anthropic Claude (if key provided)
        if (!claudeKey.isNullOrBlank()) {
            val result = ClaudeExplainer.explain(claudeKey, targetName, threatFamily, behaviors, permissions)
            if (!result.isNullOrBlank()) return@withContext result
        }

        // 3. Google Gemini (Free tier)
        if (!geminiApiKey.isNullOrBlank()) {
            val result = GeminiExplainer.explain(geminiApiKey, targetName, threatFamily, behaviors, permissions)
            if (!result.isNullOrBlank()) return@withContext result
        }

        // 4. Groq Cloud (Free Llama 3)
        if (!groqApiKey.isNullOrBlank()) {
            val result = GroqExplainer.explain(groqApiKey, targetName, threatFamily, behaviors, permissions)
            if (!result.isNullOrBlank()) return@withContext result
        }

        // 5. Smart offline definition fallback
        FallbackThreatDefinitions.getExplanation(threatFamily, behaviors)
    }
}

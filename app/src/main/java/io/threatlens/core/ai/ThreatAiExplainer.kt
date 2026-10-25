package io.threatlens.core.ai

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class ThreatAiExplainer(
    private val geminiApiKey: String? = null,
    private val groqApiKey: String? = null
) {

    suspend fun getExplanation(
        targetName: String,
        threatFamily: String,
        behaviors: List<String>,
        permissions: List<String>
    ): String = withContext(Dispatchers.IO) {
        // 1. Try Google Gemini if key provided
        if (!geminiApiKey.isNullOrBlank()) {
            val geminiResult = GeminiExplainer.explain(
                geminiApiKey,
                targetName,
                threatFamily,
                behaviors,
                permissions
            )
            if (!geminiResult.isNullOrBlank()) return@withContext geminiResult
        }

        // 2. Try Groq as secondary AI engine
        if (!groqApiKey.isNullOrBlank()) {
            val groqResult = GroqExplainer.explain(
                groqApiKey,
                targetName,
                threatFamily,
                behaviors,
                permissions
            )
            if (!groqResult.isNullOrBlank()) return@withContext groqResult
        }

        // 3. Instant reliable offline fallback
        FallbackThreatDefinitions.getExplanation(threatFamily, behaviors)
    }
}

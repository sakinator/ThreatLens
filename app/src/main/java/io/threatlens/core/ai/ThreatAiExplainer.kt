package io.threatlens.core.ai

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

object ThreatAiPromptBuilder {
    const val SYSTEM_PROMPT = "You are an advanced mobile cybersecurity analyst on the ThreatLens Mobile Threat Defense team. You analyze multi-engine antivirus reports, sandbox telemetry, and Android permissions to provide an authoritative, deep-dive threat analysis explaining every engine finding and risk point-by-point in plain, clear language."

    fun buildUserPrompt(
        targetName: String,
        threatFamily: String,
        behaviors: List<String>,
        permissions: List<String>,
        engineVerdicts: Map<String, String>,
        engineDetails: Map<String, List<String>>
    ): String {
        val activeVerdicts = engineVerdicts.filter { (_, verdict) ->
            !verdict.contains("not configured", ignoreCase = true) && !verdict.contains("Auth-Key", ignoreCase = true)
        }
        val inactiveEngines = engineVerdicts.filter { (_, verdict) ->
            verdict.contains("not configured", ignoreCase = true) || verdict.contains("Auth-Key", ignoreCase = true)
        }.keys.toList()

        val enginesSummary = if (activeVerdicts.isNotEmpty()) {
            activeVerdicts.map { (engine, verdict) ->
                val detailsList = engineDetails[engine]
                if (!detailsList.isNullOrEmpty()) {
                    "- $engine: $verdict\n  Findings: ${detailsList.take(6).joinToString("; ")}"
                } else {
                    "- $engine: $verdict"
                }
            }.joinToString("\n")
        } else {
            "Analyzed by ThreatLens on-device heuristic engine"
        }

        val behaviorsSummary = if (behaviors.isNotEmpty()) {
            behaviors.map { "- $it" }.joinToString("\n")
        } else {
            "No anomalous runtime behaviors directly detected"
        }

        val permissionsSummary = if (permissions.isNotEmpty()) {
            permissions.map { "- $it" }.joinToString("\n")
        } else {
            "Standard Android application permissions"
        }

        val inactiveInstruction = if (inactiveEngines.isNotEmpty()) {
            """
            
            IMPORTANT NOTE ON INACTIVE ENGINES:
            The following engines were skipped because their API keys are not configured: ${inactiveEngines.joinToString(", ")}.
            DO NOT mention, analyze, or list these unconfigured engines in Section 2 (Multi-Engine Consensus).
            Instead, at the very end after Section 4, add a brief closing note:
            "ℹ️ Inactive Engines: ${inactiveEngines.joinToString(", ")} did not provide scan results due to missing API key configuration. Configure keys in Settings to expand multi-engine coverage."
            """.trimIndent()
        } else ""

        return """
            File / Application: $targetName
            Identified Threat Classification: $threatFamily

            Multi-Engine Cloud & Local Scan Results (Active Engines Only):
            $enginesSummary

            Observed Static & Dynamic Behaviors:
            $behaviorsSummary

            Requested High-Privilege Permissions:
            $permissionsSummary

            Provide a comprehensive, point-by-point security analysis structured in clear markdown with these 5 sections:
            1. 🛡️ Executive Threat Assessment: Plain-English summary synthesizing both heuristic behavioral patterns (e.g. overlay injection, SMS/OTP interception, background surveillance) and any specific vendor/family detections. Explain exactly what this app tries to do to the user and device.
            2. 🔬 Multi-Engine Consensus & Antivirus Vendor Analysis: Explain what the active detection engines and specific AV vendors (e.g. AhnLab, Bitdefender, Kaspersky, Tencent, ClamAV) found, explaining what the signature/family names indicate. Do NOT list unconfigured engines here.
            3. ⚡ Observed Malicious Behaviors: Analyze any runtime or bytecode behavioral patterns detected (overlay attacks, SMS exfiltration, accessibility manipulation).
            4. 🔑 High-Risk Capabilities & Permissions: Explain the dangerous Android permissions requested (e.g. location, camera, SMS read) and how they could be abused.
            5. 🛡️ Recommended Action & Guidance: Step-by-step guidance on how to safely quarantine/remove this app and protect user accounts.
            $inactiveInstruction
        """.trimIndent()
    }
}

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
        permissions: List<String>,
        engineVerdicts: Map<String, String> = emptyMap(),
        engineDetails: Map<String, List<String>> = emptyMap()
    ): String = withContext(Dispatchers.IO) {
        // 1. OpenAI ChatGPT (if key provided)
        if (!openAiKey.isNullOrBlank()) {
            val result = OpenAiExplainer.explain(openAiKey, targetName, threatFamily, behaviors, permissions, engineVerdicts, engineDetails)
            if (!result.isNullOrBlank()) return@withContext result
        }

        // 2. Anthropic Claude (if key provided)
        if (!claudeKey.isNullOrBlank()) {
            val result = ClaudeExplainer.explain(claudeKey, targetName, threatFamily, behaviors, permissions, engineVerdicts, engineDetails)
            if (!result.isNullOrBlank()) return@withContext result
        }

        // 3. Google Gemini (Free tier)
        if (!geminiApiKey.isNullOrBlank()) {
            val result = GeminiExplainer.explain(geminiApiKey, targetName, threatFamily, behaviors, permissions, engineVerdicts, engineDetails)
            if (!result.isNullOrBlank()) return@withContext result
        }

        // 4. Groq Cloud (Free Llama 3)
        if (!groqApiKey.isNullOrBlank()) {
            val result = GroqExplainer.explain(groqApiKey, targetName, threatFamily, behaviors, permissions, engineVerdicts, engineDetails)
            if (!result.isNullOrBlank()) return@withContext result
        }

        // 5. Smart offline definition fallback
        FallbackThreatDefinitions.getExplanation(threatFamily, behaviors, permissions, engineVerdicts, engineDetails)
    }
}

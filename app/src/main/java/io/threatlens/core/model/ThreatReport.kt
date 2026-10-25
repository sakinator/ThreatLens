package io.threatlens.core.model

data class ThreatReport(
    val id: String = java.util.UUID.randomUUID().toString(),
    val targetName: String,
    val targetPath: String,
    val appName: String? = null,
    val packageName: String? = null,
    val sha256: String,
    val fileSize: Long = 0L,
    val isApk: Boolean = true,
    val localScore: Int = 0,
    val cloudScore: Int = 0,
    val currentScore: Int = 0,
    val threatScore: Int = currentScore,
    val severity: ThreatSeverity = ThreatSeverity.SAFE,
    val threatFamily: String = "Clean",
    val detectedBehaviors: List<String> = emptyList(),
    val dangerousPermissions: List<String> = emptyList(),
    val cloudEnginesFlagged: Int = 0,
    val cloudEnginesTotal: Int = 0,
    val cloudSources: List<String> = emptyList(),
    val failedEngines: List<String> = emptyList(),
    val successfulEngines: List<String> = emptyList(),
    val isOfflineMode: Boolean = false,
    val contributingEngines: List<String> = emptyList(),
    val engineVerdictMap: Map<String, String> = emptyMap(),
    val aiExplanation: String? = null,
    val isFinal: Boolean = false,
    val pendingEngines: List<String> = emptyList(),
    val statusMessage: String = "Analyzing...",
    val timestamp: Long = System.currentTimeMillis()
) {
    val finalScore: Int get() = currentScore
}

enum class ThreatSeverity(val label: String, val colorHex: Long) {
    SAFE("Clean", 0xFF00E676),            // Neon Green
    SUSPICIOUS("Suspicious", 0xFFFFB300),  // Cyber Amber
    HIGH_RISK("High Risk", 0xFFFF5722),    // Neon Orange
    MALICIOUS("Critical Malware", 0xFFFF1744) // Neon Crimson
}

sealed class ScanTarget {
    data class FileTarget(val file: java.io.File) : ScanTarget()
    data class PackageTarget(val packageName: String, val appName: String, val apkFile: java.io.File) : ScanTarget()
}
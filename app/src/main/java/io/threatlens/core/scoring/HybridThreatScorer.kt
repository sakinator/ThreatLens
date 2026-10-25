package io.threatlens.core.scoring

import io.threatlens.core.cloud.CloudAggregatedVerdict
import io.threatlens.core.local.LocalSignatureDatabase
import io.threatlens.core.local.ManifestHeuristicEngine
import io.threatlens.core.model.ThreatSeverity

object HybridThreatScorer {

    data class ScoreBreakdown(
        val finalScore: Int,
        val severity: ThreatSeverity,
        val primaryFamily: String,
        val reasons: List<String>,
        val isOfflineAutonomousVerdict: Boolean = false
    )

    fun calculate(
        sha256: String,
        localSig: LocalSignatureDatabase.SignatureEntry?,
        heuristic: ManifestHeuristicEngine.HeuristicResult?,
        cloudVerdict: CloudAggregatedVerdict
    ): ScoreBreakdown {
        val reasons = mutableListOf<String>()
        var primaryFamily = "Clean"

        // 1. Critical Override: If local known signature matches, instant 100
        if (localSig != null) {
            reasons.add("Exact match in Local Known Malware Database: ${localSig.threatFamily}")
            primaryFamily = localSig.threatFamily
            return ScoreBreakdown(100, ThreatSeverity.MALICIOUS, primaryFamily, reasons, isOfflineAutonomousVerdict = true)
        }

        val localScore = heuristic?.score ?: 0
        val isOffline = cloudVerdict.successfulEngines.isEmpty()

        // 2. High Cloud Override: If confirmed by Cloud Engine (e.g. MalwareBazaar or 4+ VT engines)
        if (cloudVerdict.cloudScore >= 90) {
            reasons.add("Cloud Threat Intelligence confirmed malicious: ${cloudVerdict.detectedFamily ?: "Identified Malware"}")
            reasons.addAll(cloudVerdict.sources)
            primaryFamily = cloudVerdict.detectedFamily ?: "Cloud.Malware"
            return ScoreBreakdown(100, ThreatSeverity.MALICIOUS, primaryFamily, reasons, isOfflineAutonomousVerdict = false)
        }

        // 3. Adaptive Score Calculation & API Failure Mitigation:
        val finalScore = if (isOffline) {
            // AUTONOMOUS LOCAL AUTHORITY:
            // When all cloud APIs fail (network offline, rate limits, 503s):
            // The local engine score is 100% authoritative and is NEVER penalized or diluted!
            if (cloudVerdict.failedEngines.isNotEmpty()) {
                reasons.add("Cloud APIs unreachable (${cloudVerdict.failedEngines.joinToString()}) • Protected by On-Device Local Engine")
            } else {
                reasons.add("Verified autonomously by ThreatLens 100% Offline Local Engine")
            }
            localScore
        } else {
            // Cloud engines successfully responded:
            val cloudScore = cloudVerdict.cloudScore
            if (cloudVerdict.totalEngines >= 30 && cloudVerdict.enginesFlagged == 0 && localScore < 60) {
                // False Positive Mitigation: 30+ reputable cloud AV engines confirmed clean.
                // Mitigates mild local heuristic noise safely down.
                reasons.add("Verified Clean across ${cloudVerdict.totalEngines} cloud threat engines")
                (localScore * 0.30).toInt()
            } else if (localScore >= 75) {
                // Severe on-device finding (e.g. Banking Overlay abuse): never crushed down
                maxOf(localScore, cloudScore)
            } else {
                // Balanced hybrid fusion between local heuristics and successful cloud signals
                maxOf(localScore, ((localScore * 0.40) + (cloudScore * 0.60)).toInt())
            }
        }.coerceIn(0, 100)

        if (heuristic != null && heuristic.suspiciousBehaviors.isNotEmpty()) {
            reasons.addAll(heuristic.suspiciousBehaviors)
        }
        if (cloudVerdict.sources.isNotEmpty()) {
            reasons.addAll(cloudVerdict.sources)
        }

        if (cloudVerdict.detectedFamily != null) {
            primaryFamily = cloudVerdict.detectedFamily
        } else if (heuristic != null) {
            when {
                heuristic.isLikelyBanker -> primaryFamily = "Heuristic.TrojanBanker"
                heuristic.isLikelySpyware -> primaryFamily = "Heuristic.Spyware"
                heuristic.isLikelyDropper -> primaryFamily = "Heuristic.Dropper"
                heuristic.score >= 50 -> primaryFamily = "Heuristic.Suspicious"
            }
        }

        val severity = when {
            finalScore >= 75 -> ThreatSeverity.MALICIOUS
            finalScore >= 50 -> ThreatSeverity.HIGH_RISK
            finalScore >= 25 -> ThreatSeverity.SUSPICIOUS
            else -> ThreatSeverity.SAFE
        }

        return ScoreBreakdown(
            finalScore = finalScore,
            severity = severity,
            primaryFamily = primaryFamily,
            reasons = reasons,
            isOfflineAutonomousVerdict = isOffline
        )
    }
}
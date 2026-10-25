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
        val reasons: List<String>
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
            reasons.add("Exact match in Local Known Malware Database: ${localSig.family}")
            primaryFamily = localSig.family
            return ScoreBreakdown(100, ThreatSeverity.MALICIOUS, primaryFamily, reasons)
        }

        // 2. High Cloud Override: If confirmed by Cloud Engine (e.g. MalwareBazaar or 4+ VT engines)
        if (cloudVerdict.cloudScore >= 90) {
            reasons.add("Cloud Threat Intelligence confirmed malicious: ${cloudVerdict.detectedFamily ?: "Identified Malware"}")
            reasons.addAll(cloudVerdict.sources)
            primaryFamily = cloudVerdict.detectedFamily ?: "Cloud.Malware"
            return ScoreBreakdown(100, ThreatSeverity.MALICIOUS, primaryFamily, reasons)
        }

        // 3. Hybrid Weighted Calculation
        // Weights: Local Heuristics 45%, Cloud Signals 55%
        val localScore = heuristic?.score ?: 0
        val cloudScore = cloudVerdict.cloudScore

        val weightedScore = ((localScore * 0.45) + (cloudScore * 0.55)).toInt().coerceIn(0, 100)

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
            weightedScore >= 75 -> ThreatSeverity.MALICIOUS
            weightedScore >= 50 -> ThreatSeverity.HIGH_RISK
            weightedScore >= 25 -> ThreatSeverity.SUSPICIOUS
            else -> ThreatSeverity.SAFE
        }

        return ScoreBreakdown(
            finalScore = weightedScore,
            severity = severity,
            primaryFamily = primaryFamily,
            reasons = reasons
        )
    }
}

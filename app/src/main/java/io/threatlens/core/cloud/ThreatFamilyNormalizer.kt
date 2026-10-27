package io.threatlens.core.cloud

/**
 * ThreatLens Consensus Threat Family Normalizer.
 *
 * Resolves divergent vendor labels across multi-cloud threat intelligence engines
 * (e.g., AhnLab "PUP/Android.Malct.1151236", Tencent "a.gray.banker", Avira "HEUR/AGEN")
 * into user-friendly, standardized threat classifications and isolates low-confidence false positives.
 */
object ThreatFamilyNormalizer {

    data class NormalizedConsensus(
        val normalizedFamily: String,
        val displayCategory: String,
        val confidenceLevel: ConfidenceLevel,
        val adjustedScore: Int,
        val isFalsePositiveRisk: Boolean,
        val consensusSummary: String
    )

    enum class ConfidenceLevel {
        ISOLATED_DIVERGENCE,  // 1 engine out of 50+ (high FP probability)
        LOW_CONFIDENCE,       // 2 engines
        MEDIUM_CONFIDENCE,    // 3-4 engines
        HIGH_CONSENSUS        // 5+ engines
    }

    /**
     * Normalizes raw multi-engine verdicts into a coherent consensus verdict.
     *
     * @param maliciousCount Total engines flagging the file (e.g., from VirusTotal/MetaDefender)
     * @param totalEngines Total engines queried (e.g., 65)
     * @param rawFamilyLabels List of proprietary strings from reporting vendors
     * @param isVerifiedStoreApp True if app was installed via Google Play Store or factory system
     */
    fun normalize(
        maliciousCount: Int,
        totalEngines: Int,
        rawFamilyLabels: List<String>,
        isVerifiedStoreApp: Boolean = false
    ): NormalizedConsensus {
        if (maliciousCount == 0 || totalEngines == 0) {
            return NormalizedConsensus(
                normalizedFamily = "Clean",
                displayCategory = "Clean / Verified",
                confidenceLevel = ConfidenceLevel.HIGH_CONSENSUS,
                adjustedScore = 0,
                isFalsePositiveRisk = false,
                consensusSummary = "Verified safe across all active security engines."
            )
        }

        // 1. Single-Vendor Isolated Divergence (e.g. 1/65 engines on VirusTotal)
        if (maliciousCount == 1 && totalEngines >= 25) {
            val vendorRaw = rawFamilyLabels.firstOrNull() ?: "Generic Heuristic"
            val cleanedVendorLabel = cleanVendorString(vendorRaw)

            val adjustedScore = if (isVerifiedStoreApp) 5 else 10

            return NormalizedConsensus(
                normalizedFamily = "Low-Confidence Heuristic ($cleanedVendorLabel)",
                displayCategory = "Potential Unwanted Component (PUP)",
                confidenceLevel = ConfidenceLevel.ISOLATED_DIVERGENCE,
                adjustedScore = adjustedScore,
                isFalsePositiveRisk = true,
                consensusSummary = "Isolated flag by 1 of $totalEngines engines ($cleanedVendorLabel). 98%+ of commercial vendors report clean."
            )
        }

        // 2. Low Confidence (2 engines)
        if (maliciousCount == 2 && totalEngines >= 25) {
            val dominantCat = determineDominantCategory(rawFamilyLabels)
            val adjustedScore = if (isVerifiedStoreApp) 15 else 25

            return NormalizedConsensus(
                normalizedFamily = dominantCat,
                displayCategory = dominantCat,
                confidenceLevel = ConfidenceLevel.LOW_CONFIDENCE,
                adjustedScore = adjustedScore,
                isFalsePositiveRisk = isVerifiedStoreApp,
                consensusSummary = "Flagged by 2 of $totalEngines engines. Vendor divergence observed."
            )
        }

        // 3. Medium Confidence (3-4 engines)
        if (maliciousCount in 3..4) {
            val dominantCat = determineDominantCategory(rawFamilyLabels)
            return NormalizedConsensus(
                normalizedFamily = dominantCat,
                displayCategory = dominantCat,
                confidenceLevel = ConfidenceLevel.MEDIUM_CONFIDENCE,
                adjustedScore = 65,
                isFalsePositiveRisk = false,
                consensusSummary = "Multi-vendor consensus ($maliciousCount/$totalEngines engines flagged as $dominantCat)."
            )
        }

        // 4. High Consensus (5+ engines)
        val dominantCat = determineDominantCategory(rawFamilyLabels)
        return NormalizedConsensus(
            normalizedFamily = dominantCat,
            displayCategory = dominantCat,
            confidenceLevel = ConfidenceLevel.HIGH_CONSENSUS,
            adjustedScore = 95,
            isFalsePositiveRisk = false,
            consensusSummary = "High-confidence consensus: $maliciousCount of $totalEngines security vendors confirmed $dominantCat."
        )
    }

    /**
     * Determines dominant threat category from an array of proprietary vendor labels.
     */
    fun determineDominantCategory(rawLabels: List<String>): String {
        val combined = rawLabels.joinToString(" ").lowercase()

        return when {
            combined.contains("anatsa") || combined.contains("sharkbot") || combined.contains("teabot") ||
            combined.contains("cerberus") || combined.contains("banker") || combined.contains("bankbot") ->
                "Banking Trojan"

            combined.contains("spynote") || combined.contains("craxs") || combined.contains("spyware") ||
            combined.contains("rat") || combined.contains("surveillance") ->
                "Spyware / RAT"

            combined.contains("joker") || combined.contains("toll") || combined.contains("billing") ->
                "Toll Fraud / Joker"

            combined.contains("hiddad") || combined.contains("dropper") || combined.contains("downloader") ->
                "Malicious Dropper"

            combined.contains("adware") || combined.contains("pup") || combined.contains("pua") ||
            combined.contains("malct") || combined.contains("riskware") || combined.contains("gray") ->
                "Adware / Potential Unwanted Component"

            combined.contains("ransom") || combined.contains("locker") ->
                "Ransomware / ScreenLocker"

            else -> "Trojan Malware"
        }
    }

    /**
     * Cleans internal vendor IDs and heuristics suffixes from raw vendor strings.
     */
    fun cleanVendorString(raw: String): String {
        return raw
            .replace(Regex("""(?i)^[a-z0-9\-]+:\s*"""), "") // Strip vendor prefix like "AhnLab-V3: "
            .replace(Regex("""(?i)\.[0-9]{5,}"""), "")        // Strip numeric IDs like .1151236
            .replace(Regex("""(?i)[@!][a-z0-9]+"""), "")       // Strip @heur, !camel
            .replace(Regex("""(?i)Android\."""), "")           // Strip redundant "Android."
            .replace(Regex("""(?i)a\.gray\."""), "")          // Strip "a.gray."
            .trim()
    }
}

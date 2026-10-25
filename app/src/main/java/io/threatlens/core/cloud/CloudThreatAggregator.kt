package io.threatlens.core.cloud

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.withContext

data class CloudAggregatedVerdict(
    val cloudScore: Int,
    val enginesFlagged: Int,
    val totalEngines: Int,
    val sources: List<String>,
    val detectedFamily: String?
)

class CloudThreatAggregator(
    private val vtApiKey: String? = null,
    private val haApiKey: String? = null,
    private val kasperskyKey: String? = null
) {

    suspend fun inspectHash(sha256: String): CloudAggregatedVerdict = withContext(Dispatchers.IO) {
        val sources = mutableListOf<String>()
        var flaggedCount = 0
        var totalCount = 0
        var highestScore = 0
        var detectedFamily: String? = null

        // 1. Run MalwareBazaar asynchronously (Free & fast)
        val bazaarDeferred = async { MalwareBazaarProvider.queryHash(sha256) }

        // 2. Run VirusTotal if key present
        val vtDeferred = async {
            if (!vtApiKey.isNullOrBlank()) VirusTotalProvider.queryHash(sha256, vtApiKey) else null
        }

        // 3. Run HybridAnalysis if key present
        val haDeferred = async {
            if (!haApiKey.isNullOrBlank()) HybridAnalysisProvider.queryHash(sha256, haApiKey) else null
        }

        // 4. Run Kaspersky if key present
        val kasperskyDeferred = async {
            if (!kasperskyKey.isNullOrBlank()) KasperskyOpenTipProvider.queryHash(sha256, kasperskyKey) else null
        }

        // Collect Bazaar
        val bazaar = bazaarDeferred.await()
        if (bazaar != null && bazaar.isMalicious) {
            sources.add("MalwareBazaar (Abuse.ch)")
            highestScore = maxOf(highestScore, 95)
            flaggedCount += 1
            totalCount += 1
            detectedFamily = bazaar.signature ?: "MalwareBazaar.Malware"
        }

        // Collect VirusTotal
        val vt = vtDeferred.await()
        if (vt != null && vt.totalEngines > 0) {
            sources.add("VirusTotal (${vt.maliciousCount}/${vt.totalEngines})")
            flaggedCount += vt.maliciousCount
            totalCount += vt.totalEngines
            if (vt.maliciousCount >= 4) {
                highestScore = maxOf(highestScore, 100)
            } else if (vt.maliciousCount >= 1) {
                highestScore = maxOf(highestScore, 40)
            }
            if (detectedFamily == null && !vt.suggestedThreatLabel.isNullOrBlank()) {
                detectedFamily = vt.suggestedThreatLabel
            }
        }

        // Collect Hybrid Analysis
        val ha = haDeferred.await()
        if (ha != null) {
            sources.add("Hybrid Analysis (Score ${ha.threatScore}/100)")
            highestScore = maxOf(highestScore, ha.threatScore)
            if (ha.threatScore >= 50) flaggedCount += 1
            totalCount += 1
            if (detectedFamily == null && !ha.vxFamily.isNullOrBlank()) {
                detectedFamily = ha.vxFamily
            }
        }

        // Collect Kaspersky
        val kas = kasperskyDeferred.await()
        if (kas != null) {
            sources.add("Kaspersky OpenTIP (${kas.zone})")
            if (kas.zone.equals("Red", ignoreCase = true)) {
                highestScore = maxOf(highestScore, 100)
                flaggedCount += 1
            } else if (kas.zone.equals("Yellow", ignoreCase = true)) {
                highestScore = maxOf(highestScore, 60)
                flaggedCount += 1
            }
            totalCount += 1
            if (detectedFamily == null && !kas.threatFamily.isNullOrBlank()) {
                detectedFamily = kas.threatFamily
            }
        }

        CloudAggregatedVerdict(
            cloudScore = highestScore,
            enginesFlagged = flaggedCount,
            totalEngines = totalCount,
            sources = sources,
            detectedFamily = detectedFamily
        )
    }
}

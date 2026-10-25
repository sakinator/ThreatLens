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
    private val kasperskyKey: String? = null,
    private val metaDefenderKey: String? = null,
    private val filescanKey: String? = null
) {

    suspend fun inspectHash(sha256: String): CloudAggregatedVerdict = withContext(Dispatchers.IO) {
        val sources = mutableListOf<String>()
        var flaggedCount = 0
        var totalCount = 0
        var highestScore = 0
        var detectedFamily: String? = null

        // 1. MalwareBazaar (Abuse.ch - Free community lookup)
        val bazaarDeferred = async { MalwareBazaarProvider.queryHash(sha256) }

        // 2. VirusTotal (v3)
        val vtDeferred = async {
            if (!vtApiKey.isNullOrBlank()) VirusTotalProvider.queryHash(sha256, vtApiKey) else null
        }

        // 3. Hybrid Analysis (Falcon Sandbox)
        val haDeferred = async {
            if (!haApiKey.isNullOrBlank()) HybridAnalysisProvider.queryHash(sha256, haApiKey) else null
        }

        // 4. Kaspersky OpenTIP
        val kasperskyDeferred = async {
            if (!kasperskyKey.isNullOrBlank()) KasperskyOpenTipProvider.queryHash(sha256, kasperskyKey) else null
        }

        // 5. MetaDefender Cloud (OPSWAT)
        val metaDefenderDeferred = async {
            if (!metaDefenderKey.isNullOrBlank()) MetaDefenderProvider.queryHash(sha256, metaDefenderKey) else null
        }

        // 6. Filescan.io
        val filescanDeferred = async {
            if (!filescanKey.isNullOrBlank()) FilescanProvider.queryHash(sha256, filescanKey) else null
        }

        // Await Bazaar
        val bazaar = bazaarDeferred.await()
        if (bazaar != null && bazaar.isMalicious) {
            sources.add("MalwareBazaar (Abuse.ch)")
            highestScore = maxOf(highestScore, 95)
            flaggedCount += 1
            totalCount += 1
            detectedFamily = bazaar.signature ?: "MalwareBazaar.Malware"
        }

        // Await VirusTotal
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

        // Await Hybrid Analysis
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

        // Await Kaspersky
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

        // Await MetaDefender Cloud
        val md = metaDefenderDeferred.await()
        if (md != null && md.totalEngines > 0) {
            sources.add("MetaDefender (${md.enginesFlagged}/${md.totalEngines})")
            flaggedCount += md.enginesFlagged
            totalCount += md.totalEngines
            if (md.enginesFlagged >= 3) {
                highestScore = maxOf(highestScore, 95)
            } else if (md.threatFound) {
                highestScore = maxOf(highestScore, 45)
            }
            if (detectedFamily == null && !md.threatName.isNullOrBlank()) {
                detectedFamily = md.threatName
            }
        }

        // Await Filescan.io
        val fs = filescanDeferred.await()
        if (fs != null) {
            sources.add("Filescan.io (${fs.verdict})")
            highestScore = maxOf(highestScore, fs.threatScore)
            if (fs.threatScore >= 50) flaggedCount += 1
            totalCount += 1
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

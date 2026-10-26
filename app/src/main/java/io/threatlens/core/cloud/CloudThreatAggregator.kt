package io.threatlens.core.cloud

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.withContext

data class CloudAggregatedVerdict(
    val cloudScore: Int,
    val enginesFlagged: Int,
    val totalEngines: Int,
    val sources: List<String>,
    val detectedFamily: String?,
    val failedEngines: List<String> = emptyList(),
    val successfulEngines: List<String> = emptyList()
)

class CloudThreatAggregator(
    private val vtApiKey: String? = null,
    private val haApiKey: String? = null,
    private val kasperskyKey: String? = null,
    private val metaDefenderKey: String? = null,
    private val filescanKey: String? = null,
    private val abuseChAuthKey: String? = null
) {

    suspend fun inspectHash(sha256: String): CloudAggregatedVerdict = withContext(Dispatchers.IO) {
        val sources = mutableListOf<String>()
        val successfulEngines = mutableListOf<String>()
        val failedEngines = mutableListOf<String>()
        var flaggedCount = 0
        var totalCount = 0
        var highestScore = 0
        var detectedFamily: String? = null

        // 1. AlienVault OTX (Open Threat Exchange - Free Public Community Intelligence, Zero-Key)
        val otxDeferred = async {
            try { AlienVaultOtxProvider.queryHash(sha256) } catch (_: Exception) { null }
        }

        // 2. CIRCL Hashlookup (Computer Incident Response Center Luxembourg / MISP / NSRL, Zero-Key)
        val circlDeferred = async {
            try { CirclHashlookupProvider.queryHash(sha256) } catch (_: Exception) { null }
        }

        // 3. MalwareBazaar (Abuse.ch)
        val bazaarDeferred = async { 
            try { MalwareBazaarProvider.queryHash(sha256, abuseChAuthKey) } catch (_: Exception) { null } 
        }

        // 4. VirusTotal (v3)
        val vtDeferred = async {
            if (!vtApiKey.isNullOrBlank()) {
                try { VirusTotalProvider.queryHash(sha256, vtApiKey) } catch (_: Exception) { null }
            } else null
        }

        // 5. Hybrid Analysis (Falcon Sandbox)
        val haDeferred = async {
            if (!haApiKey.isNullOrBlank()) {
                try { HybridAnalysisProvider.queryHash(sha256, haApiKey) } catch (_: Exception) { null }
            } else null
        }

        // 6. Kaspersky OpenTIP
        val kasperskyDeferred = async {
            if (!kasperskyKey.isNullOrBlank()) {
                try { KasperskyOpenTipProvider.queryHash(sha256, kasperskyKey) } catch (_: Exception) { null }
            } else null
        }

        // 7. MetaDefender Cloud (OPSWAT)
        val metaDefenderDeferred = async {
            if (!metaDefenderKey.isNullOrBlank()) {
                try { MetaDefenderProvider.queryHash(sha256, metaDefenderKey) } catch (_: Exception) { null }
            } else null
        }

        // 8. Filescan.io
        val filescanDeferred = async {
            if (!filescanKey.isNullOrBlank()) {
                try { FilescanProvider.queryHash(sha256, filescanKey) } catch (_: Exception) { null }
            } else null
        }

        // Await AlienVault OTX
        val otx = otxDeferred.await()
        if (otx != null) {
            successfulEngines.add("AlienVault OTX")
            if (otx.isMalicious) {
                sources.add("AlienVault OTX (${otx.pulseCount} pulses)")
                highestScore = maxOf(highestScore, 90)
                flaggedCount += otx.pulseCount
                totalCount += maxOf(1, otx.pulseCount)
                if (detectedFamily == null && !otx.threatFamily.isNullOrBlank()) {
                    detectedFamily = otx.threatFamily
                }
            } else {
                totalCount += 1
            }
        } else {
            failedEngines.add("AlienVault OTX")
        }

        // Await CIRCL Hashlookup
        val circl = circlDeferred.await()
        if (circl != null) {
            successfulEngines.add("CIRCL Hashlookup")
            if (circl.isMalicious) {
                sources.add("CIRCL CERT Threat DB")
                highestScore = maxOf(highestScore, 90)
                flaggedCount += 1
                totalCount += 1
            } else {
                totalCount += 1
            }
        } else {
            failedEngines.add("CIRCL Hashlookup")
        }

        // Await Bazaar
        val bazaar = bazaarDeferred.await()
        if (bazaar != null) {
            successfulEngines.add("MalwareBazaar")
            if (bazaar.isMalicious) {
                sources.add("MalwareBazaar (Abuse.ch)")
                highestScore = maxOf(highestScore, 95)
                flaggedCount += 1
                totalCount += 1
                if (detectedFamily == null) {
                    detectedFamily = bazaar.signature ?: "MalwareBazaar.Malware"
                }
            }
        } else if (!abuseChAuthKey.isNullOrBlank()) {
            failedEngines.add("MalwareBazaar")
        }

        // Await VirusTotal
        if (!vtApiKey.isNullOrBlank()) {
            val vt = vtDeferred.await()
            if (vt != null) {
                successfulEngines.add("VirusTotal")
                if (vt.totalEngines > 0) {
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
            } else {
                failedEngines.add("VirusTotal")
            }
        }

        // Await Hybrid Analysis
        if (!haApiKey.isNullOrBlank()) {
            val ha = haDeferred.await()
            if (ha != null) {
                successfulEngines.add("Hybrid Analysis")
                sources.add("Hybrid Analysis (Score ${ha.threatScore}/100)")
                highestScore = maxOf(highestScore, ha.threatScore)
                if (ha.threatScore >= 50) flaggedCount += 1
                totalCount += 1
                if (detectedFamily == null && !ha.vxFamily.isNullOrBlank()) {
                    detectedFamily = ha.vxFamily
                }
            } else {
                failedEngines.add("Hybrid Analysis")
            }
        }

        // Await Kaspersky
        if (!kasperskyKey.isNullOrBlank()) {
            val kas = kasperskyDeferred.await()
            if (kas != null) {
                successfulEngines.add("Kaspersky OpenTIP")
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
            } else {
                failedEngines.add("Kaspersky OpenTIP")
            }
        }

        // Await MetaDefender Cloud
        if (!metaDefenderKey.isNullOrBlank()) {
            val md = metaDefenderDeferred.await()
            if (md != null) {
                successfulEngines.add("MetaDefender")
                if (md.totalEngines > 0) {
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
            } else {
                failedEngines.add("MetaDefender")
            }
        }

        // Await Filescan.io
        if (!filescanKey.isNullOrBlank()) {
            val fs = filescanDeferred.await()
            if (fs != null) {
                successfulEngines.add("Filescan.io")
                sources.add("Filescan.io (${fs.verdict})")
                highestScore = maxOf(highestScore, fs.threatScore)
                if (fs.threatScore >= 50) flaggedCount += 1
                totalCount += 1
            } else {
                failedEngines.add("Filescan.io")
            }
        }

        CloudAggregatedVerdict(
            cloudScore = highestScore,
            enginesFlagged = flaggedCount,
            totalEngines = totalCount,
            sources = sources,
            detectedFamily = detectedFamily,
            failedEngines = failedEngines,
            successfulEngines = successfulEngines
        )
    }

    companion object {
        fun getEngineWebReportUrl(engineName: String, sha256: String): String? {
            if (sha256.isBlank()) return null
            return when (engineName) {
                "VirusTotal" -> "https://www.virustotal.com/gui/file/$sha256"
                "AlienVault OTX" -> "https://otx.alienvault.com/indicator/file/$sha256"
                "CIRCL Hashlookup" -> "https://hashlookup.circl.lu/lookup/sha256/$sha256"
                "MalwareBazaar" -> "https://bazaar.abuse.ch/sample/$sha256/"
                "Kaspersky OpenTIP" -> "https://opentip.kaspersky.com/$sha256/"
                "Hybrid Analysis" -> "https://www.hybrid-analysis.com/sample/$sha256"
                "MetaDefender" -> "https://metadefender.opswat.com/results/file/$sha256/hash/overview"
                "Filescan.io" -> "https://www.filescan.io/scan/$sha256"
                else -> null
            }
        }
    }
}
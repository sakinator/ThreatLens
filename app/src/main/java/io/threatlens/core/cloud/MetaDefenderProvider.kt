package io.threatlens.core.cloud

import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.TimeUnit

object MetaDefenderProvider {

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    data class MetaDefenderModule(
        val name: String, // "Metascan", "Predictive Alin AI", "Vulnerability Assessment", "Deep CDR", "Adaptive Sandbox", "Country of Origin"
        val isActive: Boolean,
        val isDetected: Boolean,
        val summary: String,
        val details: List<String> = emptyList()
    )

    data class MetaDefenderResult(
        val threatFound: Boolean,
        val enginesFlagged: Int,
        val totalEngines: Int,
        val threatName: String?,
        val detectedVendors: List<String> = emptyList(),
        val cleanVendors: List<String> = emptyList(),
        val modules: List<MetaDefenderModule> = emptyList(),
        val isUnindexed: Boolean = false
    )

    fun queryHash(sha256: String, apiKey: String): MetaDefenderResult? {
        if (apiKey.isBlank()) return null
        return try {
            val request = Request.Builder()
                .url("https://api.metadefender.com/v4/hash/${sha256.trim()}")
                .addHeader("apikey", apiKey.trim())
                .addHeader("User-Agent", "ThreatLens-Security/1.5.5")
                .get()
                .build()

            client.newCall(request).execute().use { response ->
                if (response.code == 404) {
                    return MetaDefenderResult(
                        threatFound = false,
                        enginesFlagged = 0,
                        totalEngines = 0,
                        threatName = null,
                        detectedVendors = emptyList(),
                        cleanVendors = emptyList(),
                        modules = emptyList(),
                        isUnindexed = true
                    )
                }
                if (!response.isSuccessful) return null
                val raw = response.body?.string() ?: return null
                val root = JSONObject(raw)
                val scanResults = root.optJSONObject("scan_results") ?: return null

                val totalEngines = scanResults.optInt("total_avs", 0)
                val detectedEngines = scanResults.optInt("total_detected_avs", 0)
                val scanDetails = scanResults.optJSONObject("scan_details")

                var topThreatName: String? = null
                val flaggedVendors = mutableListOf<String>()
                val cleanVendors = mutableListOf<String>()

                // Track Alin AI if it appears in scanDetails
                var alinFromScanDetails: JSONObject? = null

                if (scanDetails != null) {
                    val keys = scanDetails.keys()
                    while (keys.hasNext()) {
                        val engine = keys.next()
                        if (engine.contains("alin", ignoreCase = true) || engine.equals("Alin AI", ignoreCase = true)) {
                            alinFromScanDetails = scanDetails.getJSONObject(engine)
                            continue
                        }
                        val result = scanDetails.getJSONObject(engine)
                        val threat = result.optString("threat_found")
                        val scanResultI = result.optInt("scan_result_i", 0)
                        if (!threat.isNullOrBlank() || scanResultI in listOf(1, 2)) {
                            val resolvedThreat = if (!threat.isNullOrBlank()) threat else "Malware.Detected"
                            if (topThreatName == null) topThreatName = resolvedThreat
                            flaggedVendors.add("$engine: $resolvedThreat")
                        } else {
                            cleanVendors.add("$engine: Clean (No threat detected)")
                        }
                    }
                }

                val activeModules = mutableListOf<MetaDefenderModule>()

                // 1. Metascan (Multiscanning)
                val isMetascanActive = totalEngines > 0 || scanDetails != null
                if (isMetascanActive) {
                    val isMetascanDetected = detectedEngines > 0 || flaggedVendors.isNotEmpty()
                    val metascanDetails = mutableListOf<String>()
                    if (isMetascanDetected) {
                        metascanDetails.addAll(flaggedVendors)
                        metascanDetails.addAll(cleanVendors)
                        activeModules.add(
                            MetaDefenderModule(
                                name = "Metascan",
                                isActive = true,
                                isDetected = true,
                                summary = "Metascan: ${maxOf(detectedEngines, flaggedVendors.size)}/$totalEngines AV engines flagged",
                                details = metascanDetails
                            )
                        )
                    } else {
                        if (cleanVendors.isNotEmpty()) {
                            metascanDetails.addAll(cleanVendors)
                        } else {
                            metascanDetails.add("No commercial antivirus threats detected across $totalEngines engines")
                        }
                        activeModules.add(
                            MetaDefenderModule(
                                name = "Metascan",
                                isActive = true,
                                isDetected = false,
                                summary = "Metascan: Clean (0/$totalEngines AV engines flagged)",
                                details = metascanDetails
                            )
                        )
                    }
                }

                // 2. Predictive Alin AI
                val alinObj = alinFromScanDetails
                    ?: scanResults.optJSONObject("alin_ai")
                    ?: scanResults.optJSONObject("ai_analysis")
                    ?: scanResults.optJSONObject("ai_prediction")
                    ?: root.optJSONObject("alin_ai")
                    ?: root.optJSONObject("ai_analysis")
                    ?: root.optJSONObject("predictive_alin_ai")

                if (alinObj != null) {
                    val status = alinObj.optString("status", "")
                    val isNotActive = status.equals("Not Active", ignoreCase = true) || status.equals("inactive", ignoreCase = true)
                    if (!isNotActive) {
                        val threat = alinObj.optString("threat_found", "").trim()
                            .ifEmpty { alinObj.optString("verdict", "").trim() }
                            .ifEmpty { alinObj.optString("threat_name", "").trim() }
                        val scanResultI = alinObj.optInt("scan_result_i", 0)
                        val assessment = alinObj.optInt("assessment", 0)
                        val isAlinDetected = (threat.isNotEmpty() && !threat.equals("CLEAN", ignoreCase = true) && !threat.equals("NO_THREAT", ignoreCase = true) && !threat.equals("BENIGN", ignoreCase = true)) || scanResultI in listOf(1, 2) || assessment > 0

                        if (isAlinDetected) {
                            val threatLabel = if (threat.isNotEmpty()) threat else "Malicious Anomaly"
                            activeModules.add(
                                MetaDefenderModule(
                                    name = "Predictive Alin AI",
                                    isActive = true,
                                    isDetected = true,
                                    summary = "Alin AI: Threat Detected ($threatLabel)",
                                    details = listOf("Predictive Alin AI: Pre-execution static AI model flagged malicious pattern ($threatLabel)")
                                )
                            )
                            if (topThreatName == null) topThreatName = "AlinAI.$threatLabel"
                        } else {
                            activeModules.add(
                                MetaDefenderModule(
                                    name = "Predictive Alin AI",
                                    isActive = true,
                                    isDetected = false,
                                    summary = "Alin AI: No Threat Detected (Clean)",
                                    details = listOf("Predictive Alin AI: Pre-execution static AI inference verified safe")
                                )
                            )
                        }
                    }
                }
                // If alinObj == null or Not Active: HIDE IT (do not add to activeModules)

                // 3. Vulnerability Assessment
                val vulObj = scanResults.optJSONObject("vulnerability")
                    ?: root.optJSONObject("vulnerability")
                    ?: scanResults.optJSONObject("vulnerability_assessment")
                    ?: root.optJSONObject("vulnerability_assessment")
                    ?: root.optJSONObject("process_info")?.optJSONObject("vulnerability")

                if (vulObj != null) {
                    val vulStatus = vulObj.optString("status", "")
                    val isNotActive = vulStatus.equals("Not Active", ignoreCase = true)
                    if (!isNotActive) {
                        val totalVul = vulObj.optInt("total_vulnerabilities", -1)
                        val severity = vulObj.optString("severity", "").trim()
                        val vulArray = vulObj.optJSONArray("vulnerabilities")
                        val isVulDetected = (totalVul > 0) || (vulArray != null && vulArray.length() > 0) || (severity.isNotEmpty() && !severity.equals("NONE", ignoreCase = true) && !severity.equals("CLEAN", ignoreCase = true))

                        if (isVulDetected) {
                            val count = if (totalVul > 0) totalVul else (vulArray?.length() ?: 1)
                            val sevText = if (severity.isNotEmpty()) " - Severity: $severity" else ""
                            val cveDetails = mutableListOf<String>()
                            if (vulArray != null) {
                                for (i in 0 until minOf(vulArray.length(), 5)) {
                                    val cveItem = vulArray.optJSONObject(i)
                                    if (cveItem != null) {
                                        val cveId = cveItem.optString("cve")
                                        val pkg = cveItem.optString("package")
                                        val cveSev = cveItem.optString("severity")
                                        val itemStr = listOfNotNull(cveId.ifBlank { null }, cveSev.ifBlank { null }, pkg.ifBlank { null }).joinToString(" ")
                                        if (itemStr.isNotBlank()) cveDetails.add(itemStr)
                                    }
                                }
                            }
                            if (cveDetails.isEmpty()) {
                                cveDetails.add("Known software vulnerabilities detected in application components.")
                            }
                            activeModules.add(
                                MetaDefenderModule(
                                    name = "Vulnerability Assessment",
                                    isActive = true,
                                    isDetected = true,
                                    summary = "Vulnerability Assessment: $count CVE(s) Detected$sevText",
                                    details = cveDetails
                                )
                            )
                        } else {
                            activeModules.add(
                                MetaDefenderModule(
                                    name = "Vulnerability Assessment",
                                    isActive = true,
                                    isDetected = false,
                                    summary = "Vulnerability Assessment: No Vulnerabilities Detected (Clean)",
                                    details = listOf("File components & dependencies scanned: 0 known CVEs found")
                                )
                            )
                        }
                    }
                }
                // If vulObj == null or Not Active: HIDE IT

                // 4. Adaptive Sandbox
                val sandboxObj = scanResults.optJSONObject("sandbox_scan_details")
                    ?: root.optJSONObject("sandbox")
                    ?: root.optJSONObject("adaptive_sandbox")
                if (sandboxObj != null) {
                    val sbStatus = sandboxObj.optString("status", "")
                    if (!sbStatus.equals("Not Active", ignoreCase = true)) {
                        val metaSandbox = sandboxObj.optJSONObject("MetaDefender Sandbox")
                        val sbVerdict = metaSandbox?.optString("verdict", "") ?: sandboxObj.optString("verdict", "")
                        val isSbDetected = sbVerdict.equals("MALICIOUS", ignoreCase = true) || sbVerdict.equals("SUSPICIOUS", ignoreCase = true)
                        if (isSbDetected) {
                            activeModules.add(
                                MetaDefenderModule(
                                    name = "Adaptive Sandbox",
                                    isActive = true,
                                    isDetected = true,
                                    summary = "Adaptive Sandbox: Threat Detected ($sbVerdict)",
                                    details = listOf("Adaptive Sandbox: Malicious behavioral patterns observed in detonation sandbox")
                                )
                            )
                        } else if (metaSandbox != null || sandboxObj.length() > 0) {
                            activeModules.add(
                                MetaDefenderModule(
                                    name = "Adaptive Sandbox",
                                    isActive = true,
                                    isDetected = false,
                                    summary = "Adaptive Sandbox: No Malicious Behavior Detected (Clean)",
                                    details = listOf("Adaptive Sandbox: Pre-execution detonation verified safe")
                                )
                            )
                        }
                    }
                }

                // 5. Deep CDR (Content Disarm & Reconstruction)
                val cdrObj = root.optJSONObject("sanitized")
                    ?: root.optJSONObject("cdr")
                    ?: root.optJSONObject("process_info")?.optJSONObject("post_processing")

                if (cdrObj != null) {
                    val cdrStatus = cdrObj.optString("status", "")
                    val actionsRan = cdrObj.optString("actions_ran", "")
                    val result = cdrObj.optString("result", cdrStatus)
                    val isCdrActive = !cdrStatus.equals("Not Active", ignoreCase = true) &&
                        (actionsRan.contains("cdr", ignoreCase = true) || actionsRan.contains("sanitize", ignoreCase = true) || cdrObj.has("result") || cdrObj.has("sanitized_file"))
                    if (isCdrActive) {
                        val isSanitized = result.contains("sanitized", ignoreCase = true) || result.contains("removed", ignoreCase = true) || result.contains("disarmed", ignoreCase = true) || cdrObj.optInt("sanitized_objects", 0) > 0
                        if (isSanitized) {
                            val resLabel = if (result.isNotBlank()) result else "Sanitized"
                            activeModules.add(
                                MetaDefenderModule(
                                    name = "Deep CDR",
                                    isActive = true,
                                    isDetected = true,
                                    summary = "Deep CDR: Content Sanitized ($resLabel)",
                                    details = listOf("Active scripts, macros or embedded threats disarmed by Deep CDR")
                                )
                            )
                        } else {
                            activeModules.add(
                                MetaDefenderModule(
                                    name = "Deep CDR",
                                    isActive = true,
                                    isDetected = false,
                                    summary = "Deep CDR: No Threats to Disarm (Clean)",
                                    details = listOf("File structure verified clean: No malicious embedded objects detected")
                                )
                            )
                        }
                    }
                }

                // 6. Country of Origin
                val cooObj = root.optJSONObject("country_of_origin")
                    ?: root.optJSONObject("file_info")?.optJSONObject("country_of_origin")
                if (cooObj != null) {
                    val cooStatus = cooObj.optString("status", "")
                    if (!cooStatus.equals("Not Active", ignoreCase = true) && !cooStatus.equals("inactive", ignoreCase = true)) {
                        val isRestricted = cooObj.optBoolean("restricted", false)
                        val country = cooObj.optString("country", "")
                        if (isRestricted) {
                            activeModules.add(
                                MetaDefenderModule(
                                    name = "Country of Origin",
                                    isActive = true,
                                    isDetected = true,
                                    summary = "Country of Origin: Restricted Origin ($country)",
                                    details = listOf("Binary origin detected from restricted geopolitical region: $country")
                                )
                            )
                        } else {
                            activeModules.add(
                                MetaDefenderModule(
                                    name = "Country of Origin",
                                    isActive = true,
                                    isDetected = false,
                                    summary = "Country of Origin: No Restricted Origin (Clean)",
                                    details = listOf("Developer & infrastructure origin verified: No restricted country flags")
                                )
                            )
                        }
                    }
                }

                // 7. Proactive DLP (Data Loss Prevention)
                val dlpObj = root.optJSONObject("dlp_info")
                    ?: root.optJSONObject("proactive_dlp")
                    ?: root.optJSONObject("dlp")
                    ?: scanResults.optJSONObject("dlp")
                if (dlpObj != null) {
                    val dlpStatus = dlpObj.optString("status", "")
                    if (!dlpStatus.equals("Not Active", ignoreCase = true) && !dlpStatus.equals("inactive", ignoreCase = true)) {
                        val isDlpDetected = dlpObj.optBoolean("has_sensitive_data", false) ||
                            dlpObj.optInt("detected_items", 0) > 0 ||
                            dlpObj.optString("verdict", "").equals("DETECTED", ignoreCase = true) ||
                            dlpObj.optString("verdict", "").equals("BLOCKED", ignoreCase = true)
                        if (isDlpDetected) {
                            activeModules.add(
                                MetaDefenderModule(
                                    name = "Proactive DLP",
                                    isActive = true,
                                    isDetected = true,
                                    summary = "Proactive DLP: Sensitive Data Found",
                                    details = listOf("Data Loss Prevention: Sensitive PII or confidential assets detected")
                                )
                            )
                        } else {
                            activeModules.add(
                                MetaDefenderModule(
                                    name = "Proactive DLP",
                                    isActive = true,
                                    isDetected = false,
                                    summary = "Proactive DLP: No Sensitive Data (Clean)",
                                    details = listOf("Data Loss Prevention: No sensitive or confidential data detected")
                                )
                            )
                        }
                    }
                }

                // 8. OPSWAT AI Content Inspector
                val aiContentObj = root.optJSONObject("ai_content_inspector")
                    ?: root.optJSONObject("content_inspection")
                    ?: root.optJSONObject("ai_content_inspection")
                    ?: scanResults.optJSONObject("ai_content_inspector")
                if (aiContentObj != null) {
                    val aiStatus = aiContentObj.optString("status", "")
                    if (!aiStatus.equals("Not Active", ignoreCase = true) && !aiStatus.equals("inactive", ignoreCase = true)) {
                        val isAiDetected = aiContentObj.optBoolean("violation", false) ||
                            aiContentObj.optInt("threat_count", 0) > 0 ||
                            aiContentObj.optString("verdict", "").equals("FLAGGED", ignoreCase = true)
                        if (isAiDetected) {
                            activeModules.add(
                                MetaDefenderModule(
                                    name = "AI Content Inspector",
                                    isActive = true,
                                    isDetected = true,
                                    summary = "AI Content Inspector: Policy Violation Detected",
                                    details = listOf("AI Content Inspector flagged policy violations or unsafe content")
                                )
                            )
                        } else {
                            activeModules.add(
                                MetaDefenderModule(
                                    name = "AI Content Inspector",
                                    isActive = true,
                                    isDetected = false,
                                    summary = "AI Content Inspector: Clean (Verified)",
                                    details = listOf("AI Content Inspector verified safe compliance")
                                )
                            )
                        }
                    }
                }

                val hasAnyDetection = detectedEngines > 0 || flaggedVendors.isNotEmpty() || activeModules.any { it.isDetected }

                MetaDefenderResult(
                    threatFound = hasAnyDetection,
                    enginesFlagged = detectedEngines,
                    totalEngines = totalEngines,
                    threatName = topThreatName,
                    detectedVendors = flaggedVendors,
                    cleanVendors = cleanVendors,
                    modules = activeModules,
                    isUnindexed = false
                )
            }
        } catch (e: Exception) {
            null
        }
    }
}

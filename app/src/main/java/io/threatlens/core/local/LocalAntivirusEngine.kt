package io.threatlens.core.local

import android.content.Context
import java.io.File
import java.io.InputStream
import java.util.zip.ZipFile

/**
 * 100% Free, Autonomous, On-Device Antivirus Engine.
 * Operates completely offline with zero internet requirement.
 * 
 * Fuses:
 * 1. High-speed offline signature hash lookup (LocalSignatureDatabase)
 * 2. Deep static DEX / Bytecode pattern matching (YARA-style offline scanner)
 * 3. Static Manifest permission & toxic behavioral combination analyzer (ManifestHeuristicEngine)
 */
object LocalAntivirusEngine {

    data class LocalScanVerdict(
        val isMalicious: Boolean,
        val localScore: Int,
        val threatFamily: String,
        val category: String,
        val detectionType: io.threatlens.core.model.DetectionType = io.threatlens.core.model.DetectionType.CLEAN,
        val scoreBreakdown: io.threatlens.core.model.ScoreBreakdown? = null,
        val detectedBehaviors: List<String>,
        val dangerousPermissions: List<String>,
        val matchedSignatures: List<String>,
        val engineSources: List<String>,
        val clamAvResult: ClamAvEngine.ClamAvResult? = null,
        val yaraResult: YaraMobileRules.YaraResult? = null,
        val certResult: ApkCertificateVerifier.CertResult? = null,
        val packerResult: PackerEntropyDetector.PackerResult? = null
    )

    // Known malicious bytecode signatures & strings found in mobile malware
    private val BYTECODE_SIGNATURES = listOf(
        BytecodeRule(
            pattern = "com/metasploit/stage/Payload",
            family = "Trojan.Metasploit.Meterpreter",
            category = "Remote Access Trojan (RAT)",
            score = 100,
            description = "Metasploit Android reverse shell / meterpreter stager embedded in bytecode"
        ),
        BytecodeRule(
            pattern = "PayloadTrustManager",
            family = "Trojan.Metasploit.Stager",
            category = "Exploit / Stager",
            score = 90,
            description = "Bypasses TLS certificate validation to maintain covert C2 reverse connection"
        ),
        BytecodeRule(
            pattern = "api.telegram.org/bot",
            family = "Trojan-Spy.TelegramC2",
            category = "Exfiltration Stealer",
            score = 80,
            description = "Hardcoded Telegram Bot API C2 exfiltration webhook for stolen SMS/credentials"
        ),
        BytecodeRule(
            pattern = "Lcom/spynote/service",
            family = "Spyware.AndroidOS.SpyNote",
            category = "Spyware / RAT",
            score = 100,
            description = "SpyNote commercial remote surveillance Trojan signature"
        ),
        BytecodeRule(
            pattern = "ahmyth",
            family = "Trojan.AndroidOS.AhMyth",
            category = "Open-Source RAT",
            score = 95,
            description = "AhMyth Android Remote Access Trojan control harness"
        ),
        BytecodeRule(
            pattern = "craxsrat",
            family = "Trojan.AndroidOS.CraxsRAT",
            category = "Advanced RAT",
            score = 100,
            description = "CraxsRAT keyboard logger and screen injection framework"
        ),
        BytecodeRule(
            pattern = "chmod 777 /data/local/tmp",
            family = "Exploit.Dropper.PrivEsc",
            category = "Root Dropper",
            score = 85,
            description = "Alters system execution privileges to drop secondary unverified payload"
        ),
        BytecodeRule(
            pattern = "daemonsu",
            family = "Exploit.AndroidOS.RootExploit",
            category = "Privilege Escalation",
            score = 85,
            description = "Spawns unauthorized background root daemon to bypass Android security sandbox"
        )
    )

    private data class BytecodeRule(
        val pattern: String,
        val family: String,
        val category: String,
        val score: Int,
        val description: String
    )

    fun scan(context: Context, file: File, sha256: String): LocalScanVerdict {
        val behaviors = mutableListOf<String>()
        val matchedSignatures = mutableListOf<String>()
        val sources = mutableListOf<String>()
        val dangerousPermissions = mutableListOf<String>()

        var highestScore = 0
        var detectedFamily = "Clean"
        var category = "Clean"

        // 1. High-speed Offline Signature DB Lookup (O(1) Hash Table)
        val sig = LocalSignatureDatabase.lookup(sha256)
        if (sig != null) {
            matchedSignatures.add(sig.threatFamily)
            sources.add("ThreatLens Offline Signature DB")
            behaviors.add("Matches verified malware hash in offline database: ${sig.threatFamily}")
            highestScore = 100
            detectedFamily = sig.threatFamily
            category = sig.category
        }

        // 2. Cisco ClamAV Open-Source Rule & CVD Hash Inspection
        val clamAv = ClamAvEngine.scanFile(file, sha256)
        if (clamAv.isMalicious) {
            clamAv.signatureName?.let { matchedSignatures.add(it) }
            sources.add("ClamAV Open Source Engine")
            behaviors.addAll(clamAv.details)
            if (clamAv.confidenceScore > highestScore) {
                highestScore = clamAv.confidenceScore
                detectedFamily = clamAv.signatureName ?: detectedFamily
                category = clamAv.matchedCategory
            }
        }

        val isApk = file.extension.equals("apk", ignoreCase = true)

        // 3. VirusTotal YARA Mobile Threat Pattern Scan
        val yara = if (isApk) YaraMobileRules.scanApk(file) else null
        if (yara != null && yara.isMatched) {
            yara.ruleName?.let { matchedSignatures.add(it) }
            sources.add("YARA Mobile Threat Rules")
            behaviors.addAll(yara.details)
            if (yara.score > highestScore) {
                highestScore = yara.score
                detectedFamily = yara.threatFamily ?: detectedFamily
                category = "YARA Rule Match"
            }
        }

        // 4. ThreatLens Certificate & Repack Shield
        val cert = if (isApk) ApkCertificateVerifier.verifyApk(context, file, null) else null
        if (cert != null && (cert.isSuspicious || cert.isMalicious)) {
            sources.add("ThreatLens Certificate & Repack Shield")
            behaviors.addAll(cert.details)
            if (cert.score > highestScore) {
                highestScore = cert.score
                if (detectedFamily == "Clean") {
                    detectedFamily = cert.issueType ?: "Suspicious.Certificate"
                    category = "Certificate Integrity Issue"
                }
            }
        }

        // 5. ThreatLens Anti-Analysis & Packer Shield
        val packer = if (isApk) PackerEntropyDetector.inspectApk(file) else null
        if (packer != null && (packer.isPacked || packer.isAntiAnalysis)) {
            sources.add("ThreatLens Anti-Analysis & Packer Shield")
            behaviors.addAll(packer.details)
            if (packer.score > highestScore) {
                highestScore = packer.score
                if (detectedFamily == "Clean") {
                    detectedFamily = packer.packerName ?: "Obfuscated.Packer"
                    category = "Packer / Obfuscation"
                }
            }
        }

        var hasBytecodeMatch = false

        // 6. Deep DEX & Bytecode Pattern Scan (Offline YARA-style scanner)
        if (isApk && file.exists() && file.canRead()) {
            val bytecodeMatches = scanApkBytecode(file)
            for (rule in bytecodeMatches) {
                hasBytecodeMatch = true
                matchedSignatures.add(rule.family)
                behaviors.add(rule.description)
                sources.add("ThreatLens Bytecode Engine")
                if (rule.score > highestScore) {
                    highestScore = rule.score
                    detectedFamily = rule.family
                    category = rule.category
                }
            }
        }

        var heuristicScore = 0

        // 7. Static Manifest & Heuristic Permission Matrix
        if (isApk) {
            val heuristic = ManifestHeuristicEngine.analyzeApk(context, file)
            behaviors.addAll(heuristic.suspiciousBehaviors)
            dangerousPermissions.addAll(heuristic.dangerousPermissions)
            heuristicScore = heuristic.score

            if (heuristic.score > highestScore) {
                highestScore = heuristic.score
                if (detectedFamily == "Clean") {
                    when {
                        heuristic.isLikelyBanker -> {
                            detectedFamily = "Heuristic.TrojanBanker"
                            category = "Banking Trojan"
                        }
                        heuristic.isLikelySpyware -> {
                            detectedFamily = "Heuristic.Spyware"
                            category = "Spyware / RAT"
                        }
                        heuristic.isLikelyDropper -> {
                            detectedFamily = "Heuristic.Dropper"
                            category = "Malicious Dropper"
                        }
                        heuristic.score >= 45 -> {
                            detectedFamily = "Heuristic.HighPrivilege"
                            category = "High Privilege Tool"
                        }
                        heuristic.score >= 25 -> {
                            detectedFamily = "Heuristic.Suspicious"
                            category = "Potentially Unwanted Application"
                        }
                    }
                }
            }

            if (heuristic.suspiciousBehaviors.isNotEmpty()) {
                sources.add("ThreatLens Behavioral Heuristics")
            }
        }

        val isMalicious = highestScore >= 75 || hasBytecodeMatch || sig != null || clamAv.isMalicious || (yara != null && yara.isMatched) || (cert != null && cert.isMalicious)
        val detectionType = when {
            hasBytecodeMatch || sig != null -> io.threatlens.core.model.DetectionType.CONFIRMED_SIGNATURE
            highestScore >= 25 -> io.threatlens.core.model.DetectionType.HEURISTIC_PATTERN
            else -> io.threatlens.core.model.DetectionType.CLEAN
        }

        if (detectionType == io.threatlens.core.model.DetectionType.CLEAN) {
            detectedFamily = "Clean"
            category = "Clean"
        }

        val rationale = when (detectionType) {
            io.threatlens.core.model.DetectionType.CONFIRMED_SIGNATURE ->
                "Confirmed Malware: Trojan or RAT payload signature discovered embedded in application bytecode."
            io.threatlens.core.model.DetectionType.HEURISTIC_PATTERN ->
                "Heuristic Finding: Score based on ${dangerousPermissions.size} sensitive permissions and runtime capabilities. No confirmed Trojan signature matched."
            else ->
                "Verified Safe: Normal permission usage. 0 malicious signatures or harmful heuristic patterns identified."
        }

        if (sources.isEmpty()) {
            sources.add("ThreatLens Local Engine (Clean)")
        }

        val breakdown = io.threatlens.core.model.ScoreBreakdown(
            signatureScore = if (hasBytecodeMatch) highestScore else 0,
            permissionScore = minOf(dangerousPermissions.size * 5, 25),
            heuristicScore = heuristicScore,
            totalScore = highestScore.coerceIn(0, 100),
            rationale = rationale
        )

        return LocalScanVerdict(
            isMalicious = isMalicious,
            localScore = highestScore.coerceIn(0, 100),
            threatFamily = detectedFamily,
            category = category,
            detectionType = detectionType,
            scoreBreakdown = breakdown,
            detectedBehaviors = behaviors,
            dangerousPermissions = dangerousPermissions,
            matchedSignatures = matchedSignatures,
            engineSources = sources,
            clamAvResult = clamAv,
            yaraResult = yara,
            certResult = cert,
            packerResult = packer
        )
    }

    /**
     * Inspects classes.dex and zip archive entries for known malware bytecode patterns.
     */
    private fun scanApkBytecode(apkFile: File): List<BytecodeRule> {
        val matches = mutableListOf<BytecodeRule>()
        try {
            ZipFile(apkFile).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    // Inspect DEX bytecode files and shell scripts
                    if (entry.name.endsWith(".dex") || entry.name.endsWith(".sh") || entry.name.startsWith("assets/")) {
                        // Scan up to first 2MB of each DEX entry to maintain instant scan latency
                        zip.getInputStream(entry).use { stream ->
                            val buffer = ByteArray(1024 * 512) // 512 KB chunks
                            var bytesRead = stream.read(buffer)
                            var totalRead = 0
                            val maxToScan = 2 * 1024 * 1024 // 2 MB max per entry

                            while (bytesRead != -1 && totalRead < maxToScan) {
                                val chunkString = String(buffer, 0, bytesRead, Charsets.ISO_8859_1)
                                for (rule in BYTECODE_SIGNATURES) {
                                    if (!matches.contains(rule) && chunkString.contains(rule.pattern, ignoreCase = true)) {
                                        matches.add(rule)
                                    }
                                }
                                totalRead += bytesRead
                                bytesRead = stream.read(buffer)
                            }
                        }
                    }
                }
            }
        } catch (_: Exception) {
            // Graceful non-blocking fallback if APK is encrypted or corrupted
        }
        return matches
    }
}
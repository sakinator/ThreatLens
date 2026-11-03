package io.threatlens.core.local

import android.util.Base64
import java.io.File
import java.util.regex.Pattern
import java.util.zip.ZipFile

/**
 * P7: Autonomous Static String De-Obfuscator.
 *
 * Scans DEX bytecode and resource string pools for encrypted or obfuscated command & control
 * endpoints, stealth download URLs, Telegram bot tokens, and root commands hidden behind
 * Base64 encoding, single-byte XOR ciphers, and ROT13 substitution.
 */
object StringDeobfuscator {

    data class DeobfuscationResult(
        val hasHiddenThreats: Boolean,
        val score: Int,
        val discoveredC2Urls: List<String>,
        val discoveredIps: List<String>,
        val discoveredCommands: List<String>,
        val findings: List<String>
    )

    private val URL_PATTERN = Pattern.compile("https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}(/[a-zA-Z0-9._~:/?#\\[\\]@!$&'()*+,;=-]*)?")
    private val IP_PATTERN = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b")
    private val TELEGRAM_BOT_PATTERN = Pattern.compile("bot[0-9]{8,10}:[a-zA-Z0-9_-]{35}")

    private val SUSPICIOUS_SHELL_STRINGS = listOf(
        "/system/bin/su",
        "chmod 777",
        "setenforce 0",
        "reboot",
        "daemonsu",
        "pm install -r",
        "rm -rf /data",
        "content://telephony/siminfo"
    )

    /**
     * Inspects DEX string pools in an APK file.
     */
    fun scanApk(apkFile: File): DeobfuscationResult {
        val discoveredUrls = mutableListOf<String>()
        val discoveredIps = mutableListOf<String>()
        val discoveredCommands = mutableListOf<String>()
        val findings = mutableListOf<String>()
        var score = 0

        try {
            ZipFile(apkFile).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    if (entry.name.endsWith(".dex")) {
                        zip.getInputStream(entry).use { stream ->
                            val bytes = stream.readBytes()
                            val dexStrings = extractStringsFromBytes(bytes)
                            for (str in dexStrings) {
                                analyzeCandidateString(
                                    candidate = str,
                                    urls = discoveredUrls,
                                    ips = discoveredIps,
                                    commands = discoveredCommands,
                                    findings = findings
                                )
                            }
                        }
                    }
                }
            }
        } catch (_: Exception) {}

        if (discoveredUrls.isNotEmpty()) score += 35
        if (discoveredIps.isNotEmpty()) score += 25
        if (discoveredCommands.isNotEmpty()) score += 30

        return DeobfuscationResult(
            hasHiddenThreats = findings.isNotEmpty(),
            score = score.coerceIn(0, 80),
            discoveredC2Urls = discoveredUrls.distinct(),
            discoveredIps = discoveredIps.distinct(),
            discoveredCommands = discoveredCommands.distinct(),
            findings = findings.distinct()
        )
    }

    /**
     * Inspects an individual string literal or byte array.
     */
    fun analyzeCandidateString(
        candidate: String,
        urls: MutableList<String> = mutableListOf(),
        ips: MutableList<String> = mutableListOf(),
        commands: MutableList<String> = mutableListOf(),
        findings: MutableList<String> = mutableListOf()
    ) {
        val trimmed = candidate.trim()
        if (trimmed.length < 10 || trimmed.length > 500) return

        // 1. Base64 De-obfuscation Sweep
        if (isLikelyBase64(trimmed)) {
            try {
                val decodedBytes = Base64.decode(trimmed, Base64.DEFAULT)
                val decoded = String(decodedBytes, Charsets.UTF_8).trim()
                if (decoded.length >= 8 && isPrintableAscii(decoded)) {
                    inspectDecodedText("Base64", decoded, urls, ips, commands, findings)
                }
            } catch (_: Exception) {}
        }

        // 2. ROT13 Substitution Sweep
        val rot13 = applyRot13(trimmed)
        if (rot13 != trimmed) {
            inspectDecodedText("ROT13", rot13, urls, ips, commands, findings)
        }
    }

    /**
     * Performs single-byte XOR de-obfuscation on byte arrays.
     */
    fun xorSweep(data: ByteArray): List<String> {
        val discovered = mutableListOf<String>()
        val sampleLen = minOf(data.size, 4096)
        val sample = data.copyOfRange(0, sampleLen)

        for (key in 1..255) {
            val decrypted = ByteArray(sample.size)
            for (i in sample.indices) {
                decrypted[i] = (sample[i].toInt() xor key).toByte()
            }
            val text = String(decrypted, Charsets.ISO_8859_1)
            val matcher = URL_PATTERN.matcher(text)
            while (matcher.find()) {
                val url = matcher.group()
                if (!url.contains("schema") && !url.contains("w3.org") && !url.contains("android.com")) {
                    discovered.add("XOR(0x${key.toString(16)}): $url")
                }
            }
        }
        return discovered.distinct()
    }

    private fun inspectDecodedText(
        transform: String,
        text: String,
        urls: MutableList<String>,
        ips: MutableList<String>,
        commands: MutableList<String>,
        findings: MutableList<String>
    ) {
        // Match URLs
        val urlMatcher = URL_PATTERN.matcher(text)
        while (urlMatcher.find()) {
            val url = urlMatcher.group()
            if (!url.contains("schema.org") && !url.contains("w3.org") && !url.contains("android.com")) {
                urls.add(url)
                findings.add("[$transform De-Obfuscated] Hidden URL target: $url")
            }
        }

        // Match Telegram Bot Webhooks
        val tgMatcher = TELEGRAM_BOT_PATTERN.matcher(text)
        if (tgMatcher.find()) {
            val token = tgMatcher.group()
            findings.add("[$transform De-Obfuscated] Stealth Telegram Bot C2 webhook token: ${token.take(12)}...")
        }

        // Match Hidden IPs
        val ipMatcher = IP_PATTERN.matcher(text)
        while (ipMatcher.find()) {
            val ip = ipMatcher.group()
            if (!ip.startsWith("127.") && !ip.startsWith("0.0") && !ip.startsWith("255.")) {
                ips.add(ip)
                findings.add("[$transform De-Obfuscated] Concealed IP address: $ip")
            }
        }

        // Match Suspicious Shell Commands
        for (cmd in SUSPICIOUS_SHELL_STRINGS) {
            if (text.contains(cmd, ignoreCase = true)) {
                commands.add(cmd)
                findings.add("[$transform De-Obfuscated] Covert shell command: '$cmd'")
            }
        }
    }

    private fun isLikelyBase64(str: String): Boolean {
        if (str.length % 4 != 0 && (str.length + 1) % 4 != 0 && (str.length + 2) % 4 != 0) return false
        return str.all { c ->
            (c in 'A'..'Z') || (c in 'a'..'z') || (c in '0'..'9') || c == '+' || c == '/' || c == '='
        }
    }

    private fun applyRot13(input: String): String {
        val sb = StringBuilder(input.length)
        for (c in input) {
            when (c) {
                in 'A'..'M' -> sb.append((c.code + 13).toChar())
                in 'N'..'Z' -> sb.append((c.code - 13).toChar())
                in 'a'..'m' -> sb.append((c.code + 13).toChar())
                in 'n'..'z' -> sb.append((c.code - 13).toChar())
                else -> sb.append(c)
            }
        }
        return sb.toString()
    }

    private fun isPrintableAscii(str: String): Boolean {
        var printable = 0
        for (c in str) {
            if (c.code in 32..126) printable++
        }
        return (printable.toDouble() / str.length) >= 0.85
    }

    private fun extractStringsFromBytes(bytes: ByteArray): List<String> {
        val result = mutableListOf<String>()
        val sb = StringBuilder()
        for (b in bytes) {
            val c = b.toInt() and 0xFF
            if (c in 32..126) {
                sb.append(c.toChar())
            } else {
                if (sb.length >= 10) {
                    result.add(sb.toString())
                }
                sb.setLength(0)
            }
        }
        if (sb.length >= 10) {
            result.add(sb.toString())
        }
        return result
    }
}

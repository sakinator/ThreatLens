package io.threatlens.core.local

import java.io.File
import java.util.zip.ZipFile
import kotlin.math.ln

/**
 * ThreatLens Anti-Analysis & Packer Shield.
 *
 * Inspects APK binaries for commercial Android packers/crypters (Bangcle, Jiagu, Tencent Legu),
 * anti-analysis evasion hooks, and high-entropy encrypted secondary payloads.
 */
object PackerEntropyDetector {

    data class PackerResult(
        val isPacked: Boolean,
        val isAntiAnalysis: Boolean,
        val packerName: String?,
        val dexEntropy: Float,
        val score: Int,
        val details: List<String>
    )

    private val KNOWN_PACKERS = mapOf(
        "libsecmain.so" to "Bangcle / SecShell Packer",
        "libsecexe.so" to "Bangcle / SecShell Packer",
        "libshella.so" to "Tencent Legu Crypter",
        "libshellx.so" to "Tencent Legu Crypter",
        "libjiagu.so" to "Qihoo 360 Jiagu Packer",
        "libprotectClass.so" to "Qihoo 360 Jiagu Packer",
        "libbaiduprotect.so" to "Baidu Android Packer",
        "libapkprotect.so" to "APKProtect Crypter",
        "libmobisec.so" to "AliPay Mobisec Packer"
    )

    private val ANTI_DEBUG_HOOKS = listOf(
        "frida-server",
        "xposed.installer",
        "/system/bin/failsafe/su",
        "ro.kernel.qemu",
        "goldfish",
        "ptrace(PTRACE_TRACEME"
    )

    fun inspectApk(apkFile: File): PackerResult {
        if (!apkFile.exists() || !apkFile.extension.equals("apk", ignoreCase = true)) {
            return cleanResult("Target is not an APK archive")
        }

        var detectedPacker: String? = null
        var maxDexEntropy = 0f
        val detectedHooks = mutableListOf<String>()

        try {
            ZipFile(apkFile).use { zip ->
                // 1. Scan for commercial packer dynamic libraries in lib/ and assets/
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    val filename = entry.name.substringAfterLast("/")
                    val packerMatch = KNOWN_PACKERS[filename.lowercase()]
                    if (packerMatch != null) {
                        detectedPacker = packerMatch
                    }
                }

                // 2. Measure Shannon Entropy on classes.dex
                val dexEntry = zip.getEntry("classes.dex")
                if (dexEntry != null) {
                    val dexBytes = zip.getInputStream(dexEntry).use { it.readBytes() }
                    maxDexEntropy = calculateShannonEntropy(dexBytes)

                    val dexString = String(dexBytes, Charsets.ISO_8859_1)
                    for (hook in ANTI_DEBUG_HOOKS) {
                        if (dexString.contains(hook, ignoreCase = true)) {
                            detectedHooks.add(hook)
                        }
                    }
                }
            }

            if (detectedPacker != null) {
                return PackerResult(
                    isPacked = true,
                    isAntiAnalysis = detectedHooks.isNotEmpty(),
                    packerName = detectedPacker,
                    dexEntropy = maxDexEntropy,
                    score = 65,
                    details = listOf(
                        "Packer Detected: $detectedPacker",
                        "The application uses heavy runtime code encryption to conceal bytecode from static AV scanners.",
                        "Shannon Entropy: %.2f bits/byte (High Obfuscation)".format(maxDexEntropy),
                        if (detectedHooks.isNotEmpty()) "Anti-Analysis Evasion: ${detectedHooks.joinToString(", ")}" else "Standard unpacker stub"
                    )
                )
            }

            // High Entropy Flag (entropy > 7.4 in classes.dex is abnormal for plain DEX bytecode)
            if (maxDexEntropy >= 7.45f) {
                return PackerResult(
                    isPacked = true,
                    isAntiAnalysis = detectedHooks.isNotEmpty(),
                    packerName = "Encrypted DEX Payload",
                    dexEntropy = maxDexEntropy,
                    score = 45,
                    details = listOf(
                        "Abnormal Shannon Entropy: %.2f bits/byte (Indicates encrypted payload or compressed assets inside DEX)".format(maxDexEntropy),
                        if (detectedHooks.isNotEmpty()) "Anti-Analysis Evasion: ${detectedHooks.joinToString(", ")}" else "Elevated bytecode entropy"
                    )
                )
            }

            return PackerResult(
                isPacked = false,
                isAntiAnalysis = detectedHooks.isNotEmpty(),
                packerName = null,
                dexEntropy = maxDexEntropy,
                score = if (detectedHooks.isNotEmpty()) 20 else 0,
                details = listOf(
                    "Bytecode Structure: Standard uncompressed Dalvik DEX",
                    "Shannon Entropy: %.2f bits/byte (Normal plain bytecode)".format(maxDexEntropy),
                    "No commercial crypters or anti-analysis evasion stubs detected"
                )
            )

        } catch (e: Exception) {
            return cleanResult("Packer inspection skipped: ${e.message}")
        }
    }

    /**
     * Calculates Shannon Entropy: H = - sum(P(i) * log2(P(i)))
     * Range: 0.0 (uniform) to 8.0 (completely random / encrypted)
     */
    fun calculateShannonEntropy(data: ByteArray): Float {
        if (data.isEmpty()) return 0f
        val frequencies = IntArray(256)
        for (b in data) {
            frequencies[b.toInt() and 0xFF]++
        }

        var entropy = 0.0
        val len = data.size.toDouble()
        val log2 = ln(2.0)

        for (count in frequencies) {
            if (count > 0) {
                val p = count / len
                entropy -= p * (ln(p) / log2)
            }
        }
        return entropy.toFloat()
    }

    private fun cleanResult(msg: String): PackerResult {
        return PackerResult(
            isPacked = false,
            isAntiAnalysis = false,
            packerName = null,
            dexEntropy = 0f,
            score = 0,
            details = listOf(msg)
        )
    }
}

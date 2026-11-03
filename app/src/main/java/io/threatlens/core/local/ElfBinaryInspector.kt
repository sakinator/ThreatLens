package io.threatlens.core.local

import java.io.ByteArrayInputStream
import java.io.File
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile

/**
 * P2: Pure-Kotlin Native .so ELF Library Inspector.
 *
 * Scans compiled native binaries (.so files) embedded inside APK packages across all architectures
 * (arm64-v8a, armeabi-v7a, x86, x86_64) to detect low-level rootkits, memory tampering hooks,
 * anti-debugging routines, raw socket backdoors, and stealth payloads designed to evade DEX analysis.
 */
object ElfBinaryInspector {

    data class ElfScanResult(
        val isSuspicious: Boolean,
        val riskScore: Int,
        val threatFamily: String,
        val category: String,
        val inspectedLibraries: List<String>,
        val dangerousSymbols: List<String>,
        val antiDebugTechniques: List<String>,
        val stealthBackdoors: List<String>,
        val findings: List<String>
    )

    private val DANGEROUS_SYSTEM_CALLS = mapOf(
        "ptrace" to "Process anti-debugging & memory tampering syscall (ptrace)",
        "process_vm_readv" to "Direct cross-process memory reading (process_vm_readv)",
        "process_vm_writev" to "Direct cross-process memory modification & code injection (process_vm_writev)",
        "mprotect" to "Alters memory execution permissions to enable arbitrary shellcode execution",
        "execve" to "Low-level system binary execution without Java runtime authorization",
        "fork" to "Native daemon process bifurcation & evasion",
        "dlopen" to "Stealth dynamic native payload loader (dlopen)",
        "dlsym" to "Dynamic symbol resolution bypassing static import inspection"
    )

    private val RAW_SOCKET_CALLS = mapOf(
        "socket" to "Raw Linux network socket creation",
        "connect" to "Low-level network connection bypassing Android NetworkSecurityConfig",
        "sendto" to "Direct UDP packet transmission / exfiltration",
        "recvfrom" to "Direct UDP packet reception",
        "bind" to "Local port binding / reverse listener"
    )

    private val HOOKING_ROOTKIT_MARKERS = mapOf(
        "frida" to "Frida dynamic instrumentation & hooking agent",
        "xposed" to "Xposed bytecode injection framework",
        "substrate" to "Cydia Substrate native API hook engine",
        "magisk" to "Magisk root hiding & su binary detection bypass"
    )

    /**
     * Inspects native libraries packaged inside an APK file.
     */
    fun inspectApk(apkFile: File): ElfScanResult {
        val inspectedLibs = mutableListOf<String>()
        val foundDangerousSymbols = mutableListOf<String>()
        val foundAntiDebug = mutableListOf<String>()
        val foundBackdoors = mutableListOf<String>()
        val allFindings = mutableListOf<String>()
        var score = 0

        try {
            ZipFile(apkFile).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    val name = entry.name
                    if (name.startsWith("lib/") && name.endsWith(".so")) {
                        inspectedLibs.add(name.substringAfterLast('/'))
                        zip.getInputStream(entry).use { stream ->
                            val bytes = stream.readBytes()
                            if (bytes.size >= 4 && bytes[0] == 0x7F.toByte() &&
                                bytes[1] == 'E'.code.toByte() &&
                                bytes[2] == 'L'.code.toByte() &&
                                bytes[3] == 'F'.code.toByte()
                            ) {
                                inspectElfBytes(
                                    libName = name.substringAfterLast('/'),
                                    bytes = bytes,
                                    dangerousSymbols = foundDangerousSymbols,
                                    antiDebug = foundAntiDebug,
                                    backdoors = foundBackdoors,
                                    findings = allFindings
                                )
                            }
                        }
                    }
                }
            }
        } catch (_: Exception) {}

        // Calculate score
        if (foundAntiDebug.isNotEmpty()) score += 20
        if (foundDangerousSymbols.any { it.contains("process_vm") || it.contains("mprotect") }) score += 25
        if (foundDangerousSymbols.any { it.contains("execve") }) score += 20
        if (foundBackdoors.size >= 2) score += 25
        if (allFindings.any { it.contains("Frida") || it.contains("Substrate") }) score += 30

        val isSuspicious = score >= 35
        val threatFamily = when {
            allFindings.any { it.contains("Frida") || it.contains("Substrate") } -> "NativeHook.FridaSubstrate"
            foundBackdoors.isNotEmpty() && foundDangerousSymbols.isNotEmpty() -> "Trojan.NativeBackdoor"
            foundAntiDebug.isNotEmpty() -> "Heuristic.NativeAntiAnalysis"
            else -> "Clean"
        }

        return ElfScanResult(
            isSuspicious = isSuspicious,
            riskScore = score.coerceIn(0, 85),
            threatFamily = threatFamily,
            category = if (isSuspicious) "Native ELF Binary Threat" else "Clean Native Binary",
            inspectedLibraries = inspectedLibs.distinct(),
            dangerousSymbols = foundDangerousSymbols.distinct(),
            antiDebugTechniques = foundAntiDebug.distinct(),
            stealthBackdoors = foundBackdoors.distinct(),
            findings = allFindings.distinct()
        )
    }

    private fun inspectElfBytes(
        libName: String,
        bytes: ByteArray,
        dangerousSymbols: MutableList<String>,
        antiDebug: MutableList<String>,
        backdoors: MutableList<String>,
        findings: MutableList<String>
    ) {
        val content = String(bytes, java.nio.charset.StandardCharsets.ISO_8859_1)

        // Check for Dangerous System Calls
        for ((syscall, desc) in DANGEROUS_SYSTEM_CALLS) {
            if (content.contains(syscall)) {
                dangerousSymbols.add(syscall)
                findings.add("[$libName] $desc")
                if (syscall == "ptrace") {
                    antiDebug.add("ptrace anti-debugging mechanism")
                }
            }
        }

        // Check for Raw Network Socket Calls
        for ((call, desc) in RAW_SOCKET_CALLS) {
            if (content.contains(call)) {
                backdoors.add(call)
                findings.add("[$libName] $desc")
            }
        }

        // Check Hooking & Rootkit Artifacts
        for ((framework, desc) in HOOKING_ROOTKIT_MARKERS) {
            if (content.contains(framework, ignoreCase = true)) {
                findings.add("[$libName] Embedded $desc")
            }
        }

        // Check for hidden shell invocation strings
        if (content.contains("/system/bin/sh") || content.contains("/system/bin/su")) {
            findings.add("[$libName] Hardcoded root shell invocation path (/system/bin/sh, su)")
            dangerousSymbols.add("native_root_shell")
        }
    }
}

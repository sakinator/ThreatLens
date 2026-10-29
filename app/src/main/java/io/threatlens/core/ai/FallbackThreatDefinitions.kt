package io.threatlens.core.ai

object FallbackThreatDefinitions {

    fun getExplanation(
        family: String,
        behaviors: List<String> = emptyList(),
        permissions: List<String> = emptyList(),
        engineVerdicts: Map<String, String> = emptyMap(),
        engineDetails: Map<String, List<String>> = emptyMap()
    ): String {
        val lower = family.lowercase()
        val sb = StringBuilder()

        // Extract any vendor detections from engineDetails
        val allDetections = mutableListOf<String>()
        engineDetails.values.flatten().forEach { detail ->
            if (detail.contains(":")) {
                allDetections.add(detail.substringAfter(":").trim())
            }
        }
        val combinedDetectionText = (allDetections + family).joinToString(" ").lowercase()

        // 1. Executive Threat Assessment (Heuristic + Family + Vendor Synthesis)
        sb.append("### 🛡️ Executive Threat Assessment\n")

        val isConfirmedSignature = !family.startsWith("Heuristic", ignoreCase = true) &&
                                   !family.startsWith("Low-Confidence", ignoreCase = true) &&
                                   !family.equals("Clean", ignoreCase = true) &&
                                   (allDetections.size >= 5 || family.contains("Trojan") || family.contains("Spyware") || family.contains("Ransomware"))

        val isRansomware = combinedDetectionText.contains("ransomware") || combinedDetectionText.contains("simplelocker") ||
                           combinedDetectionText.contains("doublelocker") || combinedDetectionText.contains("wannalocker") ||
                           combinedDetectionText.contains("screenlocker") || (combinedDetectionText.contains("locker") && !combinedDetectionText.contains("applock"))
        val isBanker = combinedDetectionText.contains("bankchameleon") || combinedDetectionText.contains("cerberus") ||
                       combinedDetectionText.contains("anatsa") || combinedDetectionText.contains("sharkbot") ||
                       combinedDetectionText.contains("teabot") || (combinedDetectionText.contains("banker") && !combinedDetectionText.contains("pup"))
        val isSpyware = combinedDetectionText.contains("spynote") || combinedDetectionText.contains("smsstealer") ||
                        combinedDetectionText.contains("craxs") || (combinedDetectionText.contains("spyware") && !combinedDetectionText.contains("pup"))
        val isDropper = combinedDetectionText.contains("hiddad") || (combinedDetectionText.contains("dropper") && !combinedDetectionText.contains("pup"))
        val isTollFraud = combinedDetectionText.contains("joker") || combinedDetectionText.contains("toll fraud") || combinedDetectionText.contains("billing")
        val isMalctOrRiskware = combinedDetectionText.contains("malct") || combinedDetectionText.contains("riskware") || combinedDetectionText.contains("repack")
        val isAdware = combinedDetectionText.contains("adware") || combinedDetectionText.contains("hiddenads") || combinedDetectionText.contains("pup") || combinedDetectionText.contains("pua")

        // Heuristic Behavioral Analysis
        val hasSmsTheft = behaviors.any { it.contains("sms", ignoreCase = true) || it.contains("otp", ignoreCase = true) } ||
                         permissions.any { it.contains("read_sms", ignoreCase = true) || it.contains("receive_sms", ignoreCase = true) }
        val hasOverlay = behaviors.any { it.contains("overlay", ignoreCase = true) || it.contains("alert_window", ignoreCase = true) } ||
                         permissions.any { it.contains("system_alert_window", ignoreCase = true) }
        val hasAccessibility = behaviors.any { it.contains("accessibility", ignoreCase = true) } ||
                               permissions.any { it.contains("bind_accessibility_service", ignoreCase = true) }
        val hasSurveillance = permissions.any { it.contains("record_audio", ignoreCase = true) || it.contains("camera", ignoreCase = true) }

        val assessmentSummary = buildString {
            when {
                isRansomware && isConfirmedSignature -> {
                    append("**Critical Ransomware Threat**: Classified as **Mobile Ransomware / Screen Locker** ($family). ")
                    append("Engineered to encrypt device storage or hijack device lock privileges with intent to extort financial ransom.")
                }
                isRansomware -> {
                    append("**Potential Ransomware Pattern**: Flagged by on-device heuristics for combining wide storage access and device lockout / administrative privileges. ")
                    append("Not a confirmed ransomware payload. ThreatLens flags the pattern so you can inspect granted permissions.")
                }
                isBanker && isConfirmedSignature -> {
                    append("**Critical Financial Threat**: Classified as a **Banking Trojan** (${if (combinedDetectionText.contains("bankchameleon")) "BankChameleon" else family}). ")
                    append("Engineered to superimpose deceptive login overlay screens above genuine banking and payment apps. ")
                    if (hasSmsTheft) {
                        append("It actively intercepts SMS broadcasts to siphon two-factor authentication (2FA) OTP tokens and bypass transaction verification.")
                    }
                }
                isBanker -> {
                    append("**Potential Banking Overlay Pattern**: Flagged by on-device heuristics for combining overlay projection with accessibility or sensitive privileges. ")
                    append("Not a confirmed destructive Trojan. Common in modded utilities or custom interfaces.")
                }
                isSpyware && isConfirmedSignature -> {
                    append("**High-Risk Surveillance Threat**: Classified as **Mobile Spyware / Remote Access Trojan (RAT)**. ")
                    append("Designed to covertly exfiltrate personal data. ")
                    if (hasSurveillance || hasSmsTheft) {
                        append("It combines background audio/camera access and SMS monitoring to harvest conversations, private messages, and keystrokes.")
                    }
                }
                isSpyware -> {
                    append("**Potential Surveillance Pattern**: Flagged by on-device heuristics for declaring background recording or exfiltration capabilities. ")
                    append("Not a confirmed spyware binary.")
                }
                isMalctOrRiskware -> {
                    append("**Low-Confidence Heuristic / Potential Unwanted Component**: Flagged by isolated security rules under generic heuristics. ")
                    append("Often associated with integrated advertising SDKs, analytic libraries, or repackaged binaries. Not a confirmed destructive Trojan.")
                }
                isDropper && isConfirmedSignature -> {
                    append("**Malicious Dropper**: Classified as a **Secondary Payload Dropper**. ")
                    append("Serves as an evasive initial stager engineered to bypass standard application filters and silently download secondary malicious binaries into device storage.")
                }
                isDropper -> {
                    append("**Potential Dynamic Dropper Pattern**: Flagged by on-device heuristics for declaring background installation capabilities or dynamic code loading. ")
                    append("Not a confirmed dropper Trojan.")
                }
                isTollFraud -> {
                    append("**Toll Fraud / Billing Malware**: Classified under the **Joker / Toll Fraud** family. ")
                    append("Silently subscribes the user's mobile device to unauthorized premium SMS and carrier services without notification.")
                }
                isAdware -> {
                    append("**Aggressive Adware / PUP**: Classified as intrusive adware that floods the device with unauthorized full-screen advertisements and consumes background battery and data.")
                }
                hasSmsTheft && hasOverlay -> {
                    append("**Heuristic Threat Alert (Banking Overlay & 2FA Theft Footprint)**: ThreatLens on-device heuristics detected an anomalous operational pattern. ")
                    append("The binary requests both screen overlay projection (`SYSTEM_ALERT_WINDOW`) and SMS message interception (`RECEIVE_SMS`), a combination virtually exclusive to banking credential overlay harvesters.")
                }
                hasSmsTheft -> {
                    append("**Heuristic Security Alert (2FA OTP Interception Footprint)**: ThreatLens heuristics detected SMS broadcast interception capabilities. ")
                    append("Applications with these privileges can observe incoming one-time passwords (OTP) and sensitive verification messages.")
                }
                hasOverlay -> {
                    append("**Heuristic UI Warning (Screen Overlay Capability)**: The application requests permission to draw over other active apps. ")
                    append("While sometimes used by legitimate floating utilities, this capability is frequently exploited to display deceptive phishing overlays above genuine apps.")
                }
                lower.contains("heuristic") || lower.contains("suspicious") -> {
                    append("**Heuristic Capability Finding**: While no confirmed known signature matched, the application combines high-privilege capabilities and anomalous structural patterns that elevate security and privacy risk.")
                }
                else -> {
                    append("**Threat Flagged**: Flagged by security scanning engines. ")
                    append("It exhibits anomalous behaviors or signatures deviating from standard safe Android applications.")
                }
            }
        }
        sb.append(assessmentSummary).append("\n\n")

        // Filter active vs inactive unconfigured engines
        val activeVerdicts = engineVerdicts.filter { (_, v) ->
            !v.contains("not configured", ignoreCase = true) && !v.contains("Auth-Key", ignoreCase = true)
        }
        val inactiveEngines = engineVerdicts.filter { (_, v) ->
            v.contains("not configured", ignoreCase = true) || v.contains("Auth-Key", ignoreCase = true)
        }.keys.toList()

        // 2. Multi-Engine & Antivirus Vendor Analysis (Active Engines Only)
        val flaggedEngines = activeVerdicts.filter { (_, v) ->
            val lower = v.trim().lowercase()
            !lower.startsWith("clean") && !lower.startsWith("verified") && !lower.startsWith("safe") &&
            !lower.contains("(0/") &&
            (lower.startsWith("flagged") || lower.startsWith("suspicious") || lower.contains("malicious") ||
             lower.contains("infected") || lower.contains("threat") || lower.contains("red"))
        }
        if (flaggedEngines.isNotEmpty()) {
            sb.append("### 🔬 Multi-Engine Consensus\n")
            flaggedEngines.forEach { (engine, verdict) ->
                val lower = verdict.trim().lowercase()
                val indicator = when {
                    lower.startsWith("flagged") || lower.contains("malicious") || lower.contains("infected") -> "🔴 [FLAGGED]"
                    lower.startsWith("suspicious") -> "🟡 [SUSPICIOUS]"
                    else -> "⚪ [ALERT]"
                }
                sb.append("• $indicator **$engine**: $verdict\n")
                val details = engineDetails[engine]
                if (!details.isNullOrEmpty()) {
                    details.take(4).forEach { detail ->
                        sb.append("   - $detail\n")
                    }
                }
            }
            val cleanCount = activeVerdicts.size - flaggedEngines.size
            if (cleanCount > 0) {
                sb.append("• 🟢 **Other Active Engines**: $cleanCount engine(s) verified Clean.\n")
            }
            sb.append("\n")
        } else if (activeVerdicts.isNotEmpty()) {
            sb.append("### 🔬 Multi-Engine Consensus\n")
            activeVerdicts.forEach { (engine, verdict) ->
                val lower = verdict.trim().lowercase()
                val indicator = when {
                    lower.startsWith("clean") || lower.startsWith("verified") || lower.startsWith("safe") || lower.contains("(0/") -> "🟢 [CLEAN]"
                    lower.contains("unreachable") || lower.contains("timeout") -> "⚪ [UNREACHABLE]"
                    else -> "🟢 [CLEAN]"
                }
                sb.append("• $indicator **$engine**: $verdict\n")
            }
            sb.append("\n")
        }

        // 3. Observed Malicious Behaviors (if any bytecode/runtime behaviors triggered)
        if (behaviors.isNotEmpty()) {
            sb.append("### ⚡ Observed Malicious Behaviors\n")
            behaviors.forEach { behavior ->
                val explanation = explainBehavior(behavior)
                sb.append("• **$behavior**: $explanation\n")
            }
            sb.append("\n")
        }

        // 4. High-Risk Capabilities & Permissions
        val dangerousPerms = permissions.filter { isHighRiskPermission(it) }
        if (dangerousPerms.isNotEmpty()) {
            sb.append("### 🔑 High-Risk Capabilities & Permissions\n")
            dangerousPerms.forEach { perm ->
                val explanation = explainPermission(perm)
                sb.append("• **${perm.substringAfterLast(".")}**: $explanation\n")
            }
            sb.append("\n")
        }

        // 5. Recommended Action & Guidance
        sb.append("### 🛡️ Recommended Action & Guidance\n")
        val action = when {
            isConfirmedSignature && (isBanker || isSpyware || isDropper || isRansomware) ->
                "**1. Immediate Threat Removal:** Uninstall this application from your device.\n**2. Check Device Administrators:** Verify in Android Settings that no persistent administrative privileges were granted.\n**3. Protect Financial Accounts:** If this application was recently launched, change online banking and sensitive passwords from another secure device."
            isConfirmedSignature && isTollFraud ->
                "**1. Uninstall Application:** Remove the application immediately.\n**2. Review Carrier Statement:** Check your mobile bill for unrecognized premium SMS subscription charges."
            else ->
                "**1. Review Source & Purpose:** This application was flagged under generic heuristic capability patterns or minor vendor divergence. It is not a confirmed destructive malware binary.\n**2. Check Sensitive Privileges:** Verify in Android Settings > Apps that this application has only been granted strictly necessary permissions.\n**3. Trust or Remove:** If you installed this mod or utility intentionally from a trusted source, you can add it to your Trusted Applications in Settings to suppress future alerts. If unrecognized, uninstall it at your convenience."
        }
        sb.append(action)

        // 6. Inactive Engines Coverage Notice at the very end
        if (inactiveEngines.isNotEmpty()) {
            sb.append("\n\n### ℹ️ Engine Coverage Notice\n")
            sb.append("The following engines were not queried due to missing API key configuration: **${inactiveEngines.joinToString(", ")}**. Configure keys in Settings to expand multi-engine coverage.")
        }

        return sb.toString()
    }

    private fun explainBehavior(b: String): String {
        val lower = b.lowercase()
        return when {
            lower.contains("accessibility") -> "Can inspect screen content, inject automated touches, and silently grant itself permissions."
            lower.contains("overlay") -> "Can project transparent deceptive UI overlays above banking apps to harvest passwords and OTPs."
            lower.contains("sms") -> "Can intercept one-time passwords (OTP) and exfiltrate two-factor authentication tokens."
            lower.contains("camera") || lower.contains("audio") || lower.contains("record") -> "Can capture photos or audio in the background without user awareness."
            lower.contains("admin") -> "Attempts to lock the device or prevent standard uninstallation via device administration."
            lower.contains("dex") || lower.contains("dynamic") -> "Dynamically loads secondary code from external storage or remote servers to bypass static analysis."
            else -> "High-privilege behavioral pattern frequently leveraged by malicious software."
        }
    }

    private fun explainPermission(p: String): String {
        val lower = p.lowercase()
        return when {
            lower.contains("read_sms") || lower.contains("receive_sms") -> "Allows reading incoming SMS messages, commonly exploited to steal 2FA login codes."
            lower.contains("system_alert_window") -> "Allows drawing over other apps, essential for credential phishing overlay attacks."
            lower.contains("bind_accessibility_service") -> "Grants comprehensive screen observation and UI manipulation across all apps."
            lower.contains("read_contacts") -> "Permits harvesting your entire address book for spam distribution or social engineering."
            lower.contains("access_fine_location") -> "Tracks your precise physical location in real time."
            lower.contains("record_audio") -> "Allows background microphone recording without visual notification."
            lower.contains("camera") -> "Allows taking photos or video from device cameras."
            lower.contains("install_packages") || lower.contains("request_install_packages") -> "Allows installing other applications without Play Store verification."
            else -> "High-risk system capability that should be scrutinized."
        }
    }

    private fun isHighRiskPermission(p: String): Boolean {
        val lower = p.lowercase()
        return lower.contains("sms") || lower.contains("overlay") || lower.contains("alert_window") ||
               lower.contains("accessibility") || lower.contains("admin") || lower.contains("record_audio") ||
               lower.contains("camera") || lower.contains("install_packages") || lower.contains("location")
    }
}

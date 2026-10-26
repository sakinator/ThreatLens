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

        // 1. Executive Threat Assessment
        sb.append("### 🛡️ Executive Threat Assessment\n")
        val execSummary = when {
            lower.contains("banker") || lower.contains("cerberus") || lower.contains("anatsa") || lower.contains("sharkbot") ->
                "**Critical Financial Threat**: This application is classified as a Banking Trojan designed to steal credentials and 2FA codes by superimposing fraudulent overlays above genuine banking, crypto, and payment apps."
            lower.contains("spy") || lower.contains("spynote") || lower.contains("smsstealer") ->
                "**High-Risk Spyware**: This binary functions as spyware or a surveillance tool engineered to covertly harvest SMS messages, call logs, contacts, camera feeds, and keystrokes for remote exfiltration."
            lower.contains("dropper") ->
                "**Malicious Dropper**: This application serves as a covert installer designed to bypass security filters and silently download secondary high-threat payloads (ransomware or banking Trojans) onto your device."
            lower.contains("joker") || lower.contains("toll") ->
                "**Toll Fraud / Billing Malware**: This application silently subscribes your mobile device to unauthorized premium SMS and carrier billing services without your consent."
            lower.contains("adware") || lower.contains("hiddenads") ->
                "**Aggressive Adware / PUP**: Intrusive software that floods the screen with unauthorized ads, drains battery, consumes background bandwidth, and frequently conceals its icon."
            lower.contains("heuristic") || lower.contains("suspicious") ->
                "**Suspicious Capabilities**: While no confirmed known signature matched, the application combines high-privilege capabilities and anomalous structural patterns that pose security or privacy risks."
            else ->
                "**Threat Flagged**: The file has been flagged by security engines. It exhibits anomalous behaviors or signatures that deviate from standard safe Android applications."
        }
        sb.append(execSummary).append("\n\n")

        // 2. Multi-Engine & Antivirus Vendor Analysis
        val flaggedEngines = engineVerdicts.filter { (_, v) ->
            v.contains("Flagged", ignoreCase = true) || v.contains("Suspicious", ignoreCase = true) || v.contains("Red", ignoreCase = true)
        }
        if (flaggedEngines.isNotEmpty()) {
            sb.append("### 🔬 Multi-Engine Consensus\n")
            flaggedEngines.forEach { (engine, verdict) ->
                sb.append("• **$engine**: $verdict\n")
                val details = engineDetails[engine]
                if (!details.isNullOrEmpty()) {
                    details.take(4).forEach { detail ->
                        sb.append("   - $detail\n")
                    }
                }
            }
            sb.append("\n")
        }

        // 3. Point-by-Point Findings & Risk Breakdown
        if (behaviors.isNotEmpty() || permissions.isNotEmpty()) {
            sb.append("### ⚠️ Point-by-Point Finding Analysis\n")
            behaviors.forEach { behavior ->
                val explanation = explainBehavior(behavior)
                sb.append("• **$behavior**: $explanation\n")
            }
            val dangerousPerms = permissions.filter { isHighRiskPermission(it) }
            if (dangerousPerms.isNotEmpty()) {
                dangerousPerms.forEach { perm ->
                    val explanation = explainPermission(perm)
                    sb.append("• **${perm.substringAfterLast(".")}**: $explanation\n")
                }
            }
            sb.append("\n")
        }

        // 4. Recommended Action & Remediation
        sb.append("### 🛑 Recommended Remediation\n")
        val action = when {
            lower.contains("banker") || lower.contains("spy") || lower.contains("dropper") ->
                "**1.** Immediately uninstall this application without opening it.\n**2.** Check Device Administrators in Android Settings to ensure it has not granted itself persistence.\n**3.** If recently launched, change online banking and email passwords from another device."
            lower.contains("toll") || lower.contains("joker") ->
                "**1.** Uninstall the application immediately.\n**2.** Check your mobile carrier statement for unrecognized subscription charges.\n**3.** Revoke SMS permissions for unknown apps."
            lower.contains("adware") ->
                "**1.** Remove the application from Android Settings > Apps.\n**2.** Clear browser cache and restart your device to terminate background advertising services."
            else ->
                "**1.** Do not grant accessibility or device admin privileges to this app.\n**2.** If not recognized or from an unverified source, remove the file/APK immediately."
        }
        sb.append(action)

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

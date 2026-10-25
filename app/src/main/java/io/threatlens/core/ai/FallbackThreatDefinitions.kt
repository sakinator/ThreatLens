package io.threatlens.core.ai

object FallbackThreatDefinitions {

    fun getExplanation(family: String, behaviors: List<String>): String {
        val lower = family.lowercase()
        return when {
            lower.contains("banker") || lower.contains("cerberus") || lower.contains("anatsa") || lower.contains("sharkbot") -> {
                "⚠️ **Banking Trojan Detected**: This malware monitors your screen and displays fake login windows over mobile banking, crypto, and payment apps to steal financial credentials and 2FA OTP codes. \n\n**Action**: Do not launch and uninstall immediately."
            }
            lower.contains("spy") || lower.contains("spynote") || lower.contains("smsstealer") -> {
                "⚠️ **Spyware Detected**: This threat secretly intercepts SMS messages, call logs, contacts, and keystrokes to exfiltrate private data to an attacker's remote server. \n\n**Action**: Quarantine or delete immediately."
            }
            lower.contains("dropper") -> {
                "⚠️ **Malicious Dropper Detected**: This application acts as a conduit to silently download and install secondary payloads (often ransomware or banking Trojans) in the background without user permission. \n\n**Action**: Delete package immediately."
            }
            lower.contains("joker") || lower.contains("toll") -> {
                "⚠️ **Toll Fraud / Billing Malware**: Silently subscribes the device to premium SMS services and wireless carrier billing schemes without user consent. \n\n**Action**: Uninstall immediately and verify carrier statements."
            }
            lower.contains("adware") || lower.contains("hiddenads") -> {
                "⚠️ **Aggressive Adware / PUP**: Intrusively floods the device with full-screen ads, consumes mobile data, drains battery, and may hide its app icon to prevent uninstallation. \n\n**Action**: Remove to restore device performance."
            }
            behaviors.isNotEmpty() -> {
                "⚠️ **Suspicious Behavior Detected**: Flagged for unusual capabilities: ${behaviors.take(2).joinToString(", ")}. Could compromise device security or privacy. \n\n**Action**: Review permissions before opening."
            }
            else -> {
                "⚠️ **Unverified / Suspicious File**: This file was flagged by detection engines. Exercise extreme caution before installing."
            }
        }
    }
}

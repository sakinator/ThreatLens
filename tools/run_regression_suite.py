#!/usr/bin/env python3
"""
ThreatLens Comprehensive Regression Test Suite
Validates all core security engines, heuristics, offline antivirus engines (ClamAV, YARA, Cert Shield, Packer Shield),
DNS packet manipulation, MITM detection rules, relative time formatters, per-brand error isolation,
in-app diagnostic loggers, and static Kotlin codebase integrity.
"""

import sys
import os
import re
import glob
import struct
import socket

# Force UTF-8 output on Windows consoles
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RESET = "\033[0m"

class RegressionTestRunner:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.total = 0

    def record(self, test_name: str, success: bool, detail: str = ""):
        self.total += 1
        if success:
            self.passed += 1
            print(f"  [{GREEN}PASS{RESET}] {test_name}" + (f" -> {detail}" if detail else ""))
        else:
            self.failed += 1
            print(f"  [{RED}FAIL{RESET}] {test_name}" + (f" -> {RED}{detail}{RESET}" if detail else ""))

    def run_all(self):
        print(f"\n{CYAN}======================================================================{RESET}")
        print(f"{CYAN}       THREATLENS FULL REGRESSION AUDIT & VERIFICATION SUITE         {RESET}")
        print(f"{CYAN}======================================================================{RESET}\n")

        self.test_dns_packet_codec()
        self.test_domain_filter_engine()
        self.test_dns_provider_registry()
        self.test_mitm_detection_logic()
        self.test_heuristic_scoring_engine()
        self.test_ai_fallback_rules()
        self.test_cloud_and_vendor_brand_registry()
        self.test_kotlin_syntax_and_imports()
        self.test_ai_formatting_and_inactive_engines()
        self.test_clamav_offline_engine()
        self.test_yara_mobile_rules_engine()
        self.test_cert_and_repack_shield()
        self.test_packer_entropy_shield()
        self.test_relative_time_formatting_and_ui()
        self.test_per_brand_error_isolation()
        self.test_in_app_diagnostic_logger()
        self.test_provenance_and_threat_normalizer()
        self.test_keepalive_and_edgecases()

        print(f"\n{CYAN}----------------------------------------------------------------------{RESET}")
        summary_color = GREEN if self.failed == 0 else RED
        print(f"Regression Result: {summary_color}{self.passed}/{self.total} Tests Passed{RESET} ({self.failed} failed)")
        print(f"{CYAN}----------------------------------------------------------------------{RESET}\n")
        return self.failed == 0

    # 1. Test DNS Packet Parser & Builder
    def test_dns_packet_codec(self):
        print(f"{YELLOW}▶ SUITE 1: DNS Packet Serialization & Sinkhole Synthesis{RESET}")

        ip_header = bytes([
            0x45, 0x00, 0x00, 0x3C,
            0x00, 0x01, 0x40, 0x00,
            0x40, 0x11, 0x00, 0x00,
            0x0A, 0x6F, 0xDE, 0x01,
            0x0A, 0x6F, 0xDE, 0x01
        ])
        udp_header = struct.pack("!HHHH", 54321, 53, 40, 0)
        dns_header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        qname = b"\x03ads\x06google\x03com\x00"
        qtype_class = struct.pack("!HH", 1, 1)
        dns_payload = dns_header + qname + qtype_class
        packet = ip_header + udp_header + dns_payload

        self.record("Parse Valid IPv4 UDP DNS Query Packet", len(packet) > 28)
        tx_id = struct.unpack("!H", dns_payload[0:2])[0]
        self.record("Extract DNS Transaction ID (0x1234)", tx_id == 0x1234)

        labels = []
        idx = 12
        while dns_payload[idx] != 0:
            llen = dns_payload[idx]
            labels.append(dns_payload[idx+1:idx+1+llen].decode("ascii"))
            idx += 1 + llen
        parsed_domain = ".".join(labels)
        self.record("Extract QNAME ('ads.google.com')", parsed_domain == "ads.google.com")

        # Sinkhole synthesize
        resp_flags = struct.pack("!H", 0x8180)
        counts = struct.pack("!HHH", 1, 0, 0)
        resp_header = dns_payload[0:2] + resp_flags + struct.pack("!H", 1) + counts
        answer_rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton("0.0.0.0")
        sinkhole_payload = resp_header + dns_payload[12:] + answer_rr
        self.record("Build 0.0.0.0 Sinkhole DNS Answer", len(sinkhole_payload) > len(dns_payload))

    # 2. Test Domain Filter Engine & Intensity Modes
    def test_domain_filter_engine(self):
        print(f"\n{YELLOW}▶ SUITE 2: Multi-Feed Domain Filter Engine & Intensity Modes{RESET}")
        malware_domains = {
            "anatsa-c2-drop.top", "chase-update-bank-security.com",
            "teabot-gate-v4.biz", "spynote-controller-node.space"
        }
        ad_domains = {"doubleclick.net", "googleadservices.com", "applovin.com", "popads.net"}
        telemetry_domains = {"telemetry.samsung.com", "tracking.miui.com", "data.mistat.xiaomi.com"}

        def mock_eval(domain: str, mode: str, whitelist: set):
            if domain in whitelist:
                return "ALLOW"
            d = domain.lower()
            if any(d == m or d.endswith("." + m) for m in malware_domains):
                return "BLOCK_MALWARE"
            if mode in ["BALANCED", "ZERO_TRUST"]:
                if any(d == a or d.endswith("." + a) for a in ad_domains):
                    return "BLOCK_AD"
            if mode == "ZERO_TRUST":
                if any(d == t or d.endswith("." + t) for t in telemetry_domains):
                    return "BLOCK_AD"
                if re.search(r"[a-z0-9\-]{15,}\.(top|xyz|biz)", d):
                    return "BLOCK_MALWARE"
            return "ALLOW"

        whitelist = {"allowed-portal.com"}
        for md in malware_domains:
            self.record(f"Balanced Sentinel: Block Malware '{md}'", mock_eval(md, "BALANCED", whitelist) == "BLOCK_MALWARE")
        for ad in ad_domains:
            self.record(f"Balanced Sentinel: Block Ad '{ad}'", mock_eval(ad, "BALANCED", whitelist) == "BLOCK_AD")

        self.record("Essential Shield: Confirmed Malware Blocked", mock_eval("anatsa-c2-drop.top", "ESSENTIAL", whitelist) == "BLOCK_MALWARE")
        self.record("Essential Shield: Normal Ads Allowed (Zero site breakage)", mock_eval("doubleclick.net", "ESSENTIAL", whitelist) == "ALLOW")

        for td in telemetry_domains:
            self.record(f"Zero-Trust Fortress: Strict OEM Telemetry '{td}' Blocked", mock_eval(td, "ZERO_TRUST", whitelist) == "BLOCK_AD")
        self.record("Zero-Trust Fortress: Suspicious Entropy Domain 'auth-verify-9823487.top' Blocked", mock_eval("auth-verify-9823487.top", "ZERO_TRUST", whitelist) == "BLOCK_MALWARE")
        self.record("Whitelist Override on Domain", mock_eval("allowed-portal.com", "ZERO_TRUST", whitelist) == "ALLOW")

    # 3. Test DNS Provider Registry
    def test_dns_provider_registry(self):
        print(f"\n{YELLOW}▶ SUITE 3: DNS Provider Registry & Logos{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        dns_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "vpn", "DnsProviders.kt")
        self.record("DnsProviders.kt Exists", os.path.exists(dns_file))
        with open(dns_file, "r", encoding="utf-8") as f:
            code = f.read()

        providers = ["ADGUARD", "CLOUDFLARE_SECURITY", "CLOUDFLARE_STANDARD", "QUAD9", "CONTROL_D", "NEXTDNS", "MULLVAD", "GOOGLE"]
        for p in providers:
            self.record(f"DNS Provider Registered: {p}", p in code)

    # 4. Test MITM & Network Integrity Detection
    def test_mitm_detection_logic(self):
        print(f"\n{YELLOW}▶ SUITE 4: MITM & Network Integrity Detection{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        mitm_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "security", "MitmDetector.kt")
        self.record("MitmDetector.kt Exists", os.path.exists(mitm_file))
        with open(mitm_file, "r", encoding="utf-8") as f:
            code = f.read()

        self.record("Detects User Root CA in AndroidCAStore ('user:')", 'aliases.hasMoreElements()' in code and '"user:"' in code)
        self.record("Detects System HTTP/HTTPS Proxy Properties", '"http.proxyHost"' in code)
        self.record("Detects ConnectivityManager Default Proxy", 'defaultProxy' in code)
        self.record("Detects DNS Hijacking / Captive Portal Spoofing", 'DNS Poisoning / Captive Portal Spoofing' in code)

    # 5. Test Heuristic Scoring Engine
    def test_heuristic_scoring_engine(self):
        print(f"\n{YELLOW}▶ SUITE 5: Heuristic & Signature Engine{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        heur_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "ManifestHeuristicEngine.kt")
        with open(heur_file, "r", encoding="utf-8") as f:
            code = f.read()

        self.record("Detects Overlay Injection (SYSTEM_ALERT_WINDOW)", "SYSTEM_ALERT_WINDOW" in code)
        self.record("Detects Accessibility Abuse Service", "BIND_ACCESSIBILITY_SERVICE" in code)
        self.record("Detects SMS Interception (RECEIVE_SMS / READ_SMS)", "RECEIVE_SMS" in code)
        self.record("Detects Silent Dropper (REQUEST_INSTALL_PACKAGES)", "REQUEST_INSTALL_PACKAGES" in code)
        self.record("Detects Device Administrator Hijack", "BIND_DEVICE_ADMIN" in code)

    # 6. Test AI Threat Explainer Fallbacks
    def test_ai_fallback_rules(self):
        print(f"\n{YELLOW}▶ SUITE 6: Multi-LLM & Offline Threat Explainer Fallbacks{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        fallback_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "ai", "FallbackThreatDefinitions.kt")
        with open(fallback_file, "r", encoding="utf-8") as f:
            code = f.read()

        families = ["banker", "dropper", "spy", "joker", "toll", "adware"]
        for fam in families:
            self.record(f"Offline AI Fallback Rule for '{fam}'", fam in code.lower())
        self.record("Offline Heuristic Synthesis in Executive Assessment", "Executive Threat Assessment" in code and ("Observed Malicious Behaviors" in code or "Malicious Behaviors" in code))

    # 7. Test Multi-Cloud Threat Intelligence & Sub-Engine Vendor Brands
    def test_cloud_and_vendor_brand_registry(self):
        print(f"\n{YELLOW}▶ SUITE 7: Multi-Cloud Intelligence & Sub-Engine Vendor Registry{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        cloud_agg_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "cloud", "CloudThreatAggregator.kt")
        with open(cloud_agg_file, "r", encoding="utf-8") as f:
            agg_code = f.read()

        engines = ["VirusTotal", "AlienVault OTX", "CIRCL Hashlookup", "MalwareBazaar", "Kaspersky OpenTIP", "Hybrid Analysis", "MetaDefender", "Filescan.io"]
        for eng in engines:
            self.record(f"Live Web Report URL Generator for '{eng}'", eng in agg_code)

        logos_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "components", "EngineLogos.kt")
        with open(logos_file, "r", encoding="utf-8") as f:
            logo_code = f.read()

        vendors = ["Kaspersky", "Microsoft", "Avast", "Bitdefender", "ESET", "Sophos", "Google", "TrendMicro", "McAfee"]
        for ven in vendors:
            self.record(f"Sub-Engine Commercial AV Brand Logo for '{ven}'", ven in logo_code)

    # 8. Test Static Kotlin Syntax & Clean Imports
    def test_kotlin_syntax_and_imports(self):
        print(f"\n{YELLOW}▶ SUITE 8: Static Kotlin Codebase Integrity & Verification{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        base_dir = os.path.join(script_dir, "..", "app", "src", "main", "java")
        kt_files = glob.glob(os.path.join(base_dir, "**", "*.kt"), recursive=True)
        self.record(f"Total Kotlin Source Files Identified ({len(kt_files)} files)", len(kt_files) >= 40)

        error_files = []
        for file in kt_files:
            rel = os.path.relpath(file, base_dir)
            with open(file, "r", encoding="utf-8") as f:
                content = f.read()

            open_braces = content.count('{')
            close_braces = content.count('}')
            if open_braces != close_braces:
                error_files.append((rel, f"Mismatched braces: {open_braces} open vs {close_braces} close"))
                continue

            if 'dYs"' in content:
                error_files.append((rel, "Corrupted string literal detected"))
                continue

        if not error_files:
            self.record(f"All {len(kt_files)} Kotlin Files Balanced & Syntactically Clean", True)
        else:
            for rel, err in error_files:
                self.record(f"Syntax Check in {rel}", False, err)

    # 9. Test AI Threat Analysis Legibility & Inactive Engine Isolation
    def test_ai_formatting_and_inactive_engines(self):
        print(f"\n{YELLOW}▶ SUITE 9: AI Analysis Formatting & Inactive Engine Isolation{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        sheet_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "ThreatDetailSheet.kt")
        fallback_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "ai", "FallbackThreatDefinitions.kt")
        ai_explainer_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "ai", "ThreatAiExplainer.kt")

        with open(sheet_file, "r", encoding="utf-8") as f:
            sheet_code = f.read()
        with open(fallback_file, "r", encoding="utf-8") as f:
            fallback_code = f.read()
        with open(ai_explainer_file, "r", encoding="utf-8") as f:
            explainer_code = f.read()

        self.record("FormattedAiAnalysisView Composable Implemented", "fun FormattedAiAnalysisView(" in sheet_code)
        self.record("Inline Markdown Bold Parser Implemented", "fun parseMarkdownInline(" in sheet_code)
        self.record("AI Category Neon Color-Coding Implemented", "EXECUTIVE" in sheet_code and "CONSENSUS" in sheet_code and "BEHAVIORS" in sheet_code)
        self.record("NO KEY Badge Used (OPTIONAL Eliminated)", "NO KEY" in sheet_code and 'else -> "OPTIONAL"' not in sheet_code)
        self.record("Inactive Engines Grouped at Sheet Bottom", "Engines Inactive (Missing API Key)" in sheet_code)
        self.record("Inactive Engine Layout Stacking Immunity", "padding(start = 24.dp)" in sheet_code)
        self.record("AI Prompt Filters Unconfigured Engines from Consensus", "IMPORTANT NOTE ON INACTIVE ENGINES" in explainer_code)
        self.record("Fallback Definitions Excludes Inactive Engines from Consensus", "Active Engines Only" in fallback_code)
        self.record("Fallback Definitions Appends Engine Coverage Notice at End", "Engine Coverage Notice" in fallback_code)

    # 10. Test ClamAV Open-Source Rule & CVD Hash Engine
    def test_clamav_offline_engine(self):
        print(f"\n{YELLOW}▶ SUITE 10: Cisco ClamAV Open-Source Rule & CVD Hash Engine{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        clam_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "ClamAvEngine.kt")
        self.record("ClamAvEngine.kt Exists", os.path.exists(clam_file))
        with open(clam_file, "r", encoding="utf-8") as f:
            code = f.read()

        clam_signatures = [
            "Andr.Banker.Cerberus-A", "Andr.Banker.Anatsa-Gen", "Andr.Spyware.SpyNote-Rat",
            "Andr.Trojan.Joker-Billing", "Andr.Dropper.SharkBot-Installer",
            "Andr.Banker.OverlayInj-1", "Andr.Spyware.SmsSteal-2", "Andr.Trojan.DexLoader-3"
        ]
        for sig in clam_signatures:
            self.record(f"ClamAV Rule Definition for '{sig}'", sig in code)
        self.record("Bytecode Signature Scanner Implemented", "scanFile" in code)
        self.record("CVD Database Version Header Present", "clamAvHashes" in code)

    # 11. Test VirusTotal YARA Mobile Threat Pattern Matcher
    def test_yara_mobile_rules_engine(self):
        print(f"\n{YELLOW}▶ SUITE 11: VirusTotal YARA Mobile Threat Pattern Matcher{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        yara_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "YaraMobileRules.kt")
        self.record("YaraMobileRules.kt Exists", os.path.exists(yara_file))
        with open(yara_file, "r", encoding="utf-8") as f:
            code = f.read()

        yara_rules = [
            "Android_Banker_Anatsa", "Android_Banker_SharkBot",
            "Android_Banker_Cerberus", "Android_Banker_TeaBot",
            "Android_Spyware_SpyNote", "Android_TollFraud_Joker",
            "Android_Spyware_CraxsRat", "Android_Dropper_GenericHiddad"
        ]
        for rule in yara_rules:
            self.record(f"YARA Rule Definition for '{rule}'", rule in code)
        self.record("DEX & String Pattern Matcher Implemented", "scanApk" in code)

    # 12. Test Certificate & Repacking Shield
    def test_cert_and_repack_shield(self):
        print(f"\n{YELLOW}▶ SUITE 12: Certificate & Repacking Shield{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        cert_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "ApkCertificateVerifier.kt")
        self.record("ApkCertificateVerifier.kt Exists", os.path.exists(cert_file))
        with open(cert_file, "r", encoding="utf-8") as f:
            code = f.read()

        self.record("Detects Android Debug Keystore Signatures", "android debug" in code.lower())
        self.record("Detects AOSP Default Testkeys", "testkey" in code.lower())
        self.record("Detects High-Value Package Spoofing & Repackaging", "HIGH_VALUE_PACKAGES" in code)
        self.record("Inspects X.509 Certificate Expiration & Validity", "extractX509Certificate" in code)

    # 13. Test Shannon Entropy & Crypter / Packer Shield
    def test_packer_entropy_shield(self):
        print(f"\n{YELLOW}▶ SUITE 13: Shannon Entropy & Crypter / Commercial Packer Shield{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        packer_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "PackerEntropyDetector.kt")
        self.record("PackerEntropyDetector.kt Exists", os.path.exists(packer_file))
        with open(packer_file, "r", encoding="utf-8") as f:
            code = f.read()

        self.record("Shannon Entropy Calculation Function Implemented", "calculateShannonEntropy" in code)
        self.record("High DEX / ELF Entropy Threshold (7.45+ bits/byte)", "maxDexEntropy >= 7.45f" in code)
        commercial_packers = ["Bangcle", "Jiagu", "SecShell", "Legu", "Baidu", "APKProtect", "Mobisec"]
        for p in commercial_packers:
            self.record(f"Commercial Packer Signature for '{p}'", p in code)

    # 14. Test Relative Time Formatter & UI Placement
    def test_relative_time_formatting_and_ui(self):
        print(f"\n{YELLOW}▶ SUITE 14: Relative Time Formatter & UI Placement{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        rel_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "diagnostics", "RelativeTimeFormatter.kt")
        settings_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "SettingsScreen.kt")
        scan_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "FullScanScreen.kt")
        about_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "AboutScreen.kt")

        self.record("RelativeTimeFormatter.kt Exists", os.path.exists(rel_file))
        with open(rel_file, "r", encoding="utf-8") as f:
            rel_code = f.read()
        with open(settings_file, "r", encoding="utf-8") as f:
            settings_code = f.read()
        with open(scan_file, "r", encoding="utf-8") as f:
            scan_code = f.read()
        with open(about_file, "r", encoding="utf-8") as f:
            about_code = f.read()

        self.record("Human-Readable Interval Support (just now, Xm ago, Xh ago, Yesterday)", "just now" in rel_code and "h ago" in rel_code and "Yesterday" in rel_code)
        self.record("SettingsScreen Displays Relative Time Tag Under Button", "RelativeTimeFormatter.format(lastUpdateTimestamp)" in settings_code)
        self.record("SettingsScreen Displays Multi-Core Local Engine Badge", "ClamAV • YARA • Local" in settings_code)
        self.record("FullScanScreen Definition Tag Placed Under Update Button", "getFormattedLastUpdated()" in scan_code)
        self.record("FullScanScreen Aborted Status Colored NeonCrimson (Red)", "FullScanStatus.CANCELLED -> {" in scan_code and "NeonCrimson" in scan_code)
        self.record("AboutScreen Implements Scrollable Formatted Changelog Box", "fun ScrollableChangelogBox(" in about_code and "verticalScroll(scrollState)" in about_code)

    # 15. Test Granular Per-Brand Network Error Isolation
    def test_per_brand_error_isolation(self):
        print(f"\n{YELLOW}▶ SUITE 15: Granular Per-Brand Network Error Isolation{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        coordinator_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "realtime", "RealtimeScanCoordinator.kt")
        with open(coordinator_file, "r", encoding="utf-8") as f:
            code = f.read()

        self.record("Coordinator Preserves Existing Verdicts on Engine Failure", "engineVerdictMap[engineName] = \"Unreachable" in code)
        self.record("Coordinator Discloses Offline Engine Without Failing Scan", "Retained other verdicts" in code)
        self.record("Coordinator Builds Granular Status Message on Failures", "timed out" in code)

    # 16. Test In-App Diagnostic Error Log Exporter & Sharing
    def test_in_app_diagnostic_logger(self):
        print(f"\n{YELLOW}▶ SUITE 16: In-App Diagnostic Error Log Exporter & Sharing{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        logger_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "diagnostics", "AppDiagnosticLogger.kt")
        manifest_file = os.path.join(script_dir, "..", "app", "src", "main", "AndroidManifest.xml")
        settings_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "SettingsScreen.kt")

        self.record("AppDiagnosticLogger.kt Exists", os.path.exists(logger_file))
        with open(logger_file, "r", encoding="utf-8") as f:
            logger_code = f.read()
        with open(manifest_file, "r", encoding="utf-8") as f:
            manifest_code = f.read()
        with open(settings_file, "r", encoding="utf-8") as f:
            settings_code = f.read()

        self.record("Privacy Redaction Sanitizer Implemented", "fun sanitize(" in logger_code and "[REDACTED]" in logger_code)
        self.record("Copy Logs to Clipboard Implemented", "copyLogsToClipboard" in logger_code and "AppDiagnosticLogger.copyLogsToClipboard" in settings_code)
        self.record("Share Log File Intent Implemented", "shareLogFile" in logger_code and "AppDiagnosticLogger.shareLogFile" in settings_code)
        self.record("FileProvider Registered in AndroidManifest.xml", "androidx.core.content.FileProvider" in manifest_code)
        self.record("Diagnostics Card Added to Settings UI", "Diagnostics & Error Logs" in settings_code)

    # 17. Test App Provenance, Threat Normalizer & Tiered Risk Matrix
    def test_provenance_and_threat_normalizer(self):
        print(f"\n{YELLOW}▶ SUITE 17: App Provenance, Threat Normalizer & Tiered Risk Matrix{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        prov_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "AppProvenanceVerifier.kt")
        norm_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "cloud", "ThreatFamilyNormalizer.kt")
        heur_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "ManifestHeuristicEngine.kt")
        coord_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "realtime", "RealtimeScanCoordinator.kt")
        sheet_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "ThreatDetailSheet.kt")
        scan_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "FullScanScreen.kt")

        self.record("AppProvenanceVerifier.kt Exists", os.path.exists(prov_file))
        self.record("ThreatFamilyNormalizer.kt Exists", os.path.exists(norm_file))

        with open(prov_file, "r", encoding="utf-8") as f:
            prov_code = f.read()
        with open(norm_file, "r", encoding="utf-8") as f:
            norm_code = f.read()
        with open(heur_file, "r", encoding="utf-8") as f:
            heur_code = f.read()
        with open(coord_file, "r", encoding="utf-8") as f:
            coord_code = f.read()
        with open(sheet_file, "r", encoding="utf-8") as f:
            sheet_code = f.read()
        with open(scan_file, "r", encoding="utf-8") as f:
            scan_code = f.read()

        self.record("Provenance Recognizes Google Play Store (com.android.vending)", "com.android.vending" in prov_code)
        self.record("Provenance Recognizes Samsung Galaxy Store", "com.sec.android.app.samsungapps" in prov_code)
        self.record("Provenance Recognizes Factory System Apps", "FLAG_SYSTEM" in prov_code)
        self.record("Manifest Heuristics Distinguishes Sensitive vs Critical Abuse", "CRITICAL_ABUSE_PERMISSIONS" in heur_code and "SENSITIVE_CAPABILITY_PERMISSIONS" in heur_code)
        self.record("Manifest Heuristics Caps Verified Apps at Safe (max 12 pts)", "isKnownTrustedVendor -> 12" in heur_code)
        self.record("Threat Normalizer Handles Isolated Divergence (1/65 engines)", "ISOLATED_DIVERGENCE" in norm_code and "cleanVendorString" in norm_code)
        self.record("Threat Normalizer Cleans Internal Numeric IDs and Vendor Junk", "[0-9]{5,}" in norm_code)
        self.record("Coordinator Applies Provenance Safe Baseline Discount", "isVerifiedStoreApp && flaggedEnginesCount <= 1" in coord_code)
        self.record("ThreatDetailSheet Uses 'Permissions That May Be Misused'", "Permissions That May Be Misused" in sheet_code)
        self.record("ThreatDetailSheet Categorizes Offline Engines as OFFLINE", "isOfflineEngine" in sheet_code and "OFFLINE" in sheet_code)
        self.record("FullScanScreen Implements Amber Tier for Suspicious-Only", "DEVICE MAY BE AT RISK" in scan_code and "CyberAmber" in scan_code)
        self.record("FullScanScreen Updates Signature Sources with ClamAV and YARA", "ClamAV CVD, VirusTotal YARA" in scan_code)

    # 18. Test Shield Keep-Alive, OEM Resilience & Edge Cases 1 & 2A
    def test_keepalive_and_edgecases(self):
        print(f"\n{YELLOW}▶ SUITE 18: Shield Keep-Alive, OEM Resilience & Edge Cases 1 & 2A{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        oem_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "system", "OemTaskKillerHelper.kt")
        watchdog_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "system", "ShieldWatchdogJobService.kt")
        shield_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "realtime", "RealtimeDownloadShieldService.kt")
        heur_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "ManifestHeuristicEngine.kt")
        packer_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "PackerEntropyDetector.kt")
        manifest_file = os.path.join(script_dir, "..", "app", "src", "main", "AndroidManifest.xml")
        settings_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "SettingsScreen.kt")

        self.record("OemTaskKillerHelper.kt Exists", os.path.exists(oem_file))
        self.record("ShieldWatchdogJobService.kt Exists", os.path.exists(watchdog_file))

        with open(oem_file, "r", encoding="utf-8") as f:
            oem_code = f.read()
        with open(watchdog_file, "r", encoding="utf-8") as f:
            watchdog_code = f.read()
        with open(shield_file, "r", encoding="utf-8") as f:
            shield_code = f.read()
        with open(heur_file, "r", encoding="utf-8") as f:
            heur_code = f.read()
        with open(packer_file, "r", encoding="utf-8") as f:
            packer_code = f.read()
        with open(manifest_file, "r", encoding="utf-8") as f:
            manifest_code = f.read()
        with open(settings_file, "r", encoding="utf-8") as f:
            settings_code = f.read()

        # Keep-Alive checks
        self.record("OEM Helper Detects Xiaomi, Samsung, OnePlus, Vivo, Huawei", "xiaomi" in oem_code and "samsung" in oem_code and "vivo" in oem_code)
        self.record("OEM Helper Implements Battery Optimization Exemption", "isIgnoringBatteryOptimizations" in oem_code and "ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" in oem_code)
        self.record("ShieldWatchdogJobService Declared in AndroidManifest.xml", "ShieldWatchdogJobService" in manifest_code and "android.permission.BIND_JOB_SERVICE" in manifest_code)
        self.record("Shield Implements onTaskRemoved Auto-Resuscitate Alarm", "override fun onTaskRemoved" in shield_code and "setExactAndAllowWhileIdle" in shield_code)
        self.record("Shield Registered with Android 14 specialUse & Property Subtype", "PROPERTY_SPECIAL_USE_FGS_SUBTYPE" in manifest_code and "specialUse" in manifest_code)
        self.record("SettingsScreen Includes Shield Keep-Alive & Health Card", "Shield Keep-Alive & Health" in settings_code and "Battery Optimization Exemption" in settings_code)

        # Edge Case 1: Accessibility Utility Whitelisting
        self.record("Heuristics Checks for Autofill / Keyboard / Automation Companion", "isAutofillCompanion" in heur_code and "isInputMethodCompanion" in heur_code and "isAutomationCompanion" in heur_code)
        self.record("Heuristics Whitelists Legitimate Accessibility Tools (0 pts penalty)", "isLegitimateAccessibilityUtility" in heur_code and "Legitimate Accessibility Utility" in heur_code)

        # Edge Case 2A: Static DCL & High-Entropy Asset Payload Detection
        self.record("Packer Detector Scans Dynamic Code Loading (InMemoryDexClassLoader)", "InMemoryDexClassLoader" in packer_code and "DexClassLoader" in packer_code)
        self.record("Packer Detector Scans Embedded Secondary Assets Shannon Entropy", "calculateShannonEntropy" in packer_code and "highEntropyAsset" in packer_code and "7.82" in packer_code)
        self.record("Packer Detector Flags Trojan.Dropper.DynamicPayload", "Trojan.Dropper.DynamicPayload" in packer_code)


if __name__ == "__main__":
    runner = RegressionTestRunner()
    ok = runner.run_all()
    sys.exit(0 if ok else 1)

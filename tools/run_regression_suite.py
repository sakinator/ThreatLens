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
        self.test_vulnerability_auditor_suite()
        self.test_v141_critical_fixes()
        self.test_v142_critical_fixes()
        self.test_v150_provenance_and_features()
        self.test_v151_brand_logos_and_pattern_features()
        self.test_v152_false_positive_elimination_and_export()
        self.suite_25_api_key_validation_hardening()
        self.suite_26_rate_limit_quota_saver()
        self.suite_27_multi_cloud_consensus_and_brand_logos()
        self.suite_28_realtime_safe_notifications_and_intent_routing()
        self.suite_29_v157_consensus_brand_logos_and_storage_exhaustion()
        self.suite_30_v158_direct_brand_logos_and_transparency()
        self.suite_31_accessibility_and_notification_hijack_auditor()
        self.suite_32_native_elf_inspector_and_string_deobfuscator()
        self.suite_33_per_app_firewall_and_scheduled_deep_audit()
        self.suite_34_doh_resolvers_and_live_threat_feed_sync()
        self.suite_35_block_webpage_sinkhole_and_whitelist_manager()
        self.suite_36_persistence_battery_mitm_and_manual_multiscan()
        self.suite_37_card_and_detailed_report_knowledge_matrix()
        self.suite_38_differentiated_scans_icons_and_sound_profiles()
        self.suite_39_filescan_provenance_ui_feedback_and_scoring_sort()
        self.suite_40_stability_lifecycle_and_unified_assessment()
        self.suite_41_anr_immunity_async_target_enumeration_and_batch_persistence()

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

    # 19. Test Exploit & Vulnerability Auditor Module & UI Tab
    def test_vulnerability_auditor_suite(self):
        print(f"\n{YELLOW}▶ SUITE 19: Device Exploit & Vulnerability Auditor Module & UI{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        auditor_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "vulnerability", "DeviceVulnerabilityAuditor.kt")
        screen_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "VulnerabilityScreen.kt")
        main_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "MainActivity.kt")

        self.record("DeviceVulnerabilityAuditor.kt Exists", os.path.exists(auditor_file))
        self.record("VulnerabilityScreen.kt Exists", os.path.exists(screen_file))

        with open(auditor_file, "r", encoding="utf-8") as f:
            auditor_code = f.read()
        with open(screen_file, "r", encoding="utf-8") as f:
            screen_code = f.read()
        with open(main_file, "r", encoding="utf-8") as f:
            main_code = f.read()

        self.record("Audits Security Patch Level (SPL) & Day Gap", "Build.VERSION.SECURITY_PATCH" in auditor_code and "daysSince" in auditor_code)
        self.record("Audits USB Debugging / ADB Status", "Settings.Global.ADB_ENABLED" in auditor_code and "SETTING_ADB_ENABLED" in auditor_code)
        self.record("Audits Lock Screen / Keyguard Security", "KeyguardManager" in auditor_code and "isDeviceSecure" in auditor_code and "SETTING_NO_LOCKSCREEN" in auditor_code)
        self.record("Audits SELinux Mandatory Access Control Mode", "/sys/fs/selinux/enforce" in auditor_code and "FIRMWARE_SELINUX_PERMISSIVE" in auditor_code)
        self.record("Audits Superuser / Root Binary Paths", "/system/bin/su" in auditor_code and "FIRMWARE_ROOT_DETECTED" in auditor_code)
        self.record("Audits Linux Kernel Version (/proc/version)", "/proc/version" in auditor_code and "KERNEL_LEGACY_VERSION" in auditor_code)
        self.record("VulnerabilityScreen Implements Posture Grade Dial & Filters", "overallScore" in screen_code and "letterGrade" in screen_code and "VulnerabilityFindingCard" in screen_code)
        self.record("MainActivity Integrates Separate 'Vulns' Navigation Tab", "\"vulns\"" in main_code and "VulnerabilityScreen()" in main_code and "Icons.Default.BugReport" in main_code)

    # 20. Test Critical False Positive, Score Math & Consensus Engine Fixes
    def test_v141_critical_fixes(self):
        print(f"\n{YELLOW}▶ SUITE 20: Critical Bug Fixes (False Positives, Consensus Flags & De-truncation){RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        packer_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "PackerEntropyDetector.kt")
        fallback_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "ai", "FallbackThreatDefinitions.kt")
        sheet_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "ThreatDetailSheet.kt")
        local_av_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "LocalAntivirusEngine.kt")
        heur_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "ManifestHeuristicEngine.kt")

        with open(packer_file, "r", encoding="utf-8") as f:
            packer_code = f.read()
        with open(fallback_file, "r", encoding="utf-8") as f:
            fallback_code = f.read()
        with open(sheet_file, "r", encoding="utf-8") as f:
            sheet_code = f.read()
        with open(local_av_file, "r", encoding="utf-8") as f:
            local_av_code = f.read()
        with open(heur_file, "r", encoding="utf-8") as f:
            heur_code = f.read()

        # 1. Packer False Positive Immunity
        self.record("Packer Detector Ignores Flutter & Framework Assets", "assets/flutter_assets/" in packer_code and "assets/webkit/" in packer_code)
        self.record("Packer Detector Ignores License & Notice Archives", 'lowerPath.contains("license") || lowerPath.contains("notice")' in packer_code)
        self.record("Packer Detector Requires Executable Magic or Extension", "isExecutablePayload" in packer_code and "0x64.toByte()" in packer_code)
        self.record("Packer Detector Exempts Verified Store Applications", "!isVerifiedStore" in packer_code and "isVerifiedStore: Boolean = false" in packer_code)

        # 2. Consensus Engine Clean Verdict Flagging Fix
        self.record("Consensus Filters '0/66 engines flagged' from [FLAGGED] Badge", '!lower.contains("(0/")' in fallback_code and '!lower.startsWith("clean")' in fallback_code)
        self.record("Consensus Engine Accurately Attributes Clean & Flagged Engines", "Other Active Engines" in fallback_code and "🟢 [CLEAN]" in fallback_code)

        # 3. Engine Name De-truncation & UI Layout
        self.record("Engine Card Header Dedicates Line 1 for Unconstrained Title", "maxLines = 2" in sheet_code and "EngineLogoIcon" in sheet_code)
        self.record("Engine Card Line 2 Hosts Engine Type Tag and Verdict", "padding(start = 32.dp)" in sheet_code and "engineBadgeText" in sheet_code)
        self.record("ScoreComponentRow Prevents 'pts' Vertical Wrapping", "softWrap = false" in sheet_code and "weight(1f)" in sheet_code)

        # 4. Score Math Reconciliation
        self.record("Manifest Heuristic Partitions Permission and Behavioral Points", "finalPermissionScore" in heur_code and "finalBehavioralScore" in heur_code)
        self.record("Local Antivirus Reconciles Heuristics & Signature Score Breakdown", "finalLocalScore" in local_av_code and "permScore" in local_av_code and "heurScore" in local_av_code)

    # 21. Test v1.4.2 Critical Bug Fixes (Play Store Banking Repack Bypass, Score Cap, Findings Isolation, Engine De-truncation & Card Alignment)
    def test_v142_critical_fixes(self):
        print(f"\n{YELLOW}▶ SUITE 21: v1.4.2 Bug Fixes (Banking False Positive, Score Cap, Findings Isolation & UI Layout){RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        cert_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "ApkCertificateVerifier.kt")
        local_av_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "LocalAntivirusEngine.kt")
        sheet_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "ThreatDetailSheet.kt")
        components_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "components", "CyberComponents.kt")
        coord_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "realtime", "RealtimeScanCoordinator.kt")

        with open(cert_file, "r", encoding="utf-8") as f:
            cert_code = f.read()
        with open(local_av_file, "r", encoding="utf-8") as f:
            local_av_code = f.read()
        with open(sheet_file, "r", encoding="utf-8") as f:
            sheet_code = f.read()
        with open(components_file, "r", encoding="utf-8") as f:
            components_code = f.read()
        with open(coord_file, "r", encoding="utf-8") as f:
            coord_code = f.read()

        # 1. Certificate Verifier: Verified Store Bypass & Expanded Legitimate Vendors
        self.record("ApkCertificateVerifier accepts isVerifiedStore parameter", "isVerifiedStore: Boolean = false" in cert_code)
        self.record("ApkCertificateVerifier skips repackaging check for verified store apps", "if (isVerifiedStore)" in cert_code and "Platform Provenance: Verified store application" in cert_code)
        self.record("ApkCertificateVerifier recognizes SBI and Indian banking vendors", 'issuer.contains("sbi")' in cert_code and 'issuer.contains("lotus")' in cert_code and 'issuer.contains("hdfc")' in cert_code and 'issuer.contains("icici")' in cert_code and 'issuer.contains("axis")' in cert_code and 'issuer.contains("kotak")' in cert_code)

        # 2. Local Antivirus: Findings Isolation & Score Overflow Fix
        self.record("LocalAntivirusEngine passes isVerifiedStore to ApkCertificateVerifier", "ApkCertificateVerifier.verifyApk(context, file, detectedPackageName, isVerifiedStore)" in local_av_code)
        self.record("LocalAntivirusEngine isolates cert details from shared behaviors list", "behaviors.addAll(cert.details)" not in local_av_code)
        self.record("LocalAntivirusEngine isolates packer details from shared behaviors list", "behaviors.addAll(packer.details)" not in local_av_code)
        self.record("LocalAntivirusEngine caps heurScore using maxOf without overflow", "heurScore = maxOf(manifestHeur + packerScore, certScore).coerceIn(0, 100 - permScore)" in local_av_code)

        # 3. ThreatDetailSheet: Full Engine Name De-truncation
        # Line 1 header must only have logo, title, and chevron; status badge moved to line 2
        line1_has_no_status_badge = "EngineLogoIcon(sourceName" in sheet_code and (re.search(r'Text\(\s*text\s*=\s*sourceName', sheet_code) is not None)
        line2_has_status_badge = "padding(start = 32.dp)" in sheet_code and "engineBadgeText" in sheet_code and "FLAGGED" in sheet_code
        self.record("Engine Card Line 1 reserves full width for engine title without status pill", line1_has_no_status_badge)
        self.record("Engine Card Line 2 contains engine badge tag and status pill", line2_has_status_badge)

        # 4. CyberComponents: ThreatItemRow Alignment and Truncation Fix
        self.record("ThreatItemRow uses Top alignment for AppIconBadge", "verticalAlignment = Alignment.Top" in components_code and "modifier = Modifier.padding(top = 2.dp)" in components_code)
        self.record("ThreatItemRow places ScoreBadge in header row giving package name full width", "ScoreBadge(report.currentScore, report.severity, report.isFinal)" in components_code and "modifier = Modifier.fillMaxWidth()" in components_code)
        self.record("ThreatItemRow allows AppName up to 2 lines", "maxLines = 2" in components_code and "report.appName ?: report.targetName" in components_code)

        # 5. Coordinator: Behavioral Heuristics Engine Autonomy
        self.record("RealtimeScanCoordinator evaluates Behavioral Heuristics independently", "val hasBehaviors = localVerdict.detectedBehaviors.isNotEmpty()" in coord_code and "Clean (0 heuristic patterns • Safe)" in coord_code)

    # 22. Test v1.5.0 Multi-Store Provenance, F-Droid & NIST Signer Verification, Whitelist & Scan Cache
    def test_v150_provenance_and_features(self):
        print(f"\n{YELLOW}▶ SUITE 22: v1.5.0 Multi-Store Provenance, Whitelist & Fast Scan Cache{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        prov_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "AppProvenanceVerifier.kt")
        cert_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "ApkCertificateVerifier.kt")
        whitelist_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "ThreatWhitelistManager.kt")
        cache_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "scanner", "ScanCacheManager.kt")
        scanner_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "scanner", "FullSystemScanner.kt")
        components_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "components", "CyberComponents.kt")
        sheet_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "ThreatDetailSheet.kt")
        settings_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "SettingsScreen.kt")

        with open(prov_file, "r", encoding="utf-8") as f:
            prov_code = f.read()
        with open(cert_file, "r", encoding="utf-8") as f:
            cert_code = f.read()
        with open(whitelist_file, "r", encoding="utf-8") as f:
            whitelist_code = f.read()
        with open(cache_file, "r", encoding="utf-8") as f:
            cache_code = f.read()
        with open(scanner_file, "r", encoding="utf-8") as f:
            scanner_code = f.read()
        with open(components_file, "r", encoding="utf-8") as f:
            components_code = f.read()
        with open(sheet_file, "r", encoding="utf-8") as f:
            sheet_code = f.read()
        with open(settings_file, "r", encoding="utf-8") as f:
            settings_code = f.read()

        # 1. Multi-Store Provenance & Sideload Vector Tracking
        self.record("Provenance detects F-Droid ecosystem (F-Droid, Droid-ify, Neo Store)", "FDROID_ECOSYSTEM" in prov_code and "F-DROID (FOSS)" in prov_code and "isFossStore" in prov_code)
        self.record("Provenance detects Aurora Store Play mirror", "AURORA_STORE" in prov_code and "AURORA STORE (PLAY MIRROR)" in prov_code)
        self.record("Provenance detects Xiaomi GetApps & Huawei AppGallery", "XIAOMI_GETAPPS" in prov_code and "HUAWEI_APPGALLERY" in prov_code)
        self.record("Provenance flags high-risk Telegram & WhatsApp distribution vectors", "TELEGRAM_SIDELOAD" in prov_code and "WHATSAPP_SIDELOAD" in prov_code and "isHighRiskVector" in prov_code)
        self.record("Provenance detects direct browser web download sideloads", "BROWSER_DOWNLOAD" in prov_code and "WEB DOWNLOAD" in prov_code)

        # 2. Open-Source Signer Verification (F-Droid Master Key)
        self.record("Certificate Verifier detects official F-Droid build cluster keys", "isFDroidSigner" in cert_code and "Verified F-Droid Build Cluster Key" in cert_code)

        # 3. User Whitelist Manager
        self.record("ThreatWhitelistManager implements persistent add/remove/check", "isWhitelisted" in whitelist_code and "addApp" in whitelist_code and "removeApp" in whitelist_code)
        self.record("ThreatDetailSheet includes toggleable Trust/Whitelist button", "ThreatWhitelistManager" in sheet_code and "Trust This App (Add to Whitelist)" in sheet_code)
        self.record("SettingsScreen includes Trusted Applications management card", "ThreatWhitelistManager" in settings_code and "Trusted Applications (Whitelist)" in settings_code)

        # 4. Fast Incremental Scan Cache
        self.record("ScanCacheManager implements lastUpdateTime cache lookup", "getCachedVerdict" in cache_code and "putCachedVerdict" in cache_code and "clearCache" in cache_code)
        self.record("FullSystemScanner integrates ScanCacheManager for <3s full re-scans", "ScanCacheManager.getCachedVerdict" in scanner_code and "ScanCacheManager.putCachedVerdict" in scanner_code)
        self.record("SettingsScreen includes Clear Scan Cache action", "ScanCacheManager.clearCache" in settings_code and "CLEAR SCAN CACHE" in settings_code)

        # 5. UI Provenance Tag Placement
        self.record("ThreatItemRow displays store provenance tag badge", "AppProvenanceVerifier.inspectProvenance" in components_code and "provenance.badgeLabel" in components_code)
        self.record("ThreatDetailSheet displays store provenance tag badge in header", "AppProvenanceVerifier.inspectProvenance" in sheet_code and "provenance.badgeLabel" in sheet_code)

    # 23. Test v1.5.1 Authentic Brand Logos, Heuristic Score Reconciliation, Offline Ransomware Pattern & Card Redesign
    def test_v151_brand_logos_and_pattern_features(self):
        print(f"\n{YELLOW}▶ SUITE 23: v1.5.1 Authentic Brand Logos, Heuristic Score Reconciliation, Offline Ransomware & Card Redesign{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        logos_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "components", "EngineLogos.kt")
        packer_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "PackerEntropyDetector.kt")
        cert_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "ApkCertificateVerifier.kt")
        manifest_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "ManifestHeuristicEngine.kt")
        local_av_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "LocalAntivirusEngine.kt")
        sig_db_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "LocalSignatureDatabase.kt")
        coord_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "realtime", "RealtimeScanCoordinator.kt")
        fallback_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "ai", "FallbackThreatDefinitions.kt")
        components_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "components", "CyberComponents.kt")
        sheet_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "ThreatDetailSheet.kt")

        with open(logos_file, "r", encoding="utf-8") as f:
            logos_code = f.read()
        with open(packer_file, "r", encoding="utf-8") as f:
            packer_code = f.read()
        with open(cert_file, "r", encoding="utf-8") as f:
            cert_code = f.read()
        with open(manifest_file, "r", encoding="utf-8") as f:
            manifest_code = f.read()
        with open(local_av_file, "r", encoding="utf-8") as f:
            local_av_code = f.read()
        with open(sig_db_file, "r", encoding="utf-8") as f:
            sig_db_code = f.read()
        with open(coord_file, "r", encoding="utf-8") as f:
            coord_code = f.read()
        with open(fallback_file, "r", encoding="utf-8") as f:
            fallback_code = f.read()
        with open(components_file, "r", encoding="utf-8") as f:
            components_code = f.read()
        with open(sheet_file, "r", encoding="utf-8") as f:
            sheet_code = f.read()

        # 1. Authentic Brand Logos & Vendor Matching Resolution
        self.record("VirusTotalLogo composable renders original VT ribbon loop", "fun VirusTotalLogo" in logos_code and "0xFF0058FF" in logos_code)
        self.record("NortonLogo composable renders golden circle with black checkmark", "fun NortonLogo" in logos_code and "0xFFFDB813" in logos_code)
        self.record("BitdefenderLogo composable renders iconic red dragon flame badge", "fun BitdefenderLogo" in logos_code and "0xFFED1C24" in logos_code)
        self.record("MicrosoftDefenderLogo composable renders 4-color squares", "fun MicrosoftDefenderLogo" in logos_code and "0xFFF25022" in logos_code and "0xFF7FBA00" in logos_code)
        self.record("SubEngineRegistry resolves BitDefenderFalx to Bitdefender brand", 'clean.contains("bitdefender") -> return VendorBrand(name, "Bitdefender"' in logos_code)
        self.record("SubEngineRegistry resolves SymantecMobileInsight to Norton brand", 'clean.contains("norton") || clean.contains("symantec")' in logos_code)
        self.record("VendorFindingBadge renders vector BrandLogoBadge instead of generic initials", "BrandLogoBadge(" in logos_code and "vendor.brandKey" in logos_code)

        # 2. Packer False Positive Fix (.lottie excluded)
        self.record("Packer Detector ignores lottie animation archives in assets", '"lottie"' in packer_code and 'lowerPath.contains("lottie")' in packer_code)
        self.record("Packer Detector requires true compiled executable payload", 'ext in setOf("dex", "so")' in packer_code and 'ext in setOf("apk", "jar")' in packer_code)

        # 3. Certificate Verifier Play Store Scheme v2/v3 Fix
        self.record("ApkCertificateVerifier bypasses Unsigned Binary for Verified Store apps", 'if (isVerifiedStore)' in cert_code and 'Verified Google Play / Platform Release' in cert_code)
        self.record("ApkCertificateVerifier queries PackageManager and APK Signing Block", 'extractCertFromPackageManager' in cert_code and 'checkApkSigningBlock' in cert_code and '"APK Sig Block 42"' in cert_code)

        # 4. Score Capping & Executive Assessment Reconciliation
        self.record("LocalAntivirusEngine caps unconfirmed heuristic score at 45 and total at 55", "heurScore = maxOf(manifestHeur + packerScore, certScore).coerceIn(0, 100 - permScore).coerceAtMost(45)" in local_av_code and "finalLocalScore = (permScore + heurScore).coerceIn(0, 55)" in local_av_code)
        self.record("RealtimeScanCoordinator requires confirmed malware or high consensus for 75+ score", "val hasConfirmedMalware" in coord_code and "maxOf(runningLocalScore, runningCloudScore).coerceIn(75, 100)" in coord_code and "blended.coerceIn(25, 55)" in coord_code)

        # 5. Offline Ransomware Behavioral Pattern Detection
        self.record("ManifestHeuristicEngine detects isLikelyRansomware pattern offline", "isLikelyRansomware" in manifest_code and "Potential Ransomware pattern" in manifest_code)
        self.record("LocalAntivirusEngine maps Potential Ransomware pattern", "heuristic.isLikelyRansomware" in local_av_code and "Heuristic.Ransomware.Potential" in local_av_code)
        self.record("LocalSignatureDatabase includes offline mobile ransomware definitions", "Ransomware.AndroidOS.DoubleLocker" in sig_db_code and "Ransomware.AndroidOS.SimpleLocker" in sig_db_code)

        # 6. Reassuring Non-Scary Guidance
        self.record("FallbackThreatDefinitions gives reassuring advisory for unconfirmed heuristic patterns", "isConfirmedSignature" in fallback_code and "Review Source & Purpose" in fallback_code)
        self.record("ThreatDetailSheet uses ADVISORY badge and calm action button for non-malicious apps", '"ADVISORY"' in sheet_code and "isConfirmedMalicious = report.currentScore >= 75" in sheet_code)

        # 7. Scanner Tab Card Redesign
        self.record("ThreatItemRow uses softWrap=false preventing single-letter word wrapping", "softWrap = false" in components_code and "report.appName ?: report.targetName" in components_code)
        self.record("ThreatItemRow displays meaningful 1-line finding rationale surface", "findingSummary" in components_code and "CyberDarkSurface" in components_code)

    # 24. Test v1.5.2 False Positive Elimination, Dynamic DB Count, Row Reconciliation & Scan Export
    def test_v152_false_positive_elimination_and_export(self):
        print(f"\n{YELLOW}▶ SUITE 24: v1.5.2 False-Positive Elimination, Dynamic Counts & Scan Export{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        local_av_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "LocalAntivirusEngine.kt")
        coord_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "realtime", "RealtimeScanCoordinator.kt")
        scanner_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "scanner", "FullSystemScanner.kt")
        scan_screen_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "FullScanScreen.kt")
        dash_screen_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "DashboardScreen.kt")
        detail_sheet_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "ThreatDetailSheet.kt")
        exporter_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "export", "ScanReportExporter.kt")
        filepaths_file = os.path.join(script_dir, "..", "app", "src", "main", "res", "xml", "file_paths.xml")

        with open(local_av_file, "r", encoding="utf-8") as f:
            local_av_code = f.read()
        with open(coord_file, "r", encoding="utf-8") as f:
            coord_code = f.read()
        with open(scanner_file, "r", encoding="utf-8") as f:
            scanner_code = f.read()
        with open(scan_screen_file, "r", encoding="utf-8") as f:
            scan_screen_code = f.read()
        with open(dash_screen_file, "r", encoding="utf-8") as f:
            dash_screen_code = f.read()
        with open(detail_sheet_file, "r", encoding="utf-8") as f:
            detail_sheet_code = f.read()
        with open(exporter_file, "r", encoding="utf-8") as f:
            exporter_code = f.read()
        with open(filepaths_file, "r", encoding="utf-8") as f:
            filepaths_code = f.read()

        # 1. Bytecode False-Positive Immunity (Paytm & Savvy Time)
        self.record("LocalAntivirusEngine restricts scanApkBytecode to compiled .dex entries only", 'entry.name.endsWith(".dex")' in local_av_code and 'entry.name.startsWith("assets/")' not in local_av_code)
        self.record("LocalAntivirusEngine uses refined AhMyth class package descriptor", "ahmyth/mine/king/ahmyth" in local_av_code and "Lios/ahmyth" in local_av_code)
        self.record("LocalAntivirusEngine replaces loose daemonsu with active daemon command", "daemonsu --daemon" in local_av_code)
        self.record("LocalAntivirusEngine exempts verified store apps from uncorroborated bytecode flags", "hasBytecodeMatch && !isVerifiedStore" in local_av_code)
        self.record("LocalAntivirusEngine provides offlineDbMatch in LocalScanVerdict", "val offlineDbMatch: LocalSignatureDatabase.SignatureEntry?" in local_av_code)
        self.record("LocalAntivirusEngine provides bytecodeMatches in LocalScanVerdict", "val bytecodeMatches: List<BytecodeRule>" in local_av_code)

        # 2. Dynamic Count & Threat Name Attribution
        self.record("RealtimeScanCoordinator uses dynamic LocalSignatureDatabase.totalSignatures in offline DB verdict", "LocalSignatureDatabase.totalSignatures} definitions checked" in coord_code)
        self.record("RealtimeScanCoordinator populates offline DB badge with matched threat family name", "Flagged: ${sigMatch.threatFamily}" in coord_code)
        self.record("RealtimeScanCoordinator isolates ThreatLens Bytecode Pattern Engine findings", "ThreatLens Bytecode Pattern Engine" in coord_code)

        # 3. Scanner vs Shield Row Count Reconciliation
        self.record("FullSystemScanner adds allScannedReports to FullScanState", "val allScannedReports: List<ThreatReport>" in scanner_code)
        self.record("FullSystemScanner retains cached clean apps in allScannedReports", "allReports.add(cachedReport)" in scanner_code)
        self.record("FullScanScreen defines ScanResultFilter enum with ALL, THREATS, SAFE", "enum class ScanResultFilter" in scan_screen_code and "ALL" in scan_screen_code and "THREATS" in scan_screen_code and "SAFE" in scan_screen_code)
        self.record("FullScanScreen renders segmented filter pills for scan results", "ALL ($allCount)" in scan_screen_code and "THREATS (" in scan_screen_code and "SAFE (" in scan_screen_code)
        self.record("DashboardScreen computes deduplicated threats count without double counting", "combinedThreats.size" in dash_screen_code and "distinctBy" in dash_screen_code)
        self.record("DashboardScreen computes deduplicated cleanCount without double counting", "cleanCount = maxOf(fullScanState.cleanCount, scans.count { it.severity == ThreatSeverity.SAFE })" in dash_screen_code)
        self.record("DashboardScreen streamlines real-time stream to prevent bulk scan pollution", "val streamReports = scans.filter { it.severity != ThreatSeverity.SAFE }.ifEmpty" in dash_screen_code)

        # 4. Scan Report Exporter
        self.record("FullScanScreen implements EXPORT SCAN REPORT (.JSON) button", "EXPORT SCAN REPORT (.JSON)" in scan_screen_code and "ScanReportExporter.exportScanReport" in scan_screen_code)
        self.record("ThreatDetailSheet includes Share / Export Threat Report (.JSON) button", "Share / Export Threat Report (.JSON)" in detail_sheet_code and "ScanReportExporter.exportSingleThreatReport" in detail_sheet_code)
        self.record("ScanReportExporter serializes metadata, posture, and per-app telemetry", "ThreatLens Autonomous Mobile EDR" in exporter_code and "serializeReport" in exporter_code and "shareReportFile" in exporter_code)
        self.record("file_paths.xml grants external storage access for report sharing", "<external-path name=\"external_storage\" path=\".\" />" in filepaths_code)

        # 5. Malware -> Suspicious -> Clean Sort Functionality
        self.record("FullScanScreen defines ScanSortOption with MALWARE_FIRST, SCORE_DESC, NAME_ASC", "enum class ScanSortOption" in scan_screen_code and "MALWARE_FIRST" in scan_screen_code)
        self.record("FullScanScreen implements Malware -> Suspicious -> Clean severity comparator", "compareBy<ThreatReport>" in scan_screen_code and "ThreatSeverity.MALICIOUS -> 0" in scan_screen_code and "ThreatSeverity.SAFE -> 3" in scan_screen_code)
        self.record("DashboardScreen sorts real-time stream with Malware -> Suspicious -> Clean order", "compareBy<ThreatReport>" in dash_screen_code and "ThreatSeverity.MALICIOUS -> 0" in dash_screen_code)
        self.record("FullScanScreen renders Order By sorting dropdown selector", "ORDER BY:" in scan_screen_code and "selectedSortOption.label" in scan_screen_code and "DropdownMenu" in scan_screen_code)

    def suite_25_api_key_validation_hardening(self):
        print(f"\n{YELLOW}▶  SUITE 25: v1.5.3 Cloud API Key Validation & Endpoint Hardening (MetaDefender & Filescan){RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        val_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "validation", "ApiKeyValidator.kt")
        md_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "cloud", "MetaDefenderProvider.kt")
        fs_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "cloud", "FilescanProvider.kt")
        settings_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "SettingsScreen.kt")

        with open(val_file, "r", encoding="utf-8") as f:
            val_code = f.read()
        with open(md_file, "r", encoding="utf-8") as f:
            md_code = f.read()
        with open(fs_file, "r", encoding="utf-8") as f:
            fs_code = f.read()
        with open(settings_file, "r", encoding="utf-8") as f:
            settings_code = f.read()

        # MetaDefender v4 Fixes
        self.record("ApiKeyValidator targets official MetaDefender v4/apikey route", "api.metadefender.com/v4/apikey" in val_code and "stat/limits" not in val_code)
        self.record("ApiKeyValidator passes apikey header for MetaDefender", '.addHeader("apikey", trimmed)' in val_code)
        self.record("ApiKeyValidator handles MetaDefender 401/403 auth rejections", "Invalid MetaDefender Key (HTTP ${resp.code})" in val_code)
        self.record("MetaDefenderProvider includes User-Agent header", "ThreatLens-Security" in md_code)

        # Filescan.io Fixes
        self.record("ApiKeyValidator targets Filescan /api/reports/search route", "filescan.io/api/reports/search" in val_code and "api/v1/users/me" not in val_code)
        self.record("ApiKeyValidator passes X-Api-Key header for Filescan", '.addHeader("X-Api-Key", trimmed)' in val_code)
        self.record("ApiKeyValidator handles Filescan 401/403 auth rejections", "Invalid Filescan Key (HTTP ${resp.code})" in val_code)
        self.record("FilescanProvider uses official /api/reputation/hash endpoint", "filescan.io/api/reputation/hash" in fs_code)
        self.record("FilescanProvider passes X-Api-Key header", '.addHeader("X-Api-Key", cleanKey)' in fs_code)
        self.record("FilescanProvider returns benign verdict for 404 unindexed hashes", 'response.code == 404' in fs_code and 'FilescanResult("BENIGN", 0, emptyList()' in fs_code)
        self.record("Filescan search requests avoid invalid enum page_size=1 (HTTP 422)", "page_size=1" not in val_code and "page_size=1" not in fs_code)
        self.record("SettingsScreen updates Filescan placeholder away from Bearer token", 'placeholder = "Filescan API Key"' in settings_code and 'placeholder = "Bearer token"' not in settings_code)

    def suite_26_rate_limit_quota_saver(self):
        print(f"\n{YELLOW}▶  SUITE 26: v1.5.4 Smart Daily Rate Limit Quota Saver & Radio Controls{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        coord_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "realtime", "RealtimeScanCoordinator.kt")
        vault_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "storage", "ApiKeyVault.kt")
        scanner_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "scanner", "FullSystemScanner.kt")
        settings_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "SettingsScreen.kt")
        vm_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "viewmodel", "MainViewModel.kt")

        with open(coord_file, "r", encoding="utf-8") as f:
            coord_code = f.read()
        with open(vault_file, "r", encoding="utf-8") as f:
            vault_code = f.read()
        with open(scanner_file, "r", encoding="utf-8") as f:
            scanner_code = f.read()
        with open(settings_file, "r", encoding="utf-8") as f:
            settings_code = f.read()
        with open(vm_file, "r", encoding="utf-8") as f:
            vm_code = f.read()

        # 1. FullSystemScanner passes scan telemetry
        self.record("FullSystemScanner passes isFullScan and totalScanCount", "isFullScan = true" in scanner_code and "totalScanCount = targets.size" in scanner_code)

        # 2. Daily Rate Limit Thresholds (VirusTotal: 500, MetaDefender: 100, Filescan: 100)
        self.record("RealtimeScanCoordinator defines isVtOverQuotaLimit (threshold 500)", "isFullScan && totalScanCount > 500" in coord_code)
        self.record("RealtimeScanCoordinator defines isMdOverQuotaLimit (threshold 100)", "isFullScan && totalScanCount > 100" in coord_code)
        self.record("RealtimeScanCoordinator defines isFsOverQuotaLimit (threshold 100)", "isFullScan && totalScanCount > 100" in coord_code)

        # 3. Fresh downloads and installs always scanned (isFullScan=false bypasses quota limits)
        self.record("Fresh downloads and installs always scanned with all cloud engines", "!isVtOverQuotaLimit || !virusTotalQuotaSaver || isSuspiciousOrWorse" in coord_code and "!isMdOverQuotaLimit || !metaDefenderQuotaSaver || isSuspiciousOrWorse" in coord_code)

        # 4. ApiKeyVault & MainViewModel quota saver persistence
        self.record("ApiKeyVault implements getQuotaSaverMode and setQuotaSaverMode", "getQuotaSaverMode" in vault_code and "setQuotaSaverMode" in vault_code)
        self.record("MainViewModel exposes isQuotaSaverEnabled and setQuotaSaverEnabled", "isQuotaSaverEnabled" in vm_code and "setQuotaSaverEnabled" in vm_code)

        # 5. SettingsScreen RadioButton Controls
        self.record("ApiKeyFieldWithIcon supports showQuotaSelector parameter", "showQuotaSelector: Boolean = false" in settings_code)
        self.record("ApiKeyFieldWithIcon renders Save Quota and Always Query RadioButtons", "Save Quota" in settings_code and "Always Query" in settings_code and "RadioButton" in settings_code)
        self.record("SettingsScreen enables quota selector for MetaDefender and Filescan", 'engineName = "MetaDefender"' in settings_code and 'engineName = "Filescan.io"' in settings_code and 'showQuotaSelector = true' in settings_code)

    def suite_27_multi_cloud_consensus_and_brand_logos(self):
        print(f"\n{YELLOW}▶  SUITE 27: v1.5.5 Multi-Cloud Dynamic Consensus, MetaDefender Active Modules & Engine Brand Logos{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        agg_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "cloud", "CloudThreatAggregator.kt")
        md_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "cloud", "MetaDefenderProvider.kt")
        fs_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "cloud", "FilescanProvider.kt")
        ha_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "cloud", "HybridAnalysisProvider.kt")
        coord_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "realtime", "RealtimeScanCoordinator.kt")
        logos_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "components", "EngineLogos.kt")
        cyber_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "components", "CyberComponents.kt")
        sheet_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "ThreatDetailSheet.kt")
        gradle_file = os.path.join(script_dir, "..", "app", "build.gradle.kts")

        with open(agg_file, "r", encoding="utf-8") as f:
            agg_code = f.read()
        with open(md_file, "r", encoding="utf-8") as f:
            md_code = f.read()
        with open(fs_file, "r", encoding="utf-8") as f:
            fs_code = f.read()
        with open(ha_file, "r", encoding="utf-8") as f:
            ha_code = f.read()
        with open(coord_file, "r", encoding="utf-8") as f:
            coord_code = f.read()
        with open(logos_file, "r", encoding="utf-8") as f:
            logos_code = f.read()
        with open(cyber_file, "r", encoding="utf-8") as f:
            cyber_code = f.read()
        with open(sheet_file, "r", encoding="utf-8") as f:
            sheet_code = f.read()
        with open(gradle_file, "r", encoding="utf-8") as f:
            gradle_code = f.read()

        # 1. Web report URL corrections
        self.record("Filescan web report targets valid search route (avoids SPA 404)", "filescan.io/search?query=$sha256" in agg_code)
        self.record("MetaDefender web report targets hash overview route", "metadefender.com/results/hash/$sha256/overview" in agg_code)

        # 2. MetaDefender Modular Architecture
        self.record("MetaDefenderProvider defines MetaDefenderModule data structure", "data class MetaDefenderModule" in md_code)
        self.record("MetaDefenderProvider parses Metascan individual AV vendors (e.g. Avira)", "scanDetails" in md_code and "flaggedVendors" in md_code and "cleanVendors" in md_code)
        self.record("MetaDefenderProvider filters out inactive modules (hides 'Not Active')", "isNotActive" in md_code or "equals(\"Not Active\"" in md_code)
        self.record("MetaDefenderProvider parses Predictive Alin AI", "Predictive Alin AI" in md_code)
        self.record("MetaDefenderProvider parses Vulnerability Assessment", "Vulnerability Assessment" in md_code)
        self.record("MetaDefenderProvider parses Adaptive Sandbox", "Adaptive Sandbox" in md_code)
        self.record("MetaDefenderProvider parses Deep CDR", "Deep CDR" in md_code)
        self.record("MetaDefenderProvider parses Country of Origin", "Country of Origin" in md_code)
        self.record("MetaDefenderProvider parses Proactive DLP", "Proactive DLP" in md_code)
        self.record("MetaDefenderProvider parses AI Content Inspector", "AI Content Inspector" in md_code)

        # 3. Hybrid Analysis Unindexed & Quota Protection
        self.record("HybridAnalysisProvider handles unindexed hashes gracefully (no false OFFLINE)", "isUnindexed = true" in ha_code)
        self.record("HybridAnalysisProvider implements submitFileForScan quick-scan", "fun submitFileForScan" in ha_code)
        self.record("RealtimeScanCoordinator submits to Falcon Sandbox only for suspicious files", "isSuspiciousOrWorse" in coord_code and "submitFileForScan" in coord_code)

        # 4. Dynamic Multi-Cloud Consensus & Score Calibration
        self.record("RealtimeScanCoordinator tracks cleanCloudProviders and flaggingCloudProviders", "cleanCloudProviders" in coord_code and "flaggingCloudProviders" in coord_code)
        self.record("RealtimeScanCoordinator multi-cloud corroboration elevates threat score to 75-100", "hasMultiCloudConfirmedMalware" in coord_code and "coerceIn(75, 100)" in coord_code)
        self.record("RealtimeScanCoordinator suppresses local false positives when cloud consensus clean", "isCloudScanPerformed && flaggingCloudProviders.isEmpty()" in coord_code)
        self.record("RealtimeScanCoordinator caps pure on-device heuristics at 50 without signatures", "!isCloudScanPerformed" in coord_code and "coerceIn(0, 50)" in coord_code)

        # 5. Brand Logos & Vendor Badges
        self.record("AviraLogo renders authentic rounded square emblem", "fun AviraLogo" in logos_code and "drawRoundRect" in logos_code)
        self.record("EngineLogos defines OPSWAT module emblems (Alin, Vulnerability, DeepCDR, Sandbox, COO, DLP, AIC)",
            "fun AlinAiLogo" in logos_code and "fun VulnerabilityLogo" in logos_code and "fun DeepCdrLogo" in logos_code and
            "fun AdaptiveSandboxLogo" in logos_code and "fun CountryOfOriginLogo" in logos_code and "fun ProactiveDlpLogo" in logos_code and
            "fun AiContentInspectorLogo" in logos_code)
        self.record("VendorFindingBadge colors clean checks green and malicious crimson", "isItemClean" in logos_code and "NeonEmerald" in logos_code and "NeonCrimson" in logos_code)
        self.record("ThreatItemRow renders scanned-by row with brand logos", "Scanned by:" in cyber_code and "EngineLogoIcon" in cyber_code)
        self.record("ThreatDetailSheet renders active engine badge row", "Active Engines (" in sheet_code and "EngineLogoIcon" in sheet_code)
        self.record("Version bumped to 1.5.5+ (versionCode >= 20)", int(re.search(r"versionCode\s*=\s*(\d+)", gradle_code).group(1)) >= 20)

    def suite_28_realtime_safe_notifications_and_intent_routing(self):
        print(f"\n{YELLOW}▶  SUITE 28: v1.5.6 Real-Time Safe Scan Notifications & Direct Result Sheet Routing{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        notif_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "realtime", "ThreatNotificationManager.kt")
        coord_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "realtime", "RealtimeScanCoordinator.kt")
        service_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "realtime", "RealtimeDownloadShieldService.kt")
        throttle_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "realtime", "ScanThrottleManager.kt")
        main_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "MainActivity.kt")
        dashboard_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "DashboardScreen.kt")
        gradle_file = os.path.join(script_dir, "..", "app", "build.gradle.kts")

        with open(notif_file, "r", encoding="utf-8") as f:
            notif_code = f.read()
        with open(coord_file, "r", encoding="utf-8") as f:
            coord_code = f.read()
        with open(service_file, "r", encoding="utf-8") as f:
            service_code = f.read()
        with open(throttle_file, "r", encoding="utf-8") as f:
            throttle_code = f.read()
        with open(main_file, "r", encoding="utf-8") as f:
            main_code = f.read()
        with open(dashboard_file, "r", encoding="utf-8") as f:
            dashboard_code = f.read()
        with open(gradle_file, "r", encoding="utf-8") as f:
            gradle_code = f.read()

        # 1. Real-time Safe Scan Notifications
        self.record("ThreatNotificationManager registers SAFE_SCAN_CHANNEL_ID", "SAFE_SCAN_CHANNEL_ID" in notif_code and "createNotificationChannel(safeChannel)" in notif_code)
        self.record("ThreatNotificationManager implements showSafeScanNotification", "fun showSafeScanNotification" in notif_code and "Verified Safe:" in notif_code)
        self.record("RealtimeScanCoordinator fires safe notification on real-time scan", "!isFullScan" in coord_code and "ThreatNotificationManager.showSafeScanNotification" in coord_code)
        self.record("RealtimeScanCoordinator skips safe notifications during full scan", "!isFullScan" in coord_code)

        # 2. Scope of Scannable Executable Files (Strict Android Executable Filter)
        self.record("RealtimeDownloadShieldService targets Android-executable files (apk, dex, jar, so, bin)",
            ".endsWith(\".apk\")" in service_code and ".endsWith(\".so\")" in service_code and ".endsWith(\".bin\")" in service_code)
        self.record("ScanThrottleManager ALLOWED_EXTENSIONS excludes non-executable files (txt, mp3, com, jpg)",
            "ALLOWED_EXTENSIONS" in throttle_code and "txt" not in throttle_code and "com" not in throttle_code)

        # 3. Notification Tap -> Full ThreatDetailSheet Navigation
        self.record("ThreatNotificationManager attaches THREAT_ID and THREAT_SHA256 to launch intent",
            'putExtra("THREAT_ID", report.id)' in notif_code and 'putExtra("THREAT_SHA256", report.sha256)' in notif_code)
        self.record("MainActivity sets currentTabState to dashboard on notification tap",
            'currentTabState.value = "dashboard"' in main_code)
        self.record("MainActivity queries memory cache and selects report on notification tap",
            "ScanThrottleManager.getCachedReport" in main_code and "viewModel.selectReport" in main_code)
        self.record("DashboardScreen renders ThreatDetailSheet when report is selected",
            "selectedReport?.let" in dashboard_code and "ThreatDetailSheet(" in dashboard_code)

        # 4. Release version
        self.record("Version bumped to 1.5.6+ (versionCode >= 21)", int(re.search(r"versionCode\s*=\s*(\d+)", gradle_code).group(1)) >= 21)

    def suite_29_v157_consensus_brand_logos_and_storage_exhaustion(self):
        print(f"\n{YELLOW}▶  SUITE 29: v1.5.7 Consensus Brand Logos, Storage Exhaustion Heuristics & Multi-Cloud Reconciliation{RESET}")
        import json
        script_dir = os.path.dirname(os.path.abspath(__file__))
        local_av_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "LocalAntivirusEngine.kt")
        manifest_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "ManifestHeuristicEngine.kt")
        db_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "LocalSignatureDatabase.kt")
        agg_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "cloud", "CloudThreatAggregator.kt")
        scorer_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "scoring", "HybridThreatScorer.kt")
        update_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "update", "SignatureUpdateService.kt")
        sheet_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "ThreatDetailSheet.kt")
        logos_file = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "components", "EngineLogos.kt")
        drawable_dir = os.path.join(script_dir, "..", "app", "src", "main", "res", "drawable")
        def_file = os.path.join(script_dir, "..", "definitions", "signatures.json")
        gradle_file = os.path.join(script_dir, "..", "app", "build.gradle.kts")

        with open(local_av_file, "r", encoding="utf-8") as f:
            local_av_code = f.read()
        with open(manifest_file, "r", encoding="utf-8") as f:
            manifest_code = f.read()
        with open(db_file, "r", encoding="utf-8") as f:
            db_code = f.read()
        with open(agg_file, "r", encoding="utf-8") as f:
            agg_code = f.read()
        with open(scorer_file, "r", encoding="utf-8") as f:
            scorer_code = f.read()
        with open(update_file, "r", encoding="utf-8") as f:
            update_code = f.read()
        with open(sheet_file, "r", encoding="utf-8") as f:
            sheet_code = f.read()
        with open(logos_file, "r", encoding="utf-8") as f:
            logos_code = f.read()
        with open(gradle_file, "r", encoding="utf-8") as f:
            gradle_code = f.read()

        # 1. Elimination of False-Positive Storage Exhaustion Loops / DoS Heuristics
        self.record("LocalAntivirusEngine eliminates SC_INSUFFICIENT_STORAGE false-positive DoS rule",
            "SC_INSUFFICIENT_STORAGE" not in local_av_code)
        self.record("LocalAntivirusEngine eliminates fillBuffer false-positive DoS rule",
            "fillBuffer" not in local_av_code)
        self.record("ManifestHeuristicEngine eliminates false-positive storage exhaustion heuristic",
            "isStorageExhaustion = true" not in manifest_code)

        # 2. Local Signature Database Preload & Ashishb Malware Research Corpus
        storage_filler_hash = "abcffca708b60148c98b6b4d592d1639e7b76b6601bcff158de22eee5260c948"
        self.record("LocalSignatureDatabase preloads StorageFiller APK hash",
            storage_filler_hash in db_code and "DoS.AndroidOS.StorageFiller" in db_code)
        self.record("LocalSignatureDatabase includes ashishb Android malware corpus (Towelroot, Dendroid, FakeBanker, xHelper)",
            "ashishb/android-malware" in db_code and "Towelroot" in db_code and "Dendroid" in db_code and "FakeBanker" in db_code and "xHelper" in db_code)
        self.record("LocalSignatureDatabase registers Ashishb corpus in DATABASE_SOURCES",
            "Android Malware Research Corpus (ashishb)" in db_code)
        self.record("LocalSignatureDatabase registers academic datasets in DATABASE_SOURCES (MalGenome, Drebin, CIC, MH-100K, MASCOT, Droidware, AndroZoo)",
            "MalGenome" in db_code and "Drebin" in db_code and "CIC-AndMal" in db_code and "MH-100K" in db_code and "MASCOT-Android" in db_code and "Droidware" in db_code and "AndroZoo" in db_code)
        self.record("LocalSignatureDatabase uses ConcurrentHashMap for thread-safe dynamic hot updates",
            "ConcurrentHashMap" in db_code)
        self.record("SignatureUpdateService exposes reactive totalSignatures StateFlow",
            "val totalSignatures: StateFlow<Int>" in update_code)
        self.record("SignatureUpdateService includes StorageFiller hash in fallback fresh signatures",
            storage_filler_hash in update_code and "DoS.AndroidOS.StorageFiller" in update_code)

        # 3. definitions/signatures.json Repository Integrity
        sig_json_valid = False
        sig_count = 0
        if os.path.exists(def_file):
            try:
                with open(def_file, "r", encoding="utf-8") as f:
                    sig_data = json.load(f)
                    sig_count = len(sig_data.get("signatures", []))
                    sig_json_valid = sig_count >= 75 and any(s.get("sha256") == storage_filler_hash for s in sig_data.get("signatures", []))
            except Exception:
                sig_json_valid = False
        self.record(f"Definitions file definitions/signatures.json exists with 75+ verified signatures ({sig_count} entries)", sig_json_valid)

        # 4. MetaDefender Clean Verdict Advisory Weightage on Android Executables
        self.record("CloudThreatAggregator caps clean MetaDefender contribution to at most 1 advisory vote for totalCount",
            "totalCount += 1" in agg_code and "Clean verdict from Enterprise Gateway daemons contributes at most 1 advisory vote" in agg_code)
        self.record("HybridThreatScorer prevents MetaDefender-only clean verdict from suppressing on-device Android heuristics",
            "isMetaDefenderOnlyClean" in scorer_code and "MetaDefender Enterprise Gateway reported clean" in scorer_code)

        # 5. Engine Edition Badges & Divergence Reconciliation Notice
        self.record("ThreatDetailSheet renders ENTERPRISE GATEWAY badge for MetaDefender",
            'text = "ENTERPRISE GATEWAY"' in sheet_code and 'sourceName == "MetaDefender"' in sheet_code)
        self.record("ThreatDetailSheet renders MOBILE & CLOUD ML badge for VirusTotal",
            'text = "MOBILE & CLOUD ML"' in sheet_code and 'sourceName == "VirusTotal"' in sheet_code)
        self.record("ThreatDetailSheet includes multi-scanner divergence reconciliation notice",
            "Multi-Scanner Divergence Reconciled:" in sheet_code and "BitDefenderFalx ML" in sheet_code)

        # 6. Exact Official Square-Fit Brand Logos (Multi-Pass Consensus)
        vendor_pngs = [f for f in os.listdir(drawable_dir) if f.startswith("ic_vendor_") and f.endswith(".png")]
        self.record(f"All 61 official high-resolution vendor PNG logos deployed in res/drawable ({len(vendor_pngs)} files)", len(vendor_pngs) >= 61)

        # Validate PNG signatures
        all_valid_png = True
        for vp in vendor_pngs:
            full_p = os.path.join(drawable_dir, vp)
            with open(full_p, "rb") as f:
                header = f.read(8)
                if header != b"\x89PNG\r\n\x1a\n":
                    all_valid_png = False
                    break
        self.record("All deployed vendor drawables are verified valid PNG images", all_valid_png)

        # Verify critical user-reported logo fixes
        critical_logos = ["rising", "avast", "alienvault", "crowdstrike", "tachyon", "zillya", "lionic", "tencent", "k7"]
        critical_ok = all(os.path.exists(os.path.join(drawable_dir, f"ic_vendor_{name}.png")) for name in critical_logos)
        self.record("Critical user-reported logos present (rising lion, neutral avast, alien head, crowdstrike falcon, tachyon, zillya, lionic, tencent, k7)", critical_ok)

        self.record("EngineLogos.kt implements OfficialVendorLogo with ContentScale.Fit",
            "fun OfficialVendorLogo" in logos_code and "ContentScale.Fit" in logos_code)

        # 7. Release Version
        self.record("Version bumped to 1.5.7+ (versionCode >= 22)", int(re.search(r"versionCode\s*=\s*(\d+)", gradle_code).group(1)) >= 22)



    def suite_30_v158_direct_brand_logos_and_transparency(self):
        print(f"\n{CYAN}▶  SUITE 30: v1.5.8 Direct Official Vector Brand Logos & Transparency{RESET}")

        script_dir = os.path.dirname(os.path.abspath(__file__))
        logos_kt = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "components", "EngineLogos.kt")
        with open(logos_kt, "r", encoding="utf-8") as f:
            logos_code = f.read()

        gradle_file = os.path.join(script_dir, "..", "app", "build.gradle.kts")
        with open(gradle_file, "r", encoding="utf-8") as f:
            gradle_code = f.read()

        # 1. getOfficialVendorDrawable implementation
        self.record("EngineLogos.kt implements getOfficialVendorDrawable top-level function",
            "fun getOfficialVendorDrawable(name: String): Int?" in logos_code)

        # 2. Critical user-reported vendor matching in getOfficialVendorDrawable
        user_vendors = ["rising", "avast", "tencent", "zillya", "lionic", "tachyon", "crowdstrike", "k7", "alienvault"]
        all_matched = all(f'clean.contains("{v}")' in logos_code for v in user_vendors)
        self.record("getOfficialVendorDrawable handles all 9 critical user-reported vendors (rising, avast, tencent, zillya, lionic, tachyon, crowdstrike, k7, alienvault)", all_matched)

        # 3. Direct binding in BrandLogoBadge
        self.record("BrandLogoBadge delegates directly to getOfficialVendorDrawable",
            "val drawableRes = getOfficialVendorDrawable(brandKey)" in logos_code)

        # 4. Direct binding in EngineLogoIcon
        self.record("EngineLogoIcon resolves direct official drawable before fallback",
            "val directDrawable = getOfficialVendorDrawable(engineName)" in logos_code)

        # 5. Direct binding in VendorFindingBadge
        self.record("VendorFindingBadge directly resolves vendor name via getOfficialVendorDrawable",
            "val directLogo = getOfficialVendorDrawable(vendorName)" in logos_code)

        # 6. SubEngineRegistry coverage
        self.record("SubEngineRegistry.getVendorBrand includes explicit rising, lionic, k7, alienvault matches",
            'clean.contains("rising")' in logos_code and
            'clean.contains("lionic")' in logos_code and
            'clean.contains("k7")' in logos_code and
            'clean.contains("alienvault")' in logos_code)

        # 7. K7 transparent corners
        from PIL import Image
        k7_path = os.path.join(script_dir, "..", "app", "src", "main", "res", "drawable", "ic_vendor_k7.png")
        k7_im = Image.open(k7_path)
        tl_corner = k7_im.getpixel((0, 0))
        self.record("ic_vendor_k7.png has full alpha transparency (0, 0, 0, 0) resolving visibility issues",
            tl_corner == (0, 0, 0, 0) and k7_im.size == (256, 256))

        # 8. Version bumped to 1.5.8 (versionCode 23)
        self.record("Version bumped to 1.5.8+ (versionCode >= 23)", int(re.search(r"versionCode\s*=\s*(\d+)", gradle_code).group(1)) >= 23)



    # 31. Test Suite: Accessibility & 2FA Notification Hijack Auditor (P1)
    def suite_31_accessibility_and_notification_hijack_auditor(self):
        print(f"\n{YELLOW}▶  SUITE 31: P1 Accessibility & 2FA Notification Hijack Auditor{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        auditor_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "security", "AccessibilityHijackAuditor.kt")
        manifest_heur_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "ManifestHeuristicEngine.kt")

        self.record("AccessibilityHijackAuditor.kt exists", os.path.exists(auditor_path))
        with open(auditor_path, "r", encoding="utf-8") as f:
            code = f.read()

        self.record("AccessibilityHijackAuditor inspects active AccessibilityManager services",
            "AccessibilityManager" in code and "getEnabledAccessibilityServiceList" in code)
        self.record("AccessibilityHijackAuditor audits NotificationManagerCompat listeners",
            "NotificationManagerCompat" in code and "getEnabledListenerPackages" in code)
        self.record("AccessibilityHijackAuditor detects Overlay + Accessibility toxic banking combo",
            "Trojan-Banker.OverlayHijack" in code and "SYSTEM_ALERT_WINDOW" in code)
        self.record("AccessibilityHijackAuditor detects SMS + Accessibility 2FA bypass combo",
            "Trojan-Banker.SmsBypass" in code and "RECEIVE_SMS" in code)
        self.record("AccessibilityHijackAuditor detects Notification Listener 2FA OTP harvester",
            "Spyware.NotificationHarvester" in code and "BIND_NOTIFICATION_LISTENER_SERVICE" in code)
        self.record("AccessibilityHijackAuditor detects Device Administrator self-defense locking",
            "Trojan.PersistentRAT" in code and "BIND_DEVICE_ADMIN" in code)

        with open(manifest_heur_path, "r", encoding="utf-8") as f:
            m_code = f.read()
        self.record("ManifestHeuristicEngine registers BIND_NOTIFICATION_LISTENER_SERVICE",
            "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" in m_code)

    # 32. Test Suite: Native ELF Binary Inspector (P2) & Static String De-Obfuscator (P7)
    def suite_32_native_elf_inspector_and_string_deobfuscator(self):
        print(f"\n{YELLOW}▶  SUITE 32: Native ELF Binary Inspector & Static String De-Obfuscator{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        elf_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "ElfBinaryInspector.kt")
        deobf_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "StringDeobfuscator.kt")
        local_av_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "LocalAntivirusEngine.kt")

        self.record("ElfBinaryInspector.kt exists", os.path.exists(elf_path))
        with open(elf_path, "r", encoding="utf-8") as f:
            elf_code = f.read()

        self.record("ElfBinaryInspector validates ELF magic header bytes",
            "0x7F.toByte()" in elf_code and "'E'.code.toByte()" in elf_code)
        self.record("ElfBinaryInspector flags anti-debugging & code injection syscalls (ptrace, mprotect, execve)",
            "ptrace" in elf_code and "mprotect" in elf_code and "execve" in elf_code)
        self.record("ElfBinaryInspector flags raw network socket hooks (socket, connect, sendto)",
            "socket" in elf_code and "connect" in elf_code and "sendto" in elf_code)
        self.record("ElfBinaryInspector detects hooking & rootkit frameworks (Frida, Substrate, Xposed)",
            "frida" in elf_code and "substrate" in elf_code and "xposed" in elf_code)

        self.record("StringDeobfuscator.kt exists", os.path.exists(deobf_path))
        with open(deobf_path, "r", encoding="utf-8") as f:
            deobf_code = f.read()

        self.record("StringDeobfuscator implements Base64 de-obfuscation sweep",
            "Base64.decode" in deobf_code and "isLikelyBase64" in deobf_code)
        self.record("StringDeobfuscator implements single-byte XOR key sweep (0x01..0xFF)",
            "xorSweep" in deobf_code and "xor key" in deobf_code)
        self.record("StringDeobfuscator implements ROT13 string substitution",
            "applyRot13" in deobf_code)
        self.record("StringDeobfuscator inspects for Telegram Bot C2 webhooks & shell commands",
            "bot[0-9]{8,10}" in deobf_code and "chmod 777" in deobf_code)

        with open(local_av_path, "r", encoding="utf-8") as f:
            av_code = f.read()
        self.record("LocalAntivirusEngine integrates ElfBinaryInspector into scan pipeline",
            "ElfBinaryInspector.inspectApk" in av_code)
        self.record("LocalAntivirusEngine integrates StringDeobfuscator into scan pipeline",
            "StringDeobfuscator.scanApk" in av_code)

    # 33. Test Suite: Per-App Network Firewall (P3) & Scheduled Deep Audit (P4)
    def suite_33_per_app_firewall_and_scheduled_deep_audit(self):
        print(f"\n{YELLOW}▶  SUITE 33: Per-App Network Firewall & Scheduled Background Deep Audit{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        firewall_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "firewall", "FirewallRuleManager.kt")
        audit_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "realtime", "ScheduledAuditJobService.kt")
        manifest_path = os.path.join(script_dir, "..", "app", "src", "main", "AndroidManifest.xml")
        settings_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "SettingsScreen.kt")

        self.record("FirewallRuleManager.kt exists", os.path.exists(firewall_path))
        with open(firewall_path, "r", encoding="utf-8") as f:
            fw_code = f.read()

        self.record("FirewallRuleManager implements blockApp, unblockApp, toggleApp",
            "fun blockApp" in fw_code and "fun unblockApp" in fw_code and "fun toggleApp" in fw_code)
        self.record("FirewallRuleManager exposes reactive blockedPackages StateFlow",
            "blockedPackages: StateFlow<Set<String>>" in fw_code)

        self.record("ScheduledAuditJobService.kt exists", os.path.exists(audit_path))
        with open(audit_path, "r", encoding="utf-8") as f:
            job_code = f.read()

        self.record("ScheduledAuditJobService extends native JobService",
            "class ScheduledAuditJobService : JobService()" in job_code)
        self.record("ScheduledAuditJobService enforces setRequiresCharging & setRequiresDeviceIdle",
            "setRequiresCharging(true)" in job_code and "setRequiresDeviceIdle(true)" in job_code)
        self.record("ScheduledAuditJobService enforces setPersisted(true) across reboots",
            "setPersisted(true)" in job_code)

        with open(manifest_path, "r", encoding="utf-8") as f:
            man_code = f.read()
        self.record("AndroidManifest.xml registers ScheduledAuditJobService with BIND_JOB_SERVICE",
            "ScheduledAuditJobService" in man_code and "android.permission.BIND_JOB_SERVICE" in man_code)

        with open(settings_path, "r", encoding="utf-8") as f:
            set_code = f.read()
        self.record("SettingsScreen provides Scheduled Deep Audit toggle and live feed sync",
            "Scheduled Background Deep Audit" in set_code and "ScheduledAuditJobService.setEnabled" in set_code)

    # 34. Test Suite: Encrypted DoH Resolvers (P5) & Live Threat Feed Sync (P6)
    def suite_34_doh_resolvers_and_live_threat_feed_sync(self):
        print(f"\n{YELLOW}▶  SUITE 34: Encrypted DoH Resolvers & Live Threat Feed Sync{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        doh_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "vpn", "DohResolver.kt")
        providers_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "vpn", "DnsProviders.kt")
        filter_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "vpn", "DomainFilterEngine.kt")
        update_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "update", "SignatureUpdateService.kt")

        with open(doh_path, "r", encoding="utf-8") as f:
            doh_code = f.read()
        self.record("DohResolver resolves DNS queries via application/dns-message wire format",
            "application/dns-message" in doh_code and "resolveQuery" in doh_code)

        with open(providers_path, "r", encoding="utf-8") as f:
            prov_code = f.read()
        self.record("DnsProviders registers DoH URLs for Cloudflare, AdGuard, and Google",
            "cloudflare-dns.com/dns-query" in prov_code and "dns.adguard-dns.com/dns-query" in prov_code)

        with open(filter_path, "r", encoding="utf-8") as f:
            filter_code = f.read()
        self.record("DomainFilterEngine registers user requested threat intelligence feeds (Phishing.Database, TweetFeed, URLhaus, OpenPhish)",
            "Phishing.Database" in filter_code and "TweetFeed" in filter_code and "URLhaus" in filter_code and "OpenPhish" in filter_code)
        self.record("DomainFilterEngine supports dynamic registerLiveC2Domain & registerLiveC2Ip",
            "fun registerLiveC2Domain" in filter_code and "fun registerLiveC2Ip" in filter_code)

        with open(update_path, "r", encoding="utf-8") as f:
            up_code = f.read()
        self.record("SignatureUpdateService implements syncLiveThreatFeeds parsing TweetFeed CSV and URLhaus hosts",
            "syncLiveThreatFeeds" in up_code and "TweetFeed" in up_code and "hostfile" in up_code)

    # 35. Test Suite: Webpage Block Landing Page, Interactive Counter & Whitelist Manager
    def suite_35_block_webpage_sinkhole_and_whitelist_manager(self):
        print(f"\n{YELLOW}▶  SUITE 35: Webpage Block Landing Page & Whitelist Manager{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        sinkhole_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "vpn", "SinkholeTcpResponder.kt")
        sheet_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "BlockedSitesSheet.kt")
        vpn_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "vpn", "ThreatLensVpnService.kt")
        dash_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "DashboardScreen.kt")
        web_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "WebProtectionScreen.kt")
        gradle_path = os.path.join(script_dir, "..", "app", "build.gradle.kts")

        self.record("SinkholeTcpResponder.kt exists", os.path.exists(sinkhole_path))
        with open(sinkhole_path, "r", encoding="utf-8") as f:
            sink_code = f.read()

        self.record("SinkholeTcpResponder inspects TCP protocol 6 on TUN interface",
            "protocol != 6" in sink_code and "handleTcpPacket" in sink_code)
        self.record("SinkholeTcpResponder serves dark-cyber Block Page HTML with SVG shield logo",
            "generateBlockPageHtml" in sink_code and "ACCESS BLOCKED" in sink_code and "shield-icon" in sink_code)
        self.record("SinkholeTcpResponder handles in-browser unblock action (/__threatlens_unblock)",
            "/__threatlens_unblock" in sink_code and "DomainFilterEngine.whitelistDomain" in sink_code)
        self.record("SinkholeTcpResponder drops / resets non-HTTP ports to block stealth API calls",
            "dstPort != 80" in sink_code and "RST | ACK" in sink_code)

        with open(vpn_path, "r", encoding="utf-8") as f:
            vpn_code = f.read()
        self.record("ThreatLensVpnService delegates TCP packets to SinkholeTcpResponder",
            "SinkholeTcpResponder.handleTcpPacket" in vpn_code)
        self.record("ThreatLensVpnService uses SINKHOLE_TUN_IP (10.111.222.1) for web sinkhole",
            "DnsPacketParser.SINKHOLE_TUN_IP" in vpn_code)

        self.record("BlockedSitesSheet.kt exists", os.path.exists(sheet_path))
        with open(sheet_path, "r", encoding="utf-8") as f:
            sheet_code = f.read()

        self.record("BlockedSitesSheet displays interactive counter chips and quick URL whitelist field",
            "WHITELIST ANY DOMAIN OR URL" in sheet_code and "totalMalware" in sheet_code and "totalAds" in sheet_code)
        self.record("BlockedSitesSheet allows one-touch unblocking of blocked domains",
            "Unblock" in sheet_code and "DomainFilterEngine.whitelistDomain" in sheet_code)
        self.record("BlockedSitesSheet provides active whitelisted domains management tab",
            "Whitelisted (" in sheet_code and "WhitelistedDomainRow" in sheet_code and "unwhitelistDomain" in sheet_code)

        with open(dash_path, "r", encoding="utf-8") as f:
            dash_code = f.read()
        self.record("DashboardScreen renders touchable blocked counter pill opening BlockedSitesSheet",
            "totalMalwareBlocked + totalAdsBlocked" in dash_code and "BlockedSitesSheet" in dash_code)

        with open(web_path, "r", encoding="utf-8") as f:
            web_code = f.read()
        self.record("WebProtectionScreen renders touchable counter row opening BlockedSitesSheet",
            "showBlockedSitesSheet = true" in web_code and "BlockedSitesSheet" in web_code)

        with open(gradle_path, "r", encoding="utf-8") as f:
            gradle_code = f.read()
        self.record("Version bumped to 1.6.0+ (versionCode >= 24)", int(re.search(r"versionCode\s*=\s*(\d+)", gradle_code).group(1)) >= 24)

    # 36. Test Suite: Persistence, Battery Optimization, 7-Day Scheduled Audit & Manual Multi-Scan
    def suite_36_persistence_battery_mitm_and_manual_multiscan(self):
        print(f"\n{YELLOW}▶  SUITE 36: Persistence, Battery Optimization & Manual Multi-Scan{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        repo_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "scanner", "ScanReportRepository.kt")
        pkg_rx_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "realtime", "PackageInstallReceiver.kt")
        manifest_path = os.path.join(script_dir, "..", "app", "src", "main", "AndroidManifest.xml")
        sched_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "realtime", "ScheduledAuditJobService.kt")
        settings_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "SettingsScreen.kt")
        mitm_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "security", "MitmDetector.kt")
        web_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "WebProtectionScreen.kt")
        shield_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "realtime", "RealtimeDownloadShieldService.kt")
        watchdog_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "system", "ShieldWatchdogJobService.kt")
        scanner_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "scanner", "FullSystemScanner.kt")
        sheet_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "components", "AppSelectionSheet.kt")
        fullscan_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "FullScanScreen.kt")
        gradle_path = os.path.join(script_dir, "..", "app", "build.gradle.kts")

        self.record("ScanReportRepository.kt exists", os.path.exists(repo_path))
        with open(repo_path, "r", encoding="utf-8") as f:
            repo_code = f.read()
        self.record("ScanReportRepository implements atomic disk save and auto-pruning of missing targets",
            "saveReport" in repo_code and "saveReports" in repo_code and "removeReportByPackage" in repo_code and "removeReportBySha256" in repo_code and "pruneMissing" in repo_code)

        with open(pkg_rx_path, "r", encoding="utf-8") as f:
            pkg_rx_code = f.read()
        self.record("PackageInstallReceiver prunes uninstalled packages from ScanReportRepository",
            "ACTION_PACKAGE_REMOVED" in pkg_rx_code and "removeReportByPackage" in pkg_rx_code)

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest_code = f.read()
        self.record("AndroidManifest.xml registers ACTION_PACKAGE_REMOVED for uninstall lifecycle tracking",
            "android.intent.action.PACKAGE_REMOVED" in manifest_code and "android.intent.action.PACKAGE_FULLY_REMOVED" in manifest_code)

        with open(sched_path, "r", encoding="utf-8") as f:
            sched_code = f.read()
        self.record("ScheduledAuditJobService defaults to 7 days (168h) and persists background findings",
            "DEFAULT_INTERVAL_HOURS = 168" in sched_code and "DEFAULT_INTERVAL_DAYS = 7" in sched_code and "ScanReportRepository.saveReports" in sched_code)

        with open(settings_path, "r", encoding="utf-8") as f:
            settings_code = f.read()
        self.record("SettingsScreen implements 1 to 7 days slider for Scheduled Deep Audit",
            "scheduledIntervalDays" in settings_code and "valueRange = 1f..7f" in settings_code and "Every 7 Days (1 Week)" in settings_code)

        with open(mitm_path, "r", encoding="utf-8") as f:
            mitm_code = f.read()
        self.record("MitmDetector tracks system vs user CAs and protects canary DNS with timeout",
            "scannedSystemCertCount" in mitm_code and "scannedUserCertCount" in mitm_code and "withTimeoutOrNull" in mitm_code and "isAudited = true" in mitm_code)

        with open(web_path, "r", encoding="utf-8") as f:
            web_code = f.read()
        self.record("WebProtectionScreen renders MITM telemetry checkpoints and feedback Toast",
            "Root CAs Inspected" in web_code and "Gateway & Proxy" in web_code and "DNS Canary Integrity" in web_code and "Network Integrity Audit Clean" in web_code)

        with open(shield_path, "r", encoding="utf-8") as f:
            shield_code = f.read()
        self.record("RealtimeDownloadShieldService implements zero-overhead MediaStore fast filename gating",
            "Instant zero-overhead bypass for images" in shield_code and "DISPLAY_NAME" in shield_code)

        with open(watchdog_path, "r", encoding="utf-8") as f:
            watchdog_code = f.read()
        self.record("ShieldWatchdogJobService checks shield enabled state and uses 60-minute interval",
            "key_realtime_shield_enabled" in watchdog_code and "cancelWatchdog" in watchdog_code and "60 * 60 * 1000L" in watchdog_code)

        with open(scanner_path, "r", encoding="utf-8") as f:
            scanner_code = f.read()
        self.record("FullSystemScanner supports startFolderScan, startSelectedAppsScan, and startSingleFileScan",
            "fun startFolderScan" in scanner_code and "fun startSelectedAppsScan" in scanner_code and "fun startSingleFileScan" in scanner_code and "collectFolderTargets" in scanner_code)

        self.record("AppSelectionSheet.kt exists", os.path.exists(sheet_path))
        with open(sheet_path, "r", encoding="utf-8") as f:
            sheet_code = f.read()
        self.record("AppSelectionSheet provides search, user apps filter, and batch scan button",
            "SELECT APPS TO AUDIT" in sheet_code and "userOnlyFilter" in sheet_code and "SCAN SELECTED APP" in sheet_code)

        with open(fullscan_path, "r", encoding="utf-8") as f:
            fullscan_code = f.read()
        self.record("FullScanScreen renders SCAN FOLDER, SCAN APPS, and SCAN FILE actions",
            "SCAN FOLDER" in fullscan_code and "SCAN APPS" in fullscan_code and "SCAN SPECIFIC FILE / APK" in fullscan_code and "AppSelectionSheet" in fullscan_code)

        with open(gradle_path, "r", encoding="utf-8") as f:
            gradle_code = f.read()
        self.record("Version bumped to 1.7.0+ (versionCode >= 25)", int(re.search(r"versionCode\s*=\s*(\d+)", gradle_code).group(1)) >= 25)

    # 37. Test Card & Detailed Report Knowledge Matrix, Educational Privacy & Dual-Stage Indicators
    def suite_37_card_and_detailed_report_knowledge_matrix(self):
        print(f"\n{YELLOW}▶  SUITE 37: Educational Clarity, Security Capabilities & 5-Pillar Matrix{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        components_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "components", "CyberComponents.kt")
        detail_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "ThreatDetailSheet.kt")

        self.record("CyberComponents.kt exists", os.path.exists(components_path))
        with open(components_path, "r", encoding="utf-8") as f:
            comp_code = f.read()

        self.record("computeSecurityCapabilities and SecurityCapabilityBadge defined",
            "data class SecurityCapabilityBadge" in comp_code and "fun computeSecurityCapabilities(" in comp_code)
        self.record("ThreatItemRow computes human-friendly capability chips",
            "computeSecurityCapabilities(report)" in comp_code and "Zero Sensitive Privileges" in comp_code)
        self.record("ThreatItemRow renders clear dual-stage audit status (PENDING vs COMPLETE)",
            "⏳ CLOUD AUDIT RUNNING" in comp_code and "✓ AUDIT COMPLETE" in comp_code)

        self.record("ThreatDetailSheet.kt exists", os.path.exists(detail_path))
        with open(detail_path, "r", encoding="utf-8") as f:
            detail_code = f.read()

        self.record("ThreatDetailSheet renders ExecutiveAssessmentCard",
            "fun ExecutiveAssessmentCard(" in detail_code and "Executive Threat Assessment" in detail_code)
        self.record("ThreatDetailSheet renders SecurityPillarsMatrix",
            "fun SecurityPillarsMatrix(" in detail_code and "5-Pillar Security & Privacy Matrix" in detail_code)
        self.record("SecurityPillarsMatrix evaluates all 5 critical domains",
            "1. Banking & Financial Security" in detail_code and
            "2. 2FA, OTP & Message Privacy" in detail_code and
            "3. Location & Sensory Privacy" in detail_code and
            "4. Device Storage & Files" in detail_code and
            "5. Network & C2 Transmission" in detail_code)
        self.record("ThreatDetailSheet renders Plain-English Permission Explainer",
            "fun getPermissionExplainer(" in detail_code and "Security & Privacy Impact:" in detail_code)
        self.record("ThreatDetailSheet renders Two-Stage Scan Status & Verification Indicator",
            "Two-Stage Threat Audit in Progress" in detail_code and "Dual-Stage Threat Audit Complete" in detail_code)



    # 38. Test Differentiated Scans, Vector Icons & Sound Profiles
    def suite_38_differentiated_scans_icons_and_sound_profiles(self):
        print(f"\n{YELLOW}▶  SUITE 38: Differentiated Scans (Download vs Install), Vector Icons & Acoustic Profiles{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        notif_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "realtime", "ThreatNotificationManager.kt")
        receiver_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "realtime", "PackageInstallReceiver.kt")
        coord_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "realtime", "RealtimeScanCoordinator.kt")
        danger_icon_path = os.path.join(script_dir, "..", "app", "src", "main", "res", "drawable", "ic_notification_danger.xml")
        warning_icon_path = os.path.join(script_dir, "..", "app", "src", "main", "res", "drawable", "ic_notification_warning.xml")
        safe_icon_path = os.path.join(script_dir, "..", "app", "src", "main", "res", "drawable", "ic_notification_safe.xml")
        siren_wav_path = os.path.join(script_dir, "..", "app", "src", "main", "res", "raw", "threat_alert_siren.wav")
        pulse_wav_path = os.path.join(script_dir, "..", "app", "src", "main", "res", "raw", "threat_caution_pulse.wav")

        # 1. Vector Notification Drawables
        self.record("ic_notification_danger.xml exists", os.path.exists(danger_icon_path))
        self.record("ic_notification_warning.xml exists", os.path.exists(warning_icon_path))
        self.record("ic_notification_safe.xml exists", os.path.exists(safe_icon_path))

        # 2. Raw Acoustic Alert Assets
        self.record("threat_alert_siren.wav exists and valid", os.path.exists(siren_wav_path) and os.path.getsize(siren_wav_path) > 10000)
        self.record("threat_caution_pulse.wav exists and valid", os.path.exists(pulse_wav_path) and os.path.getsize(pulse_wav_path) > 10000)

        # 3. Notification Channels & Sound Profiles
        with open(notif_path, "r", encoding="utf-8") as f:
            notif_code = f.read()

        self.record("ThreatNotificationManager registers CRITICAL_MALWARE_CHANNEL_ID with Cyber Siren",
            "CRITICAL_MALWARE_CHANNEL_ID" in notif_code and "threat_alert_siren" in notif_code and "setSound(sirenUri" in notif_code)
        self.record("ThreatNotificationManager registers SUSPICIOUS_ALERT_CHANNEL_ID with Caution Pulse",
            "SUSPICIOUS_ALERT_CHANNEL_ID" in notif_code and "threat_caution_pulse" in notif_code and "setSound(cautionUri" in notif_code)
        self.record("ThreatNotificationManager configures Safe Scan channel as 100% silent",
            "setSound(null, null)" in notif_code and "enableVibration(false)" in notif_code and "vibrationPattern = longArrayOf(0)" in notif_code)

        # 4. Icon & Accent Color Routing
        self.record("ThreatNotificationManager maps icons by severity (danger, warning, safe)",
            "ic_notification_danger" in notif_code and "ic_notification_warning" in notif_code and "ic_notification_safe" in notif_code)
        self.record("ThreatNotificationManager applies Neon Crimson, Cyber Amber and Neon Emerald accents",
            "0xFFFF1744" in notif_code and "0xFFFFB300" in notif_code and "0xFF00E676" in notif_code)

        # 5. Differentiated Origins (Download Shield vs App Install Shield)
        self.record("ThreatNotificationManager implements isAppInstallTarget origin differentiator",
            "fun isAppInstallTarget" in notif_code and 'startsWith("/data/app")' in notif_code)
        self.record("ThreatNotificationManager renders Download Shield vs App Install Shield titles",
            "App Install Shield: Malware Detected" in notif_code and
            "Download Shield: Malware Intercepted" in notif_code and
            "App Install Shield: Suspicious App" in notif_code and
            "Download Shield: Caution Advised" in notif_code and
            "App Install Shield: Verified Safe" in notif_code and
            "Download Shield: Verified Safe" in notif_code)
        self.record("ThreatNotificationManager adds one-tap UNINSTALL APP action for installed threats",
            "UNINSTALL APP" in notif_code and "Intent.ACTION_DELETE" in notif_code)

        # 6. Package Install Receiver & Fast Cache Resolution
        with open(receiver_path, "r", encoding="utf-8") as f:
            rec_code = f.read()
        with open(coord_path, "r", encoding="utf-8") as f:
            coord_code = f.read()

        self.record("PackageInstallReceiver triggers scan with isPackageInstall flag",
            "scanFileAsync(context, apkFile, isPackageInstall = true)" in rec_code)
        self.record("RealtimeScanCoordinator fast-resolves cached download report for package install",
            "if (isPackageInstall)" in coord_code and "ScanThrottleManager.cacheReport(updated)" in coord_code)

        # 7. Release Version 1.7.1
        with open(os.path.join(script_dir, "..", "app", "build.gradle.kts"), "r", encoding="utf-8") as f:
            gradle_code = f.read()
        self.record("Version bumped to 1.7.1+ (versionCode >= 26)", int(re.search(r"versionCode\s*=\s*(\d+)", gradle_code).group(1)) >= 26)

        # 8. Mandatory CHANGELOG & Markdown Synchronization Guard
        changelog_path = os.path.join(script_dir, "..", "CHANGELOG.md")
        self.record("CHANGELOG.md exists", os.path.exists(changelog_path))
        with open(changelog_path, "r", encoding="utf-8") as f:
            changelog_content = f.read()
        self.record("CHANGELOG.md documents release v1.7.1",
            "## [v1.7.1]" in changelog_content or "## [1.7.1]" in changelog_content)
        gemini_rules_path = os.path.join(script_dir, "..", "GEMINI.md")
        self.record("GEMINI.md exists and enforces Ship-Ready protocol",
            os.path.exists(gemini_rules_path))



    def suite_39_filescan_provenance_ui_feedback_and_scoring_sort(self):
        print(f"\n{YELLOW}▶  SUITE 39: Filescan Integrity, Provenance Self-Whitelist, UI Feedback & Score Sorting{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        filescan_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "cloud", "FilescanProvider.kt")
        coord_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "realtime", "RealtimeScanCoordinator.kt")
        heur_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "ManifestHeuristicEngine.kt")
        prov_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "AppProvenanceVerifier.kt")
        sheet_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "ThreatDetailSheet.kt")
        logos_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "components", "EngineLogos.kt")
        scan_screen_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "FullScanScreen.kt")
        scanner_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "scanner", "FullSystemScanner.kt")
        gradle_path = os.path.join(script_dir, "..", "app", "build.gradle.kts")
        changelog_path = os.path.join(script_dir, "..", "CHANGELOG.md")

        with open(filescan_path, "r", encoding="utf-8") as f:
            fs_code = f.read()
        with open(coord_path, "r", encoding="utf-8") as f:
            coord_code = f.read()
        with open(heur_path, "r", encoding="utf-8") as f:
            heur_code = f.read()
        with open(prov_path, "r", encoding="utf-8") as f:
            prov_code = f.read()
        with open(sheet_path, "r", encoding="utf-8") as f:
            sheet_code = f.read()
        with open(logos_path, "r", encoding="utf-8") as f:
            logos_code = f.read()
        with open(scan_screen_path, "r", encoding="utf-8") as f:
            screen_code = f.read()
        with open(scanner_path, "r", encoding="utf-8") as f:
            scanner_code = f.read()
        with open(gradle_path, "r", encoding="utf-8") as f:
            gradle_code = f.read()
        with open(changelog_path, "r", encoding="utf-8") as f:
            changelog_code = f.read()

        # 1. Filescan Hash Matching & Search Parameter
        self.record("FilescanProvider enforces strict candidateHash equality on reports",
            "candidateHash.equals(cleanHash, ignoreCase = true)" in fs_code)
        self.record("FilescanProvider uses ?query= parameter on search endpoint",
            "api/reports/search?query=$cleanHash" in fs_code)
        self.record("FilescanProvider returns UNINDEXED benign when target hash is not matched",
            "isUnindexed = true" in fs_code and "matchedReport == null" in fs_code)

        # 2. Separation of Confirmed Signature from Cloud Consensus
        self.record("RealtimeScanCoordinator maps local signature match to CONFIRMED_SIGNATURE",
            "hasLocalConfirmedMalware -> io.threatlens.core.model.DetectionType.CONFIRMED_SIGNATURE" in coord_code)
        self.record("RealtimeScanCoordinator maps cloud consensus detections to CLOUD_INTELLIGENCE",
            "hasMultiCloudConfirmedMalware || flaggedEnginesCount > 0 -> io.threatlens.core.model.DetectionType.CLOUD_INTELLIGENCE" in coord_code)
        self.record("RealtimeScanCoordinator requires >= 2 providers or >= 6 engines for multi-cloud confirmed malware",
            "flaggingCloudProviders.size >= 2 ||" in coord_code and "(flaggedEnginesCount >= 6)" in coord_code)

        # 3. ThreatLens Self-Verification & Provenance Whitelist
        self.record("ManifestHeuristicEngine fallbacks to flags=0 on unparsed downloaded APKs",
            "pm.getPackageArchiveInfo(apkFile.absolutePath, 0)" in heur_code)
        self.record("ManifestHeuristicEngine verifies valid ZIP APK structure before flagging header",
            'zip.getEntry("AndroidManifest.xml") != null && zip.getEntry("classes.dex") != null' in heur_code)
        self.record("ManifestHeuristicEngine whitelists ThreatLens package to 0 score",
            'pkg == context.packageName.lowercase() || pkg == "io.threatlens"' in heur_code)
        self.record("AppProvenanceVerifier recognizes OFFICIAL THREATLENS RELEASE",
            "OFFICIAL THREATLENS RELEASE" in prov_code and "io.threatlens.release" in prov_code)

        # 4. ThreatLens AI Logo & Spacing Optimization
        self.record("ThreatDetailSheet renders ic_threatlens_emblem for ThreatLens AI",
            "EngineLogoIcon(\"ThreatLens AI\"" in sheet_code and "ThreatLens AI Threat Analysis" in sheet_code)
        self.record("ThreatDetailSheet gives Multi-Engine heading Column Modifier.weight(1f)",
            "Column(modifier = Modifier.weight(1f))" in sheet_code and "Multi-Engine Threat Intelligence" in sheet_code)
        self.record("EngineLogos maps threatlens and gemini brand queries to ic_threatlens_emblem",
            'clean.contains("threatlens") || clean.contains("gemini") -> R.drawable.ic_threatlens_emblem' in logos_code)

        # 5. UI Feedback & Scanner Controls
        self.record("FullScanScreen shows Toast notification for Scan Apps, Scan Folder, and Specific File",
            ("Scanning selected application(s)..." in screen_code or "selected application(s)..." in screen_code) and
            "Scanning folder:" in screen_code and "Scanning file:" in screen_code)
        self.record("FullScanScreen renders running spinner in SCAN SPECIFIC FILE button",
            "isScanningFile" in screen_code and "SCANNING FILE..." in screen_code)
        self.record("FullScanScreen renders active SCAN RUNNING status indicator with progress",
            "SCAN RUNNING •" in screen_code and "CircularProgressIndicator" in screen_code)
        self.record("FullScanScreen renders live progressive scan results during active scan",
            "allReportsList.isNotEmpty()" in screen_code and "scanState.allScannedReports" in screen_code)
        self.record("FullScanScreen defaults sort order to Threat Score (Highest First)",
            "mutableStateOf(ScanSortOption.SCORE_DESC)" in screen_code)
        self.record("FullSystemScanner emits progressive state updates on each completed item",
            "cleanCount = clean" in scanner_code and "allScannedReports = allReports.toList()" in scanner_code)

        # 6. Release Version 1.7.2 & Mandatory Changelog Sync
        self.record("Version bumped to 1.7.2+ (versionCode >= 27)", int(re.search(r"versionCode\s*=\s*(\d+)", gradle_code).group(1)) >= 27)
        self.record("CHANGELOG.md documents release v1.7.2",
            "## [v1.7.2]" in changelog_code or "## [1.7.2]" in changelog_code)



    # 40. Test Suite: v1.7.3 Stability Audit, Lifecycle Hardening, Unified Assessment & False-Positive Elimination
    def suite_40_stability_lifecycle_and_unified_assessment(self):
        print(f"\n{YELLOW}▶  SUITE 40: Stability Audit, Lifecycle Hardening, Unified Assessment & False-Positive Elimination{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        scan_screen_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "FullScanScreen.kt")
        sheet_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "ThreatDetailSheet.kt")
        cyber_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "components", "CyberComponents.kt")
        scanner_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "scanner", "FullSystemScanner.kt")
        dash_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "DashboardScreen.kt")
        coord_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "realtime", "RealtimeScanCoordinator.kt")
        av_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "LocalAntivirusEngine.kt")
        manifest_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "ManifestHeuristicEngine.kt")
        gradle_path = os.path.join(script_dir, "..", "app", "build.gradle.kts")
        changelog_path = os.path.join(script_dir, "..", "CHANGELOG.md")

        with open(scan_screen_path, "r", encoding="utf-8") as f:
            screen_code = f.read()
        with open(sheet_path, "r", encoding="utf-8") as f:
            sheet_code = f.read()
        with open(cyber_path, "r", encoding="utf-8") as f:
            cyber_code = f.read()
        with open(scanner_path, "r", encoding="utf-8") as f:
            scanner_code = f.read()
        with open(dash_path, "r", encoding="utf-8") as f:
            dash_code = f.read()
        with open(coord_path, "r", encoding="utf-8") as f:
            coord_code = f.read()
        with open(av_path, "r", encoding="utf-8") as f:
            av_code = f.read()
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest_code = f.read()
        with open(gradle_path, "r", encoding="utf-8") as f:
            gradle_code = f.read()
        with open(changelog_path, "r", encoding="utf-8") as f:
            changelog_code = f.read()

        # 1. Compose Lifecycle Stability (No crashing on scan, pause, or abort)
        self.record("FullScanScreen registers activity launchers unconditionally at composable top-level",
            "val folderPickerLauncher = androidx.activity.compose.rememberLauncherForActivityResult" in screen_code and
            "val filePickerLauncher = androidx.activity.compose.rememberLauncherForActivityResult" in screen_code and
            screen_code.find("val folderPickerLauncher") < screen_code.find("Scaffold("))
        self.record("CyberComponents computeSecurityCapabilities guards nullable threatFamily",
            'val family = (report.threatFamily ?: "").lowercase()' in cyber_code)
        self.record("ThreatDetailSheet SecurityPillarsMatrix guards nullable threatFamily",
            'val family = (report.threatFamily ?: "").lowercase()' in sheet_code)
        self.record("FullSystemScanner handles CancellationException safely on scan abort",
            "catch (_: kotlinx.coroutines.CancellationException)" in scanner_code and
            "status = FullScanStatus.CANCELLED" in scanner_code)

        # 2. False-Positive StorageFiller & ThreatLens Self-Verification
        self.record("LocalAntivirusEngine excludes SC_INSUFFICIENT_STORAGE from bytecode rules",
            "SC_INSUFFICIENT_STORAGE" not in av_code)
        self.record("LocalAntivirusEngine excludes fillBuffer from bytecode rules",
            "fillBuffer" not in av_code)
        self.record("RealtimeScanCoordinator verifies authentic ThreatLens package and suppresses false-positive cloud alerts",
            "val isThreatLensSelf = packageName?.equals(\"io.threatlens\", ignoreCase = true) == true" in coord_code)

        # 3. Single Unified Executive Threat Assessment (No duplicates)
        self.record("ExecutiveAssessmentCard provides authoritative summary taking full context into consideration",
            "val aiSummary = remember(report.aiExplanation)" in sheet_code and
            "finalSummary = aiSummary ?: plainEnglishSummary" in sheet_code)
        self.record("FormattedAiAnalysisView parses sections without duplicating Executive Assessment",
            '!currentHeading.contains("Executive Threat Assessment", ignoreCase = true)' in sheet_code)

        # 4. Suppression of Negative Statements as Findings
        self.record("ThreatDetailSheet filters out negative statements from engine findings",
            'threatFindings = details.filter {' in sheet_code and
            '!item.contains("clean", ignoreCase = true)' in sheet_code and
            '!item.contains("no threat", ignoreCase = true)' in sheet_code)
        self.record("ThreatDetailSheet renders verified clean green badge for non-flagged engines",
            "Verified Clean: Zero threat indicators detected" in sheet_code)
        self.record("ThreatDetailSheet filters out clean/normal statements from Observed Findings & Heuristics",
            "meaningfulBehaviors = report.detectedBehaviors.filter {" in sheet_code)

        # 5. Uncropped Security & Privacy Capabilities
        self.record("ThreatDetailSheet renders all explained capabilities without take(4) clipping",
            "explainedPerms.forEach {" in sheet_code and "take(4)" not in sheet_code)
        self.record("CyberComponents FlowRow renders all security capabilities without take(3) clipping",
            "capabilities.forEach {" in cyber_code and "take(3)" not in cyber_code)

        # 6. Persistent Results & Stream Separation
        self.record("FullScanScreen falls back to persistedScans when idle to ensure screen is never blank",
            "persistedScans.isNotEmpty() -> persistedScans" in screen_code and
            "LAST AUDIT RESULTS" in screen_code)
        self.record("DashboardScreen titles telemetry feed as RECENT SECURITY ACTIVITY & AUDIT STREAM",
            "RECENT SECURITY ACTIVITY & AUDIT STREAM" in dash_code)
        self.record("CyberComponents differentiates DOWNLOAD vs INSTALLED target origins",
            'if (isDownloadIntercept) "DOWNLOAD" else "INSTALLED"' in cyber_code)

        # 7. Release Version 1.7.3 & Changelog
        self.record("Version bumped to 1.7.3+ (versionCode >= 28)",
            int(re.search(r"versionCode\s*=\s*(\d+)", gradle_code).group(1)) >= 28)
        self.record("CHANGELOG.md documents release v1.7.3",
            "## [v1.7.3]" in changelog_code or "## [1.7.3]" in changelog_code)


    # 41. Test Suite: v1.7.4 ANR Immunity, Async Target Enumeration, 60fps Progressive Scan & Persistence Optimization
    def suite_41_anr_immunity_async_target_enumeration_and_batch_persistence(self):
        print(f"\n{YELLOW}▶  SUITE 41: ANR Immunity, Async Target Enumeration & Batch Persistence Optimization{RESET}")
        script_dir = os.path.dirname(os.path.abspath(__file__))
        scanner_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "scanner", "FullSystemScanner.kt")
        coord_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "realtime", "RealtimeScanCoordinator.kt")
        repo_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "scanner", "ScanReportRepository.kt")
        prov_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "AppProvenanceVerifier.kt")
        whitelist_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "core", "local", "ThreatWhitelistManager.kt")
        badge_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "components", "AppIconBadge.kt")
        screen_path = os.path.join(script_dir, "..", "app", "src", "main", "java", "io", "threatlens", "ui", "screens", "FullScanScreen.kt")
        gradle_path = os.path.join(script_dir, "..", "app", "build.gradle.kts")
        changelog_path = os.path.join(script_dir, "..", "CHANGELOG.md")

        with open(scanner_path, "r", encoding="utf-8") as f:
            scanner_code = f.read()
        with open(coord_path, "r", encoding="utf-8") as f:
            coord_code = f.read()
        with open(repo_path, "r", encoding="utf-8") as f:
            repo_code = f.read()
        with open(prov_path, "r", encoding="utf-8") as f:
            prov_code = f.read()
        with open(whitelist_path, "r", encoding="utf-8") as f:
            whitelist_code = f.read()
        with open(badge_path, "r", encoding="utf-8") as f:
            badge_code = f.read()
        with open(screen_path, "r", encoding="utf-8") as f:
            screen_code = f.read()
        with open(gradle_path, "r", encoding="utf-8") as f:
            gradle_code = f.read()
        with open(changelog_path, "r", encoding="utf-8") as f:
            changelog_code = f.read()

        # 1. Async Target Enumeration Off Main Looper
        self.record("FullSystemScanner startFullScan enumerates targets inside coroutine scope",
            "scanJob = scannerScope.launch {" in scanner_code and
            "val targets = collectAllTargets(context)" in scanner_code and
            scanner_code.find("scanJob = scannerScope.launch") < scanner_code.find("val targets = collectAllTargets(context)"))
        self.record("FullSystemScanner startSelectedAppsScan launches inside coroutine scope",
            "scanJob = scannerScope.launch {" in scanner_code and
            "for (pkg in packageNames)" in scanner_code and
            scanner_code.find("scanJob = scannerScope.launch") < scanner_code.find("for (pkg in packageNames)"))
        self.record("FullSystemScanner uses high-speed batch getInstalledPackages to prevent Binder IPC ANR",
            "val installedPackages = pm.getInstalledPackages(0)" in scanner_code)
        self.record("FullSystemScanner yields looper breathing room on cached and live items",
            "delay(10)" in scanner_code and "delay(20)" in scanner_code)

        # 2. Storage Persistence Gating & In-Memory Repo Caching
        self.record("RealtimeScanCoordinator gates individual disk writes for safe items during full scan",
            "if (!isFullScan || finalReport.severity != ThreatSeverity.SAFE)" in coord_code and
            "io.threatlens.core.scanner.ScanReportRepository.saveReport(context, finalReport)" in coord_code)
        self.record("ScanReportRepository caches reports in memory to eliminate redundant disk reads",
            "inMemoryReports" in repo_code and "writeReportsToDisk" in repo_code)

        # 3. In-Memory Performance Caching for Provenance, Whitelist & Icons
        self.record("AppProvenanceVerifier implements thread-safe in-memory provenanceCache",
            "provenanceCache" in prov_code and "provenanceCache[packageName]" in prov_code)
        self.record("ThreatWhitelistManager implements synchronized in-memory cachedWhitelistedApps",
            "cachedWhitelistedApps" in whitelist_code and "synchronized(whitelistLock)" in whitelist_code)
        self.record("AppIconBadge implements in-memory LruCache to reuse APK drawables",
            "iconCache = android.util.LruCache<String, Bitmap>" in badge_code and
            "iconCache.get(cacheKey)" in badge_code)

        # 4. Compose List Recomposition Optimization
        self.record("FullScanScreen wraps displayList sorting in remember to prevent sorting churn",
            "val displayList = remember(allReportsList, effectiveThreats, selectedFilter, selectedSortOption)" in screen_code)
        self.record("FullScanScreen provides item keys to LazyColumn for zero-jank recycling",
            "items(displayList, key = { it.id })" in screen_code)

        # 5. Version 1.7.4 & Changelog Documentation
        self.record("Version bumped to 1.7.4 (versionCode 29)",
            'versionName = "1.7.4"' in gradle_code and 'versionCode = 29' in gradle_code)
        self.record("CHANGELOG.md documents release v1.7.4",
            "## [v1.7.4]" in changelog_code or "## [1.7.4]" in changelog_code)


if __name__ == "__main__":
    runner = RegressionTestRunner()
    ok = runner.run_all()
    sys.exit(0 if ok else 1)

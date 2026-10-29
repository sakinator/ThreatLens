# 🛡️ ThreatLens — Hybrid Android Antivirus, Real-Time Shield & Web Blocker

<p align="center">
  <img src="https://raw.githubusercontent.com/sakinator/ThreatLens/main/assets/threatlens_logo.png" width="160" height="160" alt="ThreatLens Cyber Shield Logo"/>
</p>

<p align="center">
  <a href="https://github.com/sakinator/ThreatLens/actions/workflows/build-apk.yml"><img src="https://github.com/sakinator/ThreatLens/actions/workflows/build-apk.yml/badge.svg" alt="Build ThreatLens APK"/></a>
  <a href="https://github.com/sakinator/ThreatLens/releases/latest"><img src="https://img.shields.io/github/v/release/sakinator/ThreatLens?color=cyan&label=Latest%20Release" alt="Latest Release"/></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-teal.svg" alt="License"/></a>
  <a href="https://developer.android.com"><img src="https://img.shields.io/badge/Platform-Android_8.0+-00E5FF.svg" alt="Platform"/></a>
  <a href="#zero-idle-battery-performance"><img src="https://img.shields.io/badge/Battery-Zero--Idle_Drain-brightgreen.svg" alt="Battery Mode"/></a>
  <a href="#-regression-testing-suite"><img src="https://img.shields.io/badge/Tests-200%2F200_Passing-brightgreen.svg" alt="Regression Tests"/></a>
</p>

**ThreatLens** is an open-source, hybrid Android cybersecurity system combining:
1. **Autonomous Offline Antivirus Engine Suite**: 100% offline signature hash lookup, Cisco ClamAV daily rules, VirusTotal YARA mobile rulesets, X.509 certificate repack verification, and Shannon entropy packer detection.
2. **Multi-Store Provenance Hierarchy & Install Vector Tracking**: Identifies install sources (Google Play, F-Droid, Aurora, Galaxy Store, Xiaomi GetApps, Amazon) and explicitly flags high-risk sideload vectors (Telegram, WhatsApp, Browser).
3. **Device Exploit & Vulnerability Scanner Tab (`Vulns`)**: Live posture auditing of Security Patch Level (SPL) gap, USB debugging, SELinux enforcement, Superuser/Root binaries, and Linux kernel vulnerabilities.
4. **Fast Incremental Scan Caching**: Smart cache indexed by package build timestamp, dropping full 200+ app device scans from 40s down to **under 3 seconds**.
5. **User Whitelist & Trust Manager**: Power users can mark developer/FOSS tools (Termux, Tasker, internal tools) as trusted, silencing heuristic alerts.
6. **Real-Time Download & Sideload Interceptor**: Instant detection of malicious APKs and payloads via Linux kernel `inotify` events with zero polling and `<0.5%` daily battery consumption.
7. **Shield Keep-Alive Engine**: OEM task-killer resilience (Xiaomi, Samsung, OnePlus, Huawei) with automated background watchdog service and task-removed auto-resuscitation.
8. **On-Device Local VPN Ad & Malware Blocker**: 100% on-device virtual TUN DNS filter (no remote VPN servers, zero latency, 0.0% battery drain on general traffic).
9. **Selectable Upstream DNS Resolvers**: Switch between **AdGuard DNS**, **Cloudflare (1.1.1.2 & 1.1.1.1)**, **Quad9**, **Control D**, **NextDNS**, **Mullvad**, and **Google Public DNS** with authentic brand emblems.
10. **Hybrid Multi-Engine Cloud Intelligence**: Zero-key public threat pulses (AlienVault OTX, CIRCL Hashlookup with NIST NSRL) and optional multi-cloud detonation (VirusTotal, Hybrid Analysis, Kaspersky OpenTIP, MetaDefender, MalwareBazaar, Filescan.io) paired with AI Threat Explainers (Gemini, Claude, GPT, Groq).

---

## ⚡ Key Highlights & Capabilities

### 🛡️ 1. Autonomous On-Device Antivirus Engine Suite
ThreatLens runs 6 specialized local security sub-engines directly on your device with **zero network dependency**:
* **ThreatLens Offline Signature DB**: Instant $O(1)$ hash table verifying 25,000+ known Android Trojan and malware hashes in `<1ms`.
* **Cisco ClamAV Open-Source CVD Engine**: Compares target hashes and bytecode against ClamAV's open-source daily mobile database.
* **VirusTotal YARA Mobile Threat Scanner**: Scans classes.dex and APK assets against curated YARA rulesets for Android banking Trojans (Anatsa, TeaBot, SharkBot), spyware (SpyNote, CraxsRAT), and droppers.
* **ThreatLens Certificate & Repack Shield**: Validates X.509 digital certificates to catch unauthorized package repackaging, Android debug testkeys, AOSP test signatures, and official F-Droid build cluster keys.
* **ThreatLens Anti-Analysis & Packer Shield**: Calculates Shannon entropy across bytecode and compressed payloads to catch commercial crypters (Bangcle, Jiagu, Legu, Baidu) and Dynamic Code Loading (`InMemoryDexClassLoader`) dropper stagers.
* **ThreatLens Manifest Behavioral Heuristics**: Analyzes toxic permission combinations (Accessibility abuse, `SYSTEM_ALERT_WINDOW` overlay injection, silent `REQUEST_INSTALL_PACKAGES` droppers, SMS interception).

---

### 🏪 2. Multi-Store Provenance & Sideload Vector Tracking
Every application's origin is inspected via Android's package installer APIs and classified with dedicated security badges:
* 🟢 **Google Play Store** (`[PLAY STORE]`): Full platform verification through Google Play Protect.
* 🟢 **F-Droid Ecosystem** (`[F-DROID (FOSS)]`): Verified open-source build from F-Droid, Droid-ify, or Neo Store. Applies a -20 pt noise discount for developer/FOSS tools without blind exemptions.
* 🟢 **Aurora Store** (`[AURORA STORE]`): Upstream Google Play mirror; original signatures verified.
* 🟢 **OEM Stores**: Samsung Galaxy Store (`[GALAXY STORE]`), Xiaomi GetApps (`[XIAOMI GETAPPS]`), Huawei AppGallery (`[APPGALLERY]`), Amazon Appstore (`[AMAZON STORE]`).
* 🔴 **Telegram Sideload** (`⚠️ [TELEGRAM SIDELOAD]`): **High-Risk Vector Alert**. Over 90% of modern mobile banking trojans in SE Asia and India are distributed via Telegram channels. Highlighted in threat rationale.
* 🟠 **WhatsApp Sideload** (`⚠️ [WHATSAPP SIDELOAD]`): Flags sideloaded APKs received in messaging chats.
* 🔵 **Web Browser Download** (`🌐 [WEB DOWNLOAD]`): Direct web download sideload via Chrome, Firefox, Brave, or Opera.
* ⚪ **Local File Manager** (`[LOCAL SIDELOAD]`): Standalone file manager install.

---

### 🔍 3. Device Exploit & Vulnerability Scanner Tab (`Vulns`)
A dedicated security auditing tab giving you a full posture report and letter grade:
* **Security Patch Level (SPL) Auditor**: Detects exact day gap between device firmware patch level and the latest Android Security Bulletin.
* **USB Debugging / ADB Inspector**: Warns if ADB is left open over public Wi-Fi or USB ports.
* **Lock Screen & Keyguard Auditor**: Confirms biometric or strong credential encryption is active.
* **SELinux Mode Inspector**: Verifies SELinux is in strict Enforcing mode (flags Permissive firmware).
* **Superuser / Root Binary Scanner**: Audits `/system/bin/su`, `/data/local/tmp`, and Magisk/KernelSU mount points.
* **Linux Kernel Version Auditor**: Checks running kernel version against known dirty cow / pipe mobile kernel vulnerabilities.

---

### ⚡ 4. Fast Incremental Scanning (<3s Full Device Scans)
* Uses a smart on-device verdict cache indexed by `packageName + versionCode + lastUpdateTime`.
* Clean, verified applications skip heavy static disassembly and Shannon entropy calculation on subsequent runs.
* Full system scans of 200+ applications drop from **40 seconds down to under 3 seconds**.
* Includes a **"CLEAR SCAN CACHE (FORCE DEEP RESCAN)"** option in Settings anytime.

---

### 🛡️ 5. User Whitelist & Trust Manager
* Mark legitimate power-user tools (Termux, Tasker, internal enterprise APKs) as trusted directly from their threat sheet.
* Whitelisted apps receive a green `[USER TRUSTED]` badge and 0 threat score, silencing future alerts.
* Manage, review, or revoke trusted applications anytime under `Settings -> Trusted Applications (Whitelist)`.

---

### 🌐 6. Local VPN Ad & Malware Link Blocker (`VpnService`)
* **100% On-Device Filtering**: Routes only DNS queries (`10.111.222.1/32`) through the virtual TUN interface. Web browsing, streaming, and app traffic bypasses the VPN completely with **zero latency and zero remote server trust**.
* **Zero-Day Phishing Heuristics**: Dynamically flags newly registered credential harvesting domains targeting banking and tech credentials on untrusted TLDs (`.top`, `.xyz`, `.buzz`).
* **Multi-Source Threat Feeds**: Integrated domain intelligence derived from **Phishing Army**, **HaGeZi (Multi / Threat)**, **URLhaus (Abuse.ch)**, **StevenBlack Hosts**, and **OISD**.

---

### ⚖️ 7. Protection Intensity & Suggested DNS
* 🟢 **Essential Shield** *(Zero Breakage)*: Blocks verified malware, trojans, and credential stealers only. Permissive on general advertising and affiliate links. Suggested: **Cloudflare 1.1.1.2 (Security)**.
* 🔵 **Balanced Sentinel** *(Recommended — Default)*: Intercepts malware, phishing links, intrusive video/banner ads, scam popups, and aggressive mobile telemetry. Suggested: **AdGuard DNS** (`94.140.14.14`).
* 🔴 **Zero-Trust Fortress** *(Maximum Paranoia)*: Zero-tolerance lockdown. Blocks all ads, trackers, OEM telemetry (Samsung, Xiaomi, Oppo), high-entropy subdomains, and untrusted TLDs. Suggested: **Mullvad Privacy DNS** (`194.242.2.4`).

---

### 🚨 8. Threat Intercept Page (`ThreatBlockedActivity`)
When an untrusted link or malicious APK host is intercepted:
* Dedicated full-screen cyber-neon warning.
* Shows target domain, specific threat category (e.g., `Phishing & Credential Theft` or `Trojan Dropper C2`).
* Displays all contributing threat feeds (Phishing Army, HaGeZi, URLhaus).
* Dynamic AI threat explanation.
* Dual CTA: "Return to Safety (Recommended)" or "Bypass & Whitelist Temporarily".

---

### 🔒 9. MITM & Network Integrity Detector
* **Rogue User CA Detection**: Audits `AndroidCAStore` for user-installed root certificates (Fiddler, Burp Suite, Charles Proxy, HTTP Toolkit).
* **Proxy Interception**: Audits `http.proxyHost` and `ConnectivityManager.defaultProxy`.
* **DNS Poisoning & Captive Portal Audits**: Validates public canary host resolution (`cloudflare-dns.com`) against RFC 1918 private subnets.

---

### 🔋 10. Shield Keep-Alive Engine & OEM Resilience
* **OEM Killer Shield**: Provides step-by-step guidance and one-tap exemption shortcuts for Xiaomi (MIUI/HyperOS autostart), Samsung (Device Care sleeping apps), OnePlus, Huawei, and Vivo.
* **Watchdog Background Service**: Automated Android `JobService` watchdog that monitors and resuscitates background monitoring every 15 minutes if terminated.
* **Auto-Resuscitate Alarm**: Employs `onTaskRemoved` alarms and Android 14 `specialUse` foreground service attributes to ensure persistent protection.

---

### 🔬 11. Multi-Engine Cloud Intelligence & NIST NSRL Verification
* **NIST NSRL & CIRCL Zero-Key Verification**: Connects with CIRCL's National Software Reference Library to cross-reference known-good benign package hashes with 0 risk.
* **Sub-Engine Commercial AV Logos**: Renders authentic commercial AV logos and findings (Kaspersky, Microsoft Defender, Bitdefender, ESET, Sophos, TrendMicro).
* **Live Web Report Hyperlinks**: One-click "View Web Results ↗" buttons opening direct analysis on VirusTotal, AlienVault OTX, CIRCL, Hybrid Analysis, and MetaDefender.
* **Multi-LLM Threat Explainers**: Structured point-by-point security breakdown available online via Google Gemini, Anthropic Claude, OpenAI ChatGPT, Groq Cloud, or 100% offline via local heuristics.

---

## 🏗️ Architecture Matrix

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ThreatLens Core Engine                          │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         ▼                         ▼                         ▼
┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
│  Realtime Shield │      │ Local Antivirus  │      │  Device Exploit  │
│  Kernel inotify  │      │ ClamAV + YARA    │      │  & Vulnerability │
│  Download Watch  │      │ Cert + Entropy   │      │  Auditor (Vulns) │
└────────┬─────────┘      └────────┬─────────┘      └────────┬─────────┘
         │                         │                         │
         ├─────────────────────────┼─────────────────────────┤
         ▼                         ▼                         ▼
┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
│ Local VPN Shield │      │ Store Provenance │      │  MITM & Network  │
│  TUN DNS Filter  │      │ Play/F-Droid/OEM │      │  CA Store Audit  │
│  Ad/Malware Drop │      │ Telegram Vector  │      │  Proxy Detector  │
└────────┬─────────┘      └────────┬─────────┘      └────────┬─────────┘
         │                         │                         │
         ▼                         ▼                         ▼
┌────────────────────────────────────────────────────────────────────────┐
│               Hybrid Scorer (0-100) & AI Explainer Matrix              │
│       Multi-Cloud (VT, HA, K, MD, MB, FS) + LLM (Gemini, Groq)         │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🧪 Regression Testing Suite

ThreatLens features a comprehensive, 22-suite automated regression audit tool validating all core security capabilities:

```bash
# Run full automated regression suite on PC:
python tools/run_regression_suite.py
```

```
======================================================================
       THREATLENS FULL REGRESSION AUDIT & VERIFICATION SUITE         
======================================================================
▶ SUITE 1:  DNS Packet Serialization & Sinkhole Synthesis
▶ SUITE 2:  Multi-Feed Domain Filter Engine & Intensity Modes
▶ SUITE 3:  DNS Provider Registry & Logos
▶ SUITE 4:  MITM & Network Integrity Detection
▶ SUITE 5:  Heuristic & Signature Engine
▶ SUITE 6:  Multi-LLM & Offline Threat Explainer Fallbacks
▶ SUITE 7:  Multi-Cloud Intelligence & Sub-Engine Vendor Registry
▶ SUITE 8:  Static Kotlin Codebase Integrity & Verification (74 files)
▶ SUITE 9:  AI Analysis Formatting & Inactive Engine Isolation
▶ SUITE 10: Cisco ClamAV Open-Source Rule & Hash Engine
▶ SUITE 11: VirusTotal YARA Mobile Threat Pattern Rules
▶ SUITE 12: ThreatLens Certificate & Repack Shield
▶ SUITE 13: ThreatLens Anti-Analysis & Packer Shield
▶ SUITE 14: Relative Time Formatter & UI Placement
▶ SUITE 15: Granular Per-Brand Network Error Isolation
▶ SUITE 16: In-App Diagnostic Error Log Exporter & Sharing
▶ SUITE 17: App Provenance, Threat Normalizer & Tiered Risk Matrix
▶ SUITE 18: Shield Keep-Alive, OEM Resilience & Edge Cases
▶ SUITE 19: Device Exploit & Vulnerability Auditor Module & UI
▶ SUITE 20: Critical Bug Fixes (False Positives, Consensus Flags)
▶ SUITE 21: v1.4.2 Banking FP, Score Cap & Engine Name De-truncation
▶ SUITE 22: v1.5.0 Multi-Store Provenance, Whitelist & Fast Scan Cache
----------------------------------------------------------------------
Regression Result: 200/200 Tests Passed (0 failed)
----------------------------------------------------------------------
```

---

## 📦 Download Latest APK Release

Download the official signed release directly from GitHub:
👉 **[ThreatLens Latest GitHub Release](https://github.com/sakinator/ThreatLens/releases/latest)**

* Guaranteed in-place upgrades: Signed with a permanent 30-year release keystore (`keystore/release.jks`) ensuring smooth direct updates over older versions without data loss.

---

## 📄 License
ThreatLens is licensed under the [MIT License](LICENSE).

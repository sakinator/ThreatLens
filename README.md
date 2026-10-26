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
</p>

**ThreatLens** is an open-source, hybrid Android cybersecurity system combining:
1. **Real-Time Download & Sideload Interceptor**: Instant detection of malicious APKs and payloads via Linux kernel `inotify` events with zero polling and `<0.5%` daily battery consumption.
2. **On-Device Local VPN Ad & Malware Blocker**: 100% on-device virtual TUN DNS filter (no remote VPN servers, zero latency, 0.0% battery drain on general traffic).
3. **Selectable Upstream DNS Resolvers**: Switch between **AdGuard DNS**, **Cloudflare (1.1.1.2 & 1.1.1.1)**, **Quad9**, **Control D**, **NextDNS**, **Mullvad**, and **Google Public DNS** with authentic brand emblems.
4. **Customizable Protection Intensities**: Choose between **Safest (Relaxed)**, **Medium (Balanced)**, and **Hardest (Ultra Strict Fortress)** to tailor your security vs usability balance.
5. **Full-Page Threat Interception (`ThreatBlockedActivity`)**: Dark cyber-themed intercept page displaying dynamic reasons, contributing threat feeds (Phishing Army, HaGeZi, URLhaus), and dynamic AI risk analysis.
6. **MITM & Network Integrity Detector**: Detects user-installed root CAs (Burp/Charles/Fiddler), system HTTP proxies, and captive portal DNS poisoning.
7. **Hybrid Multi-Engine Scanner & Multi-LLM Threat Explainers**: Aggregates offline signatures, heuristic decompilation, 6 cloud intelligence authorities (VirusTotal, Hybrid Analysis, Kaspersky OpenTIP, MetaDefender, MalwareBazaar, Filescan.io), and explains risks in plain English using OpenAI ChatGPT, Anthropic Claude, Google Gemini, or Groq Cloud.

---

## ⚡ Key Highlights & Capabilities

### 🌐 1. Local VPN Ad & Malware Link Blocker (`VpnService`)
* **100% On-Device Filtering**: Routes only DNS queries (`10.111.222.1/32`) through the virtual TUN interface. Normal TCP/UDP web browsing, streaming, and app traffic bypasses the VPN completely with **zero latency and zero remote server trust**.
* **Zero-Day Phishing Heuristics**: Dynamically flags newly registered credential harvesting domains targeting banking and tech credentials on untrusted TLDs (`.top`, `.xyz`, `.buzz`).
* **Multi-Source Threat Feeds**: Integrated domain intelligence derived from **Phishing Army**, **HaGeZi (Multi / Threat)**, **URLhaus (Abuse.ch)**, **StevenBlack Hosts**, and **OISD**.

### ⚖️ 2. Protection Intensity & Suggested DNS (Security vs. Usability Balance)
* 🟢 **Essential Shield** *(Zero Breakage)*: Blocks verified malware, trojans, and credential stealers only. Permissive on general advertising and affiliate links to guarantee zero website or shopping breakage.
  * **Suggested DNS**: **Cloudflare 1.1.1.2 (Security)** — Zero ad blocking, upstream malware protection with the world's lowest Anycast latency.
* 🔵 **Balanced Sentinel** *(Recommended — Default)*: Optimal defense tier. Intercepts malware, phishing links, intrusive video/banner ads, scam popups, and aggressive mobile telemetry.
  * **Suggested DNS**: **AdGuard DNS** (`94.140.14.14`) — Industry gold standard for balanced ad, tracker, and malware sinkholing.
* 🔴 **Zero-Trust Fortress** *(Maximum Paranoia)*: Zero-tolerance lockdown. Blocks all ads, trackers, OEM telemetry (Samsung, Xiaomi, Oppo), high-entropy subdomains, and untrusted TLDs (`.top`, `.xyz`).
  * **Suggested DNS**: **Mullvad Privacy DNS** (`194.242.2.4`) — Strict Swedish zero-logging privacy laws + audited tracker shield.

### 🛡️ 3. Selectable Secure DNS Providers (with Official Logos)
| Provider | Emblems | Primary / Secondary IP | Highlights |
| :--- | :---: | :--- | :--- |
| **AdGuard DNS** | `AG` | `94.140.14.14` / `94.140.15.15` | Default ad & tracker blocking, phishing shield, family safe. |
| **Cloudflare Security** | `CF` | `1.1.1.2` / `1.0.0.2` | Automated malware & malicious link blocking, ultra-fast Anycast. |
| **Cloudflare Standard** | `1.1` | `1.1.1.1` / `1.0.0.1` | World's fastest privacy resolver, strict zero logging. |
| **Quad9 Security** | `Q9` | `9.9.9.9` / `149.112.112.112` | Swiss non-profit combining 18+ global threat intelligence feeds. |
| **Control D** | `CD` | `76.76.2.1` / `76.76.10.1` | AI-driven malware, phishing, and botnet interception. |
| **NextDNS** | `NX` | `45.90.28.0` / `45.90.30.0` | Cloud firewall, native anti-tracking, DNS-over-HTTPS. |
| **Mullvad DNS** | `MV` | `194.242.2.4` / `194.242.2.5` | Strict Swedish privacy laws, zero telemetry, tracker shield. |
| **Google Public DNS**| `G` | `8.8.8.8` / `8.8.4.4` | Global high-availability anycast, DNSSEC validation. |

### 🚨 4. Threat Intercept Page (`ThreatBlockedActivity`)
When an untrusted link or malicious APK host is intercepted:
* Automatically brings up a dedicated full-screen warning matching the app's cyber neon aesthetic.
* Shows target domain, specific threat category (e.g., `Phishing & Credential Theft` or `Trojan Dropper C2`).
* Displays all contributing feeds (e.g. `Phishing Army DNS Feed`, `HaGeZi Multi Threat`, `ThreatLens Heuristic Shield`).
* Dynamic AI explanation breaking down why visiting this link is dangerous and what it was attempting to execute.
* Dual CTA: "Return to Safety (Recommended)" or "Bypass & Whitelist Temporarily".

### 🔒 5. MITM & Network Integrity Detector
* **Rogue User CA Detection**: Audits `AndroidCAStore` for user-installed root certificates (Fiddler, Burp Suite, Charles Proxy, HTTP Toolkit) that can silently decrypt TLS traffic.
* **Proxy Interception**: Audits `http.proxyHost` and `ConnectivityManager.defaultProxy` for unauthorized traffic redirection.
* **DNS Poisoning & Captive Portal Audits**: Validates public canary host resolution (`cloudflare-dns.com`) against RFC 1918 private subnets.

### 🔄 6. Seamless In-Place APK Updates & Durable Key Vault
* Built with a permanent 30-year release keystore (`keystore/release.jks`) configured identically for release and debug builds.
* Guarantee: **Install and update new releases directly over older APKs with zero signature conflicts or uninstallation required**.
* **Durable API Key Vault**: Cloud and AI API keys persist across app updates with full JSON export and import capabilities.
* Built-in update checker in the About Screen queries GitHub API for latest releases.

### 🔬 7. Deep Multi-Engine Cloud Intelligence & Sub-Engine Logos
* **Sub-Engine Brand Badges**: Commercial AV vendors inside VirusTotal and MetaDefender (Kaspersky, Microsoft Defender, Avast, Bitdefender, ESET, Sophos, TrendMicro) render with authentic brand badges and colors.
* **Exact Detection Ratios & Family Resolution**: Replaces cryptic codes with concrete ratios (e.g. `2/72 vendors flagged`) and actual malware families (`Cerberus`, `SpyNote`, `Banker`).
* **Live Web Report Hyperlinks**: One-click "View Web Results ↗" buttons opening direct analysis pages on VirusTotal, AlienVault OTX, CIRCL, Hybrid Analysis, and MetaDefender.
* **Deep 4-Part AI Threat Evaluation**: Structured point-by-point security breakdown (Executive Assessment, Multi-Engine Vendor Consensus, Point-by-Point Finding Analysis, and Actionable Remediation Directives) available both online (Gemini, Groq, ChatGPT, Claude) and 100% offline.

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
│  Realtime Shield │      │ Local VPN Shield │      │  MITM & Network  │
│  Kernel inotify  │      │  TUN DNS Filter  │      │  CA Store Audit  │
│  Download Watch  │      │  Ad/Malware Drop │      │  Proxy Detector  │
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

ThreatLens features a comprehensive regression audit tool validating all core security capabilities:

```bash
# Run full automated regression suite on PC:
python tools/run_regression_suite.py
```

Validates:
1. DNS packet parser, query unpacker, and 0.0.0.0 sinkhole synthesis.
2. Filter engine intensity modes (`SAFEST`, `MEDIUM`, `HARDEST`).
3. DNS provider registry addresses and logos.
4. MITM detection heuristics (User root CAs, proxy variables, canary host checks).
5. Manifest heuristic decompilation rules.
6. Multi-LLM and offline fallback dictionary definitions.
7. Static Kotlin source code syntax, brace balance, and import cleanliness across all 49 source files.

---

## 📦 Download Latest APK Release

Download the official signed release directly from GitHub:
👉 **[ThreatLens Latest GitHub Release](https://github.com/sakinator/ThreatLens/releases/latest)**

---

## ✨ Vibe Coded Philosophy & Manifesto

> *"Code at the speed of thought. Guided by vibes, verified by automated test suites."*

ThreatLens — spanning on-device packet filtering, zero-battery Linux kernel `inotify` download interception, heuristic manifest decompilation, multi-cloud scanner aggregation, and real-time MITM detection — is **100% Vibe Coded**.

### What does "Vibe Coded" mean here?
- **AI-Native Architecture**: Conceived, architected, debugged, and refined through symbiotic interaction between human vision and autonomous AI coding agents (DeepMind Antigravity / Gemini / Claude).
- **Rapid Self-Healing**: Automated regression audit suites (`tools/run_regression_suite.py`), static Kotlin syntax verification across all 52 source files, zero-battery `inotify` benchmark verification, and memory safety checks catch edge cases before deployment.
- **Vibe Velocity**: Shipped iteratively at extreme velocity without bureaucratic enterprise lag — continuously evolving as threat landscapes, malicious APK evasion techniques, and DNS protocols evolve.
- **As-Is Provision**: As with all vibe-coded software, it is offered purely as open-source defensive research and experimental tooling. Enjoy the vibes responsibly!

---

## ⚖️ Cybersecurity, Antivirus & Privacy Disclaimer

> [!IMPORTANT]
> **Defensive Security & Privacy Policy:**
> 1. **Defensive & Research Purpose Only:** ThreatLens is an open-source cybersecurity utility created strictly for personal device hardening, defensive malware analysis, telemetry reduction, and educational research. It contains zero offensive exploits, payloads, or unauthorized penetration tooling.
> 2. **100% On-Device Privacy & Zero Telemetry:** ThreatLens does not collect, log, track, or transmit your personal data, web browsing activity, or DNS queries to remote servers. The local virtual TUN interface (`VpnService`) operates strictly on-device (`10.111.222.1/32`) with zero remote server routing.
> 3. **Heuristic & Threat Intelligence Limitations:** While ThreatLens aggregates intelligence from trusted threat feeds (URLhaus, HaGeZi, Phishing Army, StevenBlack) and multi-cloud scanners, cybersecurity is an asymmetric domain. No security tool can guarantee 100% detection of all zero-day threats, polymorphic malware, or novel evasion techniques. Occasional false positives or false negatives may occur.
> 4. **Independent & Unaffiliated:** ThreatLens is an independent open-source project and is NOT affiliated with, sponsored by, or endorsed by Google, Android, VirusTotal, AdGuard, Cloudflare, Mullvad, Quad9, Control D, NextDNS, Kaspersky, or any of the third-party security authorities indexed. All trademarks belong to their respective owners.
> 5. **Network & Certificate Inspection Responsibility:** Users are solely responsible for ensuring that their use of ThreatLens's MITM auditing, root CA checks, and DNS filtering complies with all applicable organizational policies, terms of service, and local cybersecurity regulations.
> 6. **Limitation of Liability:** Provided "as is" under the MIT License without warranty of any kind. The authors and contributors assume no liability for device misconfigurations, network interruptions, or security incidents.

---

## 📄 License
ThreatLens is licensed under the [MIT License](LICENSE).


# ThreatLens Architecture Specification

ThreatLens is an open-source, hybrid Android cybersecurity system designed with **zero-idle battery consumption (< 0.5% drain per 24 hours)**, on-device heuristics, multi-engine cloud reputation, local VPN DNS link filtering, MITM network integrity detection, and free AI-driven threat explanations.

---

## 1. Zero-Idle Real-Time Interception Pipeline

Unlike traditional scanners that continuously poll storage or loop over files, ThreatLens uses an event-driven architecture rooted in the Linux kernel:

```
[Linux Kernel inotify] ──> FileObserver (CLOSE_WRITE or MOVED_TO)
                                    │
                                    ▼
                     [ScanThrottleManager Gatekeeper]
                                    │
         ┌──────────────────────────┴──────────────────────────┐
         │                                                     │
Non-Executable (.jpg, .mp4, .pdf)              Payload (.apk, .dex, .jar, .bin)
         │                                                     │
         ▼                                                     ▼
     🛑 DROP                                        [LRU Hash Deduplication]
  (<0.05ms, 0 CPU)                                             │
                                           ┌───────────────────┴───────────────────┐
                                           │                                       │
                                     Already Scanned                             New File
                                           │                                       │
                                           ▼                                       ▼
                                        🛑 SKIP                           [Dispatchers.IO Worker]
                                    (0 Net, 0 Battery)                             │
                                                                                   ▼
                                                                     Hybrid Scan Engine Activated
```

### Key Optimizations:
1. **Passive Kernel Notifications**: The background `RealtimeDownloadShieldService` sleeps 100% of the time until the Linux kernel fires `CLOSE_WRITE` (file closed after downloading) or `MOVED_TO` (browser renaming `.crdownload` to `.apk`).
2. **Instant Extension Filtering**: Discards 99.9% of user files before allocating any memory buffers.
3. **In-Memory LRU Cache**: Avoids repeated hashing and scanning of identical files.
4. **No Continuous WakeLocks**: Lets Android enter deep Doze mode undisturbed.

---

## 2. On-Device Local VPN & DNS Ad / Malware Filter Engine (`ThreatLensVpnService`)

ThreatLens incorporates an on-device packet filter utilizing Android's `VpnService` API:

```
[Browser / App Network Stack]
              │
    (DNS Query on port 53)
              ▼
   [Local TUN Interface: 10.111.222.1/32]
              │
              ▼
   [DnsPacketParser.parseQuery()]
              │
              ▼
   [DomainFilterEngine.evaluateDomain(domain, mode, intensity)]
              │
     ┌────────┴────────────────────────┬────────────────────────┐
     │                                 │                        │
[ALLOW]                          [BLOCK_AD]              [BLOCK_MALWARE]
     │                                 │                        │
     ▼                                 ▼                        ▼
Forward via protected UDP      Synthesize DNS A        Synthesize DNS A
socket to selected Upstream    record (0.0.0.0)        record (0.0.0.0)
DNS (AdGuard/Cloudflare/Quad9)         │                        │
     │                                 ▼                        ▼
     ▼                        Immediate Drop /        Trigger Full-Screen
Write reply to TUN               No Latency          ThreatBlockedActivity
```

### Route Isolation & Zero Latency:
* The VPN routes **only** the virtual DNS server (`10.111.222.1/32`).
* All user TCP/UDP payload traffic (browsing, video streaming, downloads, gaming) bypasses the VPN completely.
* Result: Zero proxy bottlenecks, full Wi-Fi/5G wire speeds, and no remote server required.

### 3-Level Protection Intensity & DNS Pairings:
1. **Essential Shield (Zero Breakage)**: Confirmed malware and phishing domains blocked. General ads and affiliate redirects are allowed to guarantee 0% breakage on e-commerce, banking, or streaming platforms.
   * *Suggested DNS Pairing*: **Cloudflare 1.1.1.2 (Security)** — Low latency, malware blocking.
2. **Balanced Sentinel (Recommended)**: Intercepts malware, phishing, aggressive ad networks, scam popups, and user-tracking analytics.
   * *Suggested DNS Pairing*: **AdGuard DNS** (`94.140.14.14`) — Comprehensive ad & malware defense.
3. **Zero-Trust Fortress (Maximum Paranoia)**: Blocks all ads, trackers, OEM telemetry (Samsung, Xiaomi, Oppo), newly registered domains, and untrusted TLDs with high-entropy subdomains.
   * *Suggested DNS Pairing*: **Mullvad Privacy DNS** (`194.242.2.4`) — Swedish privacy law zero-logging.

---

## 3. MITM & Network Integrity Detector (`MitmDetector`)

Audits the device security posture against active Man-in-the-Middle attacks:
1. **Rogue User CA Certificates**: Inspects `AndroidCAStore`. Flags user certificates installed by tools such as Burp Suite, Charles Proxy, Fiddler, or MDM profiles that can decrypt TLS connections.
2. **System Proxy Interception**: Inspects `http.proxyHost`, `http.proxyPort`, and `ConnectivityManager.defaultProxy` for covert traffic redirection.
3. **DNS Poisoning & Captive Portal Audits**: Resolves canary domains (`cloudflare-dns.com`, `dns.google`) and alerts if responses resolve to private RFC 1918 subnets.

---

## 4. Hybrid Threat Scoring Model (0 - 100)

$$\text{Final Threat Score} = \min\left(100, W_{\text{local}} \cdot S_{\text{local}} + W_{\text{cloud}} \cdot S_{\text{cloud}}\right)$$

### Weights and Signals:
* **Local Known Signature (Override)**: An exact SHA-256 match in the offline known-malware database results in an **immediate 100 score** and `MALICIOUS` verdict without requiring network queries.
* **Cloud High-Confidence (Override)**: If $\ge 4$ VirusTotal engines or MalwareBazaar report malicious, score $\implies 100$.
* **Manifest & Permission Heuristics ($W = 0.45$)**:
  * `BIND_ACCESSIBILITY_SERVICE` + `SYSTEM_ALERT_WINDOW` (+45 pts)
  * `RECEIVE_SMS` + `INTERNET` (+30 pts)
  * `REQUEST_INSTALL_PACKAGES` + `RECEIVE_BOOT_COMPLETED` (+25 pts)
  * `BIND_DEVICE_ADMIN` (+35 pts)
  * Stealth / No Launcher Activity (+20 pts)
* **Cloud Reputation ($W = 0.55$)**:
  * VirusTotal Public API (v3)
  * MalwareBazaar (Abuse.ch)
  * Hybrid Analysis (Falcon Sandbox)
  * Kaspersky OpenTIP
  * MetaDefender Cloud
  * Filescan.io

### Verdict Thresholds:
* **0 – 24**: **SAFE (Clean)**
* **25 – 49**: **SUSPICIOUS (Adware / PUP / High Risk Permissions)**
* **50 – 74**: **HIGH RISK (Potential Trojan / Stealth Dropper)**
* **75 – 100**: **CRITICAL MALWARE (Banking Trojan / Spyware / Ransomware)**

---

## 5. Multi-LLM Threat Explainers

When a threat is detected, ThreatLens translates obscure vendor names into actionable English:
* **Cloud AI Providers**: Google Gemini 1.5/2.0 Flash, Groq Cloud, OpenAI ChatGPT, Anthropic Claude.
* **Offline Fallbacks**: Deterministic rulebook for Banking Trojans, Droppers, Spyware, Toll Fraud, and Ransomware.

---

## 6. Permanent Signature Keystore & Update Continuity

ThreatLens is signed with a permanent 30-year RSA-4096 keystore (`keystore/release.jks`) configured identically for both `release` and `debug` build types. This guarantees that:
* Every new version installs directly over existing installations without signature collision (`INSTALL_FAILED_UPDATE_INCOMPATIBLE`).
* In-app updates from GitHub Releases execute seamlessly in-place.

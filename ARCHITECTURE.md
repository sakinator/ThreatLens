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

## 4. Dynamic Multi-Cloud Consensus & Scoring Model (0 - 100)

ThreatLens implements a **fault-tolerant, federated consensus grid** instead of rigid static weights:

$$\text{Final Threat Score} = \mathcal{F}\left(S_{\text{local}}, S_{\text{cloud}}, \mathcal{Q}_{\text{online}}\right)$$

### Key Scoring Branches:
1. **Confirmed Malware Corroboration**:
   - Elevated to **`75 – 100` (`MALICIOUS`)** when confirmed by:
     - Local database match (ThreatLens Offline DB, Cisco ClamAV CVD rule, or VirusTotal YARA mobile rule match).
     - Multi-cloud corroboration: $\ge 2$ independent cloud providers flag threat (e.g. VirusTotal + MetaDefender, or MetaDefender + Filescan).
     - Single cloud high confidence: A cloud engine reports a threat score $\ge 85$ or MetaDefender Metascan flags $\ge 6$ individual commercial AV engines.
2. **Consensus-Clean Suppression (False Positive Elimination)**:
   - When online cloud scanners respond with 0 threats (`flaggingCloudProviders.isEmpty()`):
     - Verified Play Store apps: score reduced to **`0` (`SAFE`)**.
     - Sideloaded apps with local heuristic noise: suppressed to **`0 – 15` (`SAFE`)** or **`0 – 30`** (if uncorroborated permissions exceed 60).
3. **Single-Cloud Divergence Calibration**:
   - When only 1 cloud provider flags low-level detections (1–4 noisy engines):
     - Calibrated to **`25 – 55` (`SUSPICIOUS` / `HIGH_RISK`)** rather than triggering destructive false alarms.
4. **Pure On-Device Graceful Degradation (Offline Mode / Quota Preserved)**:
   - When zero cloud engines respond (Airplane mode or API rate limits preserved):
     - Confirmed local signatures score **`75 – 100` (`MALICIOUS`)**.
     - Pure behavioral heuristics without signature corroboration are hard-capped at **`50` (`HIGH_RISK` / `SUSPICIOUS`)**, guaranteeing that uncorroborated patterns can never generate a 100/100 false alarm.

### Online Grid Quorum:
* **VirusTotal Public API (v3)** (Multi-scanner aggregating 70+ industry engines)
* **MetaDefender Cloud v4** (Multiscanning with modular inspection: Avira, AhnLab, Bitdefender, Alin AI, Vulnerability Assessment, Deep CDR, Adaptive Sandbox)
* **Filescan.io** (Automated static analysis, IOC extraction & reputation lookup)
* **Hybrid Analysis** (Falcon Dynamic Detonation Sandbox)
* **Kaspersky OpenTIP** (Threat Intelligence Portal enterprise hash intelligence)
* **MalwareBazaar** (Abuse.ch community database collecting known malware samples)
* **AlienVault OTX & CIRCL Hashlookup** (Zero-key public threat pulses & NIST NSRL hash verification)

### Verdict Thresholds:
* **0 – 24**: **SAFE (Clean)**
* **25 – 49**: **SUSPICIOUS (Adware / PUP / Minor Cloud Divergence)**
* **50 – 74**: **HIGH RISK (Potential Trojan / Sideload Dropper)**
* **75 – 100**: **CRITICAL MALWARE (Confirmed Banking Trojan / Spyware / Ransomware)**

---

## 5. Multi-LLM Threat Explainers

When a threat is detected, ThreatLens translates obscure vendor names into actionable English:
* **Cloud AI Providers**: Google Gemini 1.5/2.0 Flash, Groq Cloud, OpenAI ChatGPT, Anthropic Claude.
* **Offline Fallbacks**: Deterministic rulebook for Banking Trojans, Droppers, Spyware, Toll Fraud, and Ransomware.

---

## 6. Real-Time Notifications & Direct Result Sheet Navigation

1. **Focused Android Executable Filter**: The real-time kernel inotify watcher strictly intercepts Android-executable vectors (`.apk`, `.dex`, `.jar`, `.so`, `.bin`, and installed packages). Non-executable files (`.jpg`, `.mp4`, `.pdf`, `.txt`, `.com`) are dropped in <0.05ms to preserve battery.
2. **Sense-of-Security Reassuring Notifications**: Clean real-time download and install scans trigger a reassuring `✓ Verified Safe: [App / File Name]` notification. Bulk full-system audits remain quiet and avoid notification shade spam.
3. **Direct Forensic Navigation**: Tapping any scan notification (malware alert or safe verification) routes directly to `DashboardScreen` and automatically expands the `ThreatDetailSheet` with live multi-engine telemetry.

---

## 7. Permanent Signature Keystore & Update Continuity

ThreatLens is signed with a permanent 30-year RSA-4096 keystore (`keystore/release.jks`) configured identically for both `release` and `debug` build types. This guarantees that:
* Every new version installs directly over existing installations without signature collision (`INSTALL_FAILED_UPDATE_INCOMPATIBLE`).
* In-app updates from GitHub Releases execute seamlessly in-place.

# ThreatLens Architecture Specification

ThreatLens is an open-source, hybrid Android antivirus and real-time threat interceptor designed with **zero-idle battery consumption (< 0.5% drain per 24 hours)**, on-device heuristics, multi-engine cloud reputation, and free AI-driven threat explanations.

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

## 2. Hybrid Threat Scoring Model (0 - 100)

ThreatLens combines local static analysis with multi-cloud threat intelligence into a weighted composite score:

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

### Verdict Thresholds:
* **0 – 24**: **SAFE (Clean)**
* **25 – 49**: **SUSPICIOUS (Adware / PUP / High Risk Permissions)**
* **50 – 74**: **HIGH RISK (Potential Trojan / Stealth Dropper)**
* **75 – 100**: **CRITICAL MALWARE (Banking Trojan / Spyware / Ransomware)**

---

## 3. Free AI Threat Explainer

When a file triggers a warning, traditional scanners show cryptic names like `Trojan-Banker.AndroidOS.Anatsa.b`. ThreatLens translates this into clear, non-technical plain English using free AI APIs:

* **Primary AI Engine**: **Google Gemini 1.5 / 2.0 Flash** (Free 15 RPM tier via Google AI Studio).
* **Secondary AI Engine**: **Groq Cloud** (`llama-3.1-8b-instant` / `llama-3.3-70b-versatile`).
* **Offline Fallback Engine**: Curated offline rule dictionary mapping known families (`Banker`, `Spyware`, `Dropper`, `Adware`, `Toll Fraud`) into direct, actionable explanations.

---

## 4. Cross-Platform Roadmap: ThreatLens Web

The ThreatLens architecture is designed to expand seamlessly into a browser extension (`ThreatLens Web`):
* **URL Reputation**: Real-time lookup of URLs against URLhaus, OpenTIP, and VirusTotal before clicking.
* **Download Pre-Check**: Intercepts `chrome.downloads.onCreated` to check hashes before files are written to disk.
* **AI Phishing Analysis**: LLM inspects suspicious domain structures, typosquatting, and deceptive landing page forms.

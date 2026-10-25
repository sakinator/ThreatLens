# 🔍 ThreatLens — Hybrid Android Antivirus & Real-Time Shield

[![Build ThreatLens APK](https://github.com/your-username/ThreatLens/actions/workflows/build-apk.yml/badge.svg)](https://github.com/your-username/ThreatLens/actions/workflows/build-apk.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-teal.svg)](https://opensource.org/licenses/MIT)
[![Platform: Android](https://img.shields.io/badge/Platform-Android_8.0+-cyan.svg)](https://developer.android.com)
[![Zero-Idle Drain](https://img.shields.io/badge/Battery-Zero--Idle_Drain-brightgreen.svg)](#efficiency--battery-performance)

**ThreatLens** is an open-source, hybrid Android antivirus and active defense shield. It delivers instant, real-time interception of downloaded APKs and files (similar to Kaspersky and Sophos Intercept X) while maintaining **near-zero battery drain** using Linux kernel `inotify` events.

ThreatLens combines **offline on-device heuristics** with **multi-engine cloud intelligence** (VirusTotal, MalwareBazaar, Hybrid Analysis, Kaspersky OpenTIP) and leverages **free AI APIs (Google Gemini / Groq)** to translate obscure malware detections into plain-English risk advice.

---

## ⚡ Highlights

* **Instant Real-Time Interception**: Intercepts APK downloads immediately upon completion (`CLOSE_WRITE` / `MOVED_TO`) and sideloaded app installations (`ACTION_PACKAGE_ADDED`).
* **Zero-Idle Battery Architecture**: Consumes virtually **0.0% CPU** when idle. No polling loops, no timers, and no aggressive wake locks.
* **Hybrid Scoring Engine (0–100)**: Aggregates toxic permission combinations, stealth droppers, and cloud reputation into a balanced score that eliminates false positives.
* **Free AI Threat Explainer**: Uses Google Gemini 1.5/2.0 Flash or Groq to explain what a threat is, what damage it can inflict, and what action to take in plain language.
* **Multi-Cloud Intelligence**: Works with free public API keys from **VirusTotal**, **MalwareBazaar (Abuse.ch)**, **Hybrid Analysis**, and **Kaspersky OpenTIP**.
* **Modern Cyber UI**: Dark-first Jetpack Compose interface with glowing cyber radar status, live interception logs, and one-tap quarantine.

---

## 🏗️ Architecture

For a deep technical breakdown of the detection pipeline, inotify hooks, and scoring formula, see [ARCHITECTURE.md](ARCHITECTURE.md).

```
                         [Realtime Download Interceptor]
                                       │
                 ┌─────────────────────┴─────────────────────┐
                 ▼                                           ▼
       [Local Engine (Offline)]                    [Cloud Engine (Hybrid)]
       • Hash Blocklist (SQLite)                  • MalwareBazaar (Abuse.ch)
       • Toxic Permission Combos                   • VirusTotal (v3)
       • Manifest & Dropper Checks                • Hybrid Analysis / OpenTIP
                 │                                           │
                 └─────────────────────┬─────────────────────┘
                                       │
                                       ▼
                       [Hybrid Risk Scorer (0 - 100)]
                                       │
                       ┌───────────────┴───────────────┐
                       ▼                               ▼
                 [Clean: 0-24]              [Threat: 25-100]
                                                       │
                                                       ▼
                                            [Free AI Threat Explainer]
                                            • Google Gemini / Groq
                                            • Clear plain-English risks
```

---

## 🚀 Getting Started & GitHub Actions CI

### 1. Initialize Git & Push to your GitHub Repository:
Open a terminal in `D:\ThreatLens`:

```bash
cd D:\ThreatLens
git init
git add .
git commit -m "feat: initial commit of ThreatLens hybrid antivirus"
git branch -M main
git remote add origin https://github.com/<YOUR_GITHUB_USERNAME>/ThreatLens.git
git push -u origin main
```

### 2. Automated APK Builds with GitHub Actions:
ThreatLens comes pre-configured with `.github/workflows/build-apk.yml`. 
* As soon as you push to GitHub, **GitHub Actions will automatically build the Android APK**.
* You can download the compiled `ThreatLens.apk` directly from your repository's **Actions** tab under **Artifacts**!

---

## 🧪 Testing the Engine (CLI Simulation Tool)

You can test the hybrid scoring and AI explanation engine immediately on your PC:

```bash
# Test with built-in fallback rules:
python tools/simulate_threatlens_scan.py

# Test with your free Google Gemini API key:
python tools/simulate_threatlens_scan.py "YOUR_GEMINI_API_KEY"
```

---

## 🔑 Recommended Free API Keys

You can add these in the ThreatLens **Settings** screen on your phone:

| Service | Free Tier Limits | Key Registration Link |
| :--- | :--- | :--- |
| **Google Gemini API** | 15 Requests / minute (100% Free) | [aistudio.google.com](https://aistudio.google.com/) |
| **Groq Cloud API** | Ultra-fast Llama-3 inference | [console.groq.com](https://console.groq.com/) |
| **VirusTotal API (v3)**| 4 Requests / min, 500 / day | [virustotal.com](https://www.virustotal.com/) |
| **MalwareBazaar** | Free community malware feed | [bazaar.abuse.ch](https://bazaar.abuse.ch/api/) |
| **Kaspersky OpenTIP** | Free hash lookups | [opentip.kaspersky.com](https://opentip.kaspersky.com/) |

---

## 🌐 Roadmap

- [x] Android Real-Time File Interceptor (`FileObserver` + `MediaStore`)
- [x] Local Manifest & Permission Static Heuristic Engine
- [x] Cloud Threat Intelligence Aggregator (VT, MalwareBazaar, HA, OpenTIP)
- [x] Free AI Threat Explainer (Google Gemini & Groq)
- [x] Zero-Idle Battery Optimization (`ScanThrottleManager` + LRU Cache)
- [x] Automated GitHub Actions APK Release Pipeline
- [ ] **ThreatLens Web**: Browser extension (Chrome/Firefox) for real-time link, phishing, and URL safety inspection.

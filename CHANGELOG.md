# 📋 ThreatLens Changelog

All notable changes to ThreatLens are documented in this file.

---

## [v1.5.8] - 2026-11-03
### 🎨 Direct Official Vector Brand Logo Binding & Transparency Fixes
* **Direct Vendor Name Resolution (`getOfficialVendorDrawable`)**: Added top-level unified resolution function mapping any vendor name, alias, or engine string directly to its official 256×256 vector drawable in `R.drawable.ic_vendor_*`. Completely eliminates generic canvas shield fallbacks for Rising, Lionic, K7, AlienVault, Trellix, Antiy, Huorong, Webroot, Xcitium, NANO, RocketCyber, Varist, Xvirus, Vir.IT, Aurora, etc.
* **Direct Logo Binding in `VendorFindingBadge`**: Sourced vendor findings directly against `getOfficialVendorDrawable(vendorName)`, preventing vendor names from collapsing into `brandKey = "Generic"`.
* **Direct Logo Binding in `EngineLogoIcon`**: Now attempts direct vendor asset resolution first before falling back to `EngineRegistry`.
* **K7 Mobile Security Official Transparent Asset**: Deployed official K7 Computing Mobile Security app asset with full alpha transparency `(0, 0, 0, 0)` corner padding, resolving dark-theme contrast blockiness.
* **`SubEngineRegistry` Full Coverage**: Added explicit Priority 1 matches for all 61 commercial antivirus vendors and updated registry tuples.

---

## [v1.5.7] - 2026-11-03
### 🦁 61 Official Brand Logos, Storage Exhaustion DoS Heuristics & Multi-Scanner Consensus Reconciliation
* **Exact Official Square-Fit Brand Logos (Multi-Pass Consensus)**: Verified and deployed 61 authentic, high-resolution 256x256 square brand logos into `app/src/main/res/drawable/ic_vendor_*.png` without distortion or canvas approximation. Direct user-reported fixes include:
  - **Rising**: Official Rising lion head mascot emblem (`Icon_512.png`).
  - **Avast**: Neutral, timeless Avast brand emblem (removed "2026" promotional banner).
  - **AlienVault OTX**: Official AlienVault green/black alien head emblem (replaced contributor avatar).
  - **CrowdStrike**: High-resolution official red Falcon emblem.
  - **Tachyon**: Official TACHYON Mobile Security brand icon.
  - **Zillya!**: Official Zillya! Antivirus brand icon.
  - **Lionic**: Official Lionic Antivirus shield emblem.
  - **Tencent**: Official Tencent penguin mascot emblem.
  - **K7 Security**: Mounted on high-contrast clean card surface to ensure crisp visibility against dark backgrounds.
* **Engine Edition Badges & Context Notes**:
  - **MetaDefender**: Tagged with `[ENTERPRISE GATEWAY]` badge; includes context note explaining perimeter server daemons focus on Windows PE/macros and exclude Android mobile PUA/adware by default.
  - **VirusTotal**: Tagged with `[MOBILE & CLOUD ML]` badge highlighting dedicated mobile ML classifiers (BitDefenderFalx, Trustlook).
  - **Multi-Scanner Divergence Reconciliation**: Dynamic notice automatically reconciles cases where mobile engines flag APK adware/PUA while enterprise gateway daemons return clean.
* **Storage Exhaustion Loops / Denial-of-Service Heuristics (`StorageFiller`)**:
  - Implemented targeted bytecode rules for `SC_INSUFFICIENT_STORAGE` (score 80) and `fillBuffer` (score 75) mapped to `DoS.AndroidOS.StorageFiller`.
  - Manifest heuristic flag (`isLikelyStorageExhaustion`) catches unverified background apps demanding full storage write access (`WRITE_EXTERNAL_STORAGE` / `MANAGE_EXTERNAL_STORAGE`) without a launcher activity.
* **MetaDefender Advisory Weightage on Android Executables**:
  - When MetaDefender returns a clean verdict for Android APKs/DEX files, it contributes at most 1 advisory gateway vote to `totalCount` instead of 32, preventing perimeter server policies from crushing mobile detections.
  - In `HybridThreatScorer.kt`, MetaDefender 0/32 clean verdicts are barred from diluting on-device Android heuristic findings.
* **Curated Mobile Malware Corpus Preloaded (13 Academic & Research Datasets)**:
  - Preloaded 80 verified mobile malware signatures into `LocalSignatureDatabase.kt` and `definitions/signatures.json` covering Banking Trojans (Anatsa, TeaBot, SharkBot, Cerberus, FluBot, Godfather, SOVA, BRATA, Octo, FakeBanker), Commercial Spyware/RATs (SpyNote, AhMyth, Pegasus IOCs, Dendroid, Exodus, Malbus, Comebot), Ransomware (SimpleLocker, DoubleLocker, WannaLocker, Koler, DSEncrypt), Persistent Droppers/Rootkits (xHelper, Towelroot, Triada, GhostPush, Rootnik), and DoS Storage Exhaustion (`StorageFiller`).
  - Registered 13 academic and intelligence datasets in `DATABASE_SOURCES`: `ashishb/android-malware`, `Android Malware Genome Project (MalGenome)`, `The Drebin Dataset (NDSS)`, `Canadian Institute for Cybersecurity (CIC-AndMal)`, `Malware-Hunter MH-100K`, `MASCOT-Android (arXiv:2606.16072)`, `Droidware (Mendeley Data)`, `AndroZoo`, `Abuse.ch MalwareBazaar`, `CIRCL & MISP`, `MITRE ATT&CK Mobile`, `VX-Underground`, and `ThreatLens YARA Engine`.
* **Dynamic Database Update & Hot-Reloading Mechanism**:
  - Implemented thread-safe `ConcurrentHashMap` in `LocalSignatureDatabase` allowing live, hot registration of new threat signatures without app restarts.
  - Upgraded `SignatureUpdateService.kt` with dual-mirror fallback synchronization, strict 64-hex SHA-256 validation, local encrypted persistence (`threatlens_signatures.json`), and reactive `totalSignatures` StateFlows.
  - Connected real-time reactive counters and expandable dataset source explorer directly in `SettingsScreen.kt`.

---

## [v1.5.6] - 2026-11-03
### 🚀 Real-Time Safe Scan Notifications & Direct Result Sheet Navigation
* **Real-Time Safe Scan Notifications ("Sense of Security")**: When newly downloaded files or newly installed apps are scanned and verified clean, ThreatLens now posts a reassuring notification (`✓ Verified Safe: [App / File Name] • No threats detected • Verified safe to use`) so users know the real-time background shield is actively protecting them.
* **Quiet Bulk Scans**: Full system audits of 100–200+ installed applications remain quiet and do not flood the notification shade with clean files.
* **Direct Forensic Sheet Navigation**: Tapping any scan notification (malware alert or safe verification) directly opens ThreatLens, switches to the Dashboard, retrieves the scan report from cache in <1ms, and automatically expands the `ThreatDetailSheet` with the full multi-engine breakdown.
* **Focused Android Executable Filter**: Gated real-time scanning strictly to Android-executable and exploitable vectors (`.apk`, `.dex`, `.jar`, `.so`, `.bin`, and installed packages), ignoring non-executable formats (`.com`, `.exe`, `.txt`, `.jpg`, `.mp3`) to preserve device battery and CPU.

---

## [v1.5.5] - 2026-11-03
### 🛡️ Multi-Cloud Dynamic Consensus, MetaDefender Active Modules & Engine Brand Logos
* **Dynamic Multi-Cloud Quorum**: If VirusTotal or any other cloud engine is offline, rate-limited (HTTP 429), or missing an API key, ThreatLens dynamically recalibrates consensus across available online providers without diluting scores or raising false alarms.
* **Multi-Cloud Corroboration**: Requires corroboration across multiple independent clouds or verified signature databases before declaring confirmed malware (`75–100/100`), preventing single-AV false-positive alarms on clean Play Store apps.
* **Consensus-Clean Heuristic Suppression**: When online cloud engines report 0 threats, noisy local heuristics are suppressed to `0–15/100` for verified store apps.
* **MetaDefender Cloud Active Module Filtering**: Inactive modules ("Not Active") are cleanly hidden; active modules clearly show clean vs detected status (Metascan, Predictive Alin AI, Vulnerability Assessment, Deep CDR, Adaptive Sandbox, Country of Origin, Proactive DLP, AI Content Inspector).
* **Commercial AV Vendor Breakdown**: Unrolls MetaDefender's internal `scan_details` to display individual participating antivirus engines (Avira, AhnLab, Bitdefender, etc.) with custom vector brand logos.
* **Filescan.io Web Report Fix**: Corrected web result links from broken SPA `/scan/$sha256` (404) to the valid `/search?query=$sha256` route.
* **Hybrid Analysis Falcon Sandbox Protection**: Fixed unindexed hash handling (no longer falsely reported as "Unreachable") and reserved dynamic detonation uploads strictly for suspicious/high-risk files to protect daily quota.

---

## [v1.5.4] - 2026-11-03
### ⚡ Smart Daily Rate Limit Quota Saver & Radio Controls
* **Daily Quota Preservation Thresholds**: Automatically detects bulk scans exceeding free daily API limits (VirusTotal: 500, MetaDefender: 100, Filescan: 100) and preserves quota on verified safe store apps.
* **Interactive RadioButton Mode Selectors**: Added "Save Quota (Bypass known safe)" vs "Always Query (Scan every app)" radio controls in Settings for all cloud engines.
* **Filescan HTTP 422 Enum Fix**: Resolved HTTP 422 unprocessable entity errors caused by invalid `page_size` query parameters.

---

## [v1.5.3] - 2026-11-03
### 🔑 Cloud API Key Validation & Endpoint Hardening
* **Dedicated Validation Endpoints**: Hardened live API key validation for MetaDefender (`v4/apikey`) and Filescan.io (`/api/reports/search`).
* **Header-Based Authentication**: Aligned header schemes (`apikey` for MetaDefender, `X-Api-Key` for Filescan.io) and added user-agent telemetry.

---

## [v1.5.2] - 2026-11-01
### 🧹 False-Positive Elimination, Dynamic Counts & Scan Export
* **Bytecode False-Positive Elimination**: Restricted bytecode pattern scanning strictly to compiled `.dex` entries, eliminating false flags on uncompiled asset text.
* **Export Scan Report (.JSON)**: One-tap export and sharing of comprehensive JSON scan reports containing full device posture, app metadata, and multi-engine telemetry.
* **Result Filters & Ordering**: Added segmented filter pills (`ALL`, `THREATS`, `SAFE`) and sorting dropdowns (`Malware First`, `Highest Score`, `Alphabetical`).
* **Deduplicated Counters**: Streamlined real-time dashboard counters to prevent double-counting between full scans and background events.

---

## [v1.5.1] - 2026-10-29
### 🎨 Authentic Brand Logos, Heuristic Score Reconciliation & Offline Ransomware
* **Vector Brand Logos**: Custom canvas-rendered emblems for 70+ industry vendors (VirusTotal, Norton, Bitdefender, Microsoft Defender, Kaspersky, Avast, ESET, McAfee, Sophos, Google Play Protect, ClamAV, Trend Micro).
* **Offline Ransomware Pattern Recognition**: Flags crypto-ransomware and screen-locker behavior locally without requiring cloud engines.
* **Heuristic Score Capping**: Unconfirmed behavioral heuristics capped at 50/100 (`SUSPICIOUS` / `HIGH_RISK`) so unverified patterns are never branded 100/100 malware.

---

## [v1.5.0] - 2026-10-29
### 🏪 Multi-Store Provenance Hierarchy & Fast Scan Cache
* **Store Provenance Badging**: Identifies install sources (Google Play, F-Droid, Aurora, Galaxy Store, GetApps, Amazon) and flags high-risk sideload vectors (Telegram, WhatsApp, Browser).
* **User Whitelist & Trust Manager**: Mark legitimate power-user tools (Termux, Tasker, internal tools) as trusted directly from their threat sheet.
* **Fast Incremental Caching**: Smart verdict cache indexed by package build timestamp, dropping full device scans from 40s to <3 seconds.

---

## [v1.4.2] - 2026-10-29
### 🛠️ Banking False-Positive Suppression & Engine Name De-truncation
* **Banking Trojan Heuristic Refinement**: Suppressed overlay injection false alarms on verified banking apps with valid Play Store certificates.
* **De-truncated Engine Titles**: Prevented engine names from truncating on smaller phone displays.

---

## [v1.4.1] - 2026-10-27
### 🌐 Geolocation & Indian Cyber Threat News Feed
* **India Regional Threat Intelligence**: Added CERT-In, digital arrest, and Indian banking fraud feeds with human-friendly relative timestamps ("2h ago", "Today").

---

## [v1.4.0] - 2026-10-27
### 🔍 Device Exploit & Vulnerability Auditor (`Vulns`)
* **SPL Gap Auditor**: Measures device firmware patch level against current Android Security Bulletins.
* **System Posture Audits**: Audits USB debugging (ADB), SELinux mode, root binaries (`su`), and Linux kernel vulnerabilities.

---

## [v1.3.0] - 2026-10-25
### 📱 Real Application Identity & Enhanced Controls
* **Human-Readable App Titles**: Displays real app names and dynamic app icons instead of generic `base.apk`.
* **Separate Actions**: Distinguishes between system uninstallation for installed apps and permanent file deletion for downloaded APKs.
* **Scan Controls**: Added Pause, Resume, and Abort controls for on-demand system scans.

#!/usr/bin/env python3
"""
ThreatLens - Progressive Streaming Simulation & Verification CLI Tool
Demonstrates:
1. Instant Phase (<20ms): Emits local heuristic findings and baseline running score.
2. Dynamic Cloud Streaming: Emits real-time score updates as each cloud engine responds.
3. Live Pending Engine Messages: Shows awaiting list while streaming.
4. AI Threat Explainer: Injects plain-English risk advice upon completion.
"""

import sys
import time
import hashlib
import json
import urllib.request
import urllib.error

# Force UTF-8 on Windows stdout
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

SAMPLE_CERBERUS = "3a6f44d8c6b75f9227181c009bdc8c1873130d2105aa0a6c085fc5794a37b089"

def banner():
    print("""
============================================================
    THREATLENS - PROGRESSIVE STREAMING ENGINE SIMULATOR
============================================================
""")

def simulate_streaming_scan(gemini_key=""):
    banner()
    file_name = "SecureBanking_Update_v4.apk"
    print(f"[*] Intercepted Download: {file_name}")
    print(f"[*] SHA-256: {SAMPLE_CERBERUS}\n")

    # -------------------------------------------------------------
    # PHASE 1: Instant Local Analysis (<20ms)
    # -------------------------------------------------------------
    local_score = 80
    pending = ["MalwareBazaar", "VirusTotal", "MetaDefender", "Kaspersky OpenTIP", "Hybrid Analysis"]
    running_score = int(local_score * 0.45)
    
    print("┌────────────────────────────────────────────────────────────")
    print(f"│ [T+15ms] ⚡ LOCAL PHASE COMPLETE (Instant UI Update)")
    print(f"│ • Running Score: {running_score}/100 [SUSPICIOUS]")
    print(f"│ • Heuristics: Overlay + Accessibility abuse, SMS intercept")
    print(f"│ • Status: Local analysis complete. Querying 5 cloud engines...")
    print(f"│ • Pending Engines: {', '.join(pending)}")
    print("└────────────────────────────────────────────────────────────\n")
    time.sleep(0.6)

    # -------------------------------------------------------------
    # PHASE 2: Dynamic Cloud Engine Streaming
    # -------------------------------------------------------------
    # Stream 1: MalwareBazaar returns
    pending.remove("MalwareBazaar")
    running_cloud_score = 95
    running_score = int((local_score * 0.45) + (running_cloud_score * 0.55))
    print("┌────────────────────────────────────────────────────────────")
    print(f"│ [T+350ms] 🔄 STREAM UPDATE 1: MalwareBazaar Responded")
    print(f"│ • Verdict: Trojan-Banker.AndroidOS.Cerberus (Malicious)")
    print(f"│ • Dynamic Score Updated: {running_score}/100 [CRITICAL MALWARE]")
    print(f"│ • Status: Pending ({len(pending)}): {', '.join(pending)}")
    print("└────────────────────────────────────────────────────────────\n")
    time.sleep(0.6)

    # Stream 2: MetaDefender returns
    pending.remove("MetaDefender")
    print("┌────────────────────────────────────────────────────────────")
    print(f"│ [T+620ms] 🔄 STREAM UPDATE 2: MetaDefender Cloud Responded")
    print(f"│ • Verdict: 26/32 engines flagged positive")
    print(f"│ • Dynamic Score Updated: {running_score}/100 [CRITICAL MALWARE]")
    print(f"│ • Status: Pending ({len(pending)}): {', '.join(pending)}")
    print("└────────────────────────────────────────────────────────────\n")
    time.sleep(0.5)

    # Stream 3: VirusTotal returns
    pending.remove("VirusTotal")
    running_cloud_score = 100
    running_score = 100
    print("┌────────────────────────────────────────────────────────────")
    print(f"│ [T+890ms] 🔄 STREAM UPDATE 3: VirusTotal Responded")
    print(f"│ • Verdict: 54/72 engines flagged positive")
    print(f"│ • Dynamic Score Updated: {running_score}/100 [CRITICAL MALWARE]")
    print(f"│ • Status: Pending ({len(pending)}): {', '.join(pending)}")
    print("└────────────────────────────────────────────────────────────\n")
    time.sleep(0.4)

    # Remaining engines wrap up
    pending.clear()
    print("┌────────────────────────────────────────────────────────────")
    print(f"│ [T+1.2s] ✓ ALL CLOUD ENGINES COMPLETE")
    print(f"│ • Composite Cloud Score: 100/100")
    print(f"│ • Status: Querying Gemini AI for plain-English explanation...")
    print("└────────────────────────────────────────────────────────────\n")

    # -------------------------------------------------------------
    # PHASE 3: AI Threat Explainer
    # -------------------------------------------------------------
    if gemini_key:
        print("[*] Contacting Google Gemini 1.5 Flash...")
        # live query
        prompt = "Explain Trojan-Banker.AndroidOS.Cerberus in 3 bullet points: 1. What is it, 2. What harm can it cause, 3. Recommended action."
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_key}"
        payload = json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode('utf-8')
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                ai_text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
        except Exception:
            ai_text = "AI explanation unavailable (fallback used)."
    else:
        ai_text = (
            "🚨 What is this? This is Cerberus, a dangerous banking trojan disguised as a bank update.\n"
            "⚠️ What can it cause? It steals online banking logins, intercepts 2FA SMS codes, and records screen taps.\n"
            "🛡️ Action: Delete and uninstall immediately! Do not open."
        )

    # -------------------------------------------------------------
    # PHASE 4: Final State Emitted
    # -------------------------------------------------------------
    print("============================================================")
    print("               FINAL VERDICT EMITTED TO UI                  ")
    print("============================================================")
    print(f"Target:          {file_name}")
    print(f"Final Score:     100/100 [CRITICAL MALWARE]")
    print(f"Threat Family:   Trojan-Banker.AndroidOS.Cerberus")
    print(f"Cloud Sources:   MalwareBazaar, VirusTotal (54/72), MetaDefender (26/32)")
    print(f"AI Brief:\n{ai_text}")
    print("============================================================\n")

if __name__ == "__main__":
    key = sys.argv[1] if len(sys.argv) > 1 else ""
    simulate_streaming_scan(key)

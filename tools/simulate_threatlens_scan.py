#!/usr/bin/env python3
"""
ThreatLens - Progressive Streaming Simulation & Multi-AI CLI Tool
Supports:
  --gemini <KEY>   : Test with Google Gemini Flash
  --openai <KEY>   : Test with OpenAI ChatGPT (gpt-4o-mini)
  --claude <KEY>   : Test with Anthropic Claude 3.5 Haiku
  --groq <KEY>     : Test with Groq Cloud (Llama 3.1)
"""

import sys
import time
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
    THREATLENS - PROGRESSIVE STREAMING & MULTI-AI ENGINE
============================================================
""")

def query_openai(api_key, target, threat, behaviors):
    print(f"[*] Querying OpenAI ChatGPT (gpt-4o-mini)...")
    url = "https://api.openai.com/v1/chat/completions"
    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": "You are a cybersecurity expert on ThreatLens. Explain threats in plain English in 3 short bullet points: 1. What is this, 2. What can it cause, 3. Recommended action."},
            {"role": "user", "content": f"Target: {target}\nThreat: {threat}\nBehaviors: {', '.join(behaviors)}"}
        ],
        "max_tokens": 150
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode('utf-8'),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return data["choices"][0]["message"]["content"].strip()
    except Exception as e:
        return f"OpenAI request error: {e}"

def query_claude(api_key, target, threat, behaviors):
    print(f"[*] Querying Anthropic Claude (claude-3-5-haiku)...")
    url = "https://api.anthropic.com/v1/messages"
    payload = {
        "model": "claude-3-5-haiku-20241022",
        "max_tokens": 150,
        "system": "You are a cybersecurity expert on ThreatLens. Explain threats in plain English in 3 short bullet points: 1. What is this, 2. What can it cause, 3. Recommended action.",
        "messages": [
            {"role": "user", "content": f"Target: {target}\nThreat: {threat}\nBehaviors: {', '.join(behaviors)}"}
        ]
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode('utf-8'),
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json"
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return data["content"][0]["text"].strip()
    except Exception as e:
        return f"Claude request error: {e}"

def main():
    banner()
    file_name = "SecureBanking_Update_v4.apk"
    print(f"[*] Intercepted Download: {file_name}")
    print(f"[*] SHA-256: {SAMPLE_CERBERUS}\n")

    behaviors = [
        "Overlay & Accessibility abuse (Injects fake login screens over banking apps)",
        "Intercepts incoming SMS/OTPs and exfiltrates over the network",
        "Requests Device Administrator privileges"
    ]

    # Progressive Cloud Streaming Simulation
    print("┌────────────────────────────────────────────────────────────")
    print(f"│ [T+15ms] ⚡ LOCAL PHASE COMPLETE (<20ms)")
    print(f"│ • Running Score: 36/100 [SUSPICIOUS]")
    print(f"│ • Status: Querying VirusTotal, MetaDefender, Kaspersky, MalwareBazaar...")
    print("└────────────────────────────────────────────────────────────\n")
    time.sleep(0.4)

    print("┌────────────────────────────────────────────────────────────")
    print(f"│ [T+450ms] 🔄 STREAM UPDATE: VirusTotal & MalwareBazaar Responded")
    print(f"│ • Dynamic Score: 100/100 [CRITICAL MALWARE]")
    print(f"│ • Identified Family: Trojan-Banker.AndroidOS.Cerberus")
    print("└────────────────────────────────────────────────────────────\n")

    # Check command-line AI flags
    ai_text = None
    args = sys.argv[1:]
    if "--openai" in args:
        idx = args.index("--openai")
        if idx + 1 < len(args):
            ai_text = query_openai(args[idx + 1], file_name, "Trojan-Banker.AndroidOS.Cerberus", behaviors)
    elif "--claude" in args:
        idx = args.index("--claude")
        if idx + 1 < len(args):
            ai_text = query_claude(args[idx + 1], file_name, "Trojan-Banker.AndroidOS.Cerberus", behaviors)

    if not ai_text:
        ai_text = (
            "🚨 What is this? This is Cerberus, a dangerous banking trojan disguised as a bank update.\n"
            "⚠️ What can it cause? It steals online banking logins, intercepts 2FA SMS codes, and records screen taps.\n"
            "🛡️ Action: Delete and uninstall immediately! Do not open."
        )

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
    main()

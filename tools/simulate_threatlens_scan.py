#!/usr/bin/env python3
"""
ThreatLens - Simulation & Verification CLI Tool
"""

import sys
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
       THREATLENS - HYBRID ANTIVIRUS VERIFICATION CLI
============================================================
""")

def test_malwarebazaar(sha256_hash, auth_key=None):
    print(f"[*] Querying MalwareBazaar (Abuse.ch)...")
    url = "https://mb-api.abuse.ch/api/v1/"
    data = f"query=get_info&hash={sha256_hash}".encode('utf-8')
    headers = {"User-Agent": "ThreatLens/1.0"}
    if auth_key:
        headers["Auth-Key"] = auth_key

    req = urllib.request.Request(url, data=data, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            res = json.loads(response.read().decode('utf-8'))
            status = res.get("query_status")
            if status == "ok" and res.get("data"):
                item = res["data"][0]
                sig = item.get("signature", "Generic.Malware")
                ftype = item.get("file_type")
                tags = item.get("tags", [])
                print(f"  [+] HIT! Detected on MalwareBazaar: {sig} ({ftype}) Tags: {tags}")
                return {"flagged": True, "family": sig, "score": 95}
            else:
                print(f"  [-] Clean or not found in MalwareBazaar ({status})")
                return {"flagged": False, "score": 0}
    except urllib.error.HTTPError as e:
        if e.code == 401:
            print("  [i] MalwareBazaar requires free Auth-Key (register free at abuse.ch/api)")
        else:
            print(f"  [!] Query failed: {e}")
        return {"flagged": False, "score": 0}
    except Exception as e:
        print(f"  [!] Query failed: {e}")
        return {"flagged": False, "score": 0}

def test_gemini_explainer(api_key, target_name, threat_family, behaviors, permissions):
    print(f"\n[*] Requesting AI Threat Explanation from Google Gemini...")
    if not api_key:
        print("  [-] No Gemini API Key provided. Testing built-in fallback engine:")
        fallback = f"[FALLBACK ENGINE] {threat_family}: Disguised application designed to steal credentials, monitor screen touches, and exfiltrate 2FA SMS codes.\nRecommended Action: Delete and uninstall immediately."
        print(f"  {fallback}")
        return fallback

    prompt = f"""
You are a cybersecurity expert on ThreatLens mobile security team.
Explain this threat in 3 concise sections (under 100 words total):
Target: {target_name}
Threat: {threat_family}
Behaviors: {', '.join(behaviors)}
Permissions: {', '.join(permissions)}

1. What is this?
2. What can it cause?
3. Recommended Action:
"""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
    payload = json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode('utf-8')
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})

    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            res = json.loads(response.read().decode('utf-8'))
            text = res["candidates"][0]["content"]["parts"][0]["text"]
            print(f"  [+] Gemini AI Response:\n{text.strip()}")
            return text.strip()
    except Exception as e:
        print(f"  [!] Gemini request failed: {e}")
        return None

def calculate_hybrid_score(local_score, cloud_score, is_exact_sig=False):
    if is_exact_sig:
        return 100, "MALICIOUS"
    final_score = int(min(100, (local_score * 0.45) + (cloud_score * 0.55)))
    if final_score >= 75:
        tier = "MALICIOUS"
    elif final_score >= 50:
        tier = "HIGH RISK"
    elif final_score >= 25:
        tier = "SUSPICIOUS"
    else:
        tier = "CLEAN"
    return final_score, tier

def main():
    banner()
    print(f"Testing Known Malware Hash (Cerberus Banker): {SAMPLE_CERBERUS}")
    
    # 1. Local Heuristics Simulation
    local_score = 85
    behaviors = [
        "Overlay & Accessibility abuse (Injects fake login screens over banking apps)",
        "Intercepts incoming SMS/OTPs and exfiltrates over the network",
        "Requests Device Administrator privileges"
    ]
    permissions = ["BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW", "RECEIVE_SMS", "INTERNET"]
    print(f"\n[1] Local Static Heuristic Score: {local_score}/100")
    for b in behaviors:
        print(f"    • {b}")

    # 2. Cloud Reputation (MalwareBazaar)
    cloud_result = test_malwarebazaar(SAMPLE_CERBERUS)
    cloud_score = cloud_result.get("score", 0)

    # 3. Hybrid Scoring Formula
    # In live app, Cerberus hash hits local signature DB (exact match)
    final_score, tier = calculate_hybrid_score(local_score, cloud_score, is_exact_sig=True)
    print(f"\n[3] ThreatLens Hybrid Threat Score: {final_score}/100 [{tier}]")

    # 4. AI Explanation
    gemini_key = sys.argv[1] if len(sys.argv) > 1 else ""
    test_gemini_explainer(
        api_key=gemini_key,
        target_name="Bank_Security_Update.apk",
        threat_family="Trojan-Banker.AndroidOS.Cerberus",
        behaviors=behaviors,
        permissions=permissions
    )

    print("\n[+] Verification simulation complete.")

if __name__ == "__main__":
    main()

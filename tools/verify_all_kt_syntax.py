#!/usr/bin/env python3
import os
import re

ROOT = "D:/ThreatLens/app/src/main/java"
kt_files = []
for r, d, files in os.walk(ROOT):
    for f in files:
        if f.endswith('.kt'):
            kt_files.append(os.path.join(r, f))

print(f"Scanning {len(kt_files)} Kotlin files for Icons.Default usage and imports...")

icon_pattern = re.compile(r'Icons\.Default\.([A-Za-z0-9_]+)')

issues = 0
for path in kt_files:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    rel = os.path.relpath(path, "D:/ThreatLens")
    matches = icon_pattern.findall(text)
    for icon_name in set(matches):
        expected_import = f"androidx.compose.material.icons.filled.{icon_name}"
        wildcard_import = "androidx.compose.material.icons.filled.*"
        if expected_import not in text and wildcard_import not in text:
            print(f"[MISSING ICON IMPORT] {rel} uses 'Icons.Default.{icon_name}' but '{expected_import}' is missing!")
            issues += 1

if issues == 0:
    print("[+] All Icons.Default references are 100% imported and valid!")
else:
    print(f"[-] Found {issues} missing icon import(s).")

#!/usr/bin/env python3
"""
ThreatLens Comprehensive Static Analyzer & Runtime Exception Auditor
"""

import os
import re

ROOT = "D:/ThreatLens/app/src/main/java"
kt_files = []
for r, d, files in os.walk(ROOT):
    for f in files:
        if f.endswith('.kt'):
            kt_files.append(os.path.join(r, f))

print(f"[*] Auditing {len(kt_files)} Kotlin files in {ROOT}...")

findings = []

for path in kt_files:
    rel_path = os.path.relpath(path, "D:/ThreatLens")
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    full_text = "".join(lines)

    # 1. Check for string corruption or stray non-ascii broken quotes
    for i, line in enumerate(lines, 1):
        if "dYs" in line or "" in line:
            findings.append((rel_path, i, "Encoding Artifact / Stray Symbol", line.strip()))

    # 2. Check for unsafe unwrap (!!)
    for i, line in enumerate(lines, 1):
        if "!!" in line and not line.strip().startswith("//"):
            findings.append((rel_path, i, "Unsafe Null Assertion (!!)", line.strip()))

    # 3. Check for raw Thread.sleep on UI
    for i, line in enumerate(lines, 1):
        if "Thread.sleep(" in line:
            findings.append((rel_path, i, "Blocking Thread.sleep() Detected", line.strip()))

    # 4. Check for OkHttp call execution outside Dispatchers.IO
    if ".execute()" in full_text:
        has_io = "Dispatchers.IO" in full_text or "withContext(Dispatchers.IO)" in full_text
        if not has_io:
            findings.append((rel_path, 0, "Network execute() missing Dispatchers.IO context", "OkHttpClient.execute()"))

print(f"\n[+] Audit Complete. Found {len(findings)} items to review:")
for f_path, line_no, category, detail in findings:
    print(f"  [{category}] {f_path}:{line_no}")
    print(f"    Code: {detail}\n")

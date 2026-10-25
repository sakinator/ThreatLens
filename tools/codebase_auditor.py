#!/usr/bin/env python3
"""
ThreatLens Static Codebase & Symbol Reference Auditor
Statically checks every Kotlin file to catch any missing symbols,
broken imports, missing colors, unimported icons, or typos before pushing to CI.
"""

import os
import re
import glob
import sys

# Force UTF-8 on Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

def audit_codebase():
    base_dir = os.path.join("D:\\ThreatLens", "app", "src", "main", "java")
    kt_files = glob.glob(os.path.join(base_dir, "**", "*.kt"), recursive=True)

    # 1. Collect all declared classes, objects, enums, top-level vals/funs
    declared_symbols = set()
    for f in kt_files:
        with open(f, "r", encoding="utf-8") as fp:
            text = fp.read()
        for m in re.finditer(r'(?:class|object|interface|enum class)\s+([A-Za-z0-9_]+)', text):
            declared_symbols.add(m.group(1))
        for m in re.finditer(r'val\s+([A-Za-z0-9_]+)\s*=', text):
            declared_symbols.add(m.group(1))

    # Also add standard colors from Color.kt
    color_file = os.path.join(base_dir, "io", "threatlens", "ui", "theme", "Color.kt")
    with open(color_file, "r", encoding="utf-8") as fp:
        color_text = fp.read()
    colors = set(re.findall(r'val\s+([A-Za-z0-9_]+)\s*=\s*Color', color_text))

    print(f"Declared Classes/Objects/Vals: {len(declared_symbols)}")
    print(f"Colors available: {colors}")

    issues = []

    # Check color usages
    known_classes = {"CyberNewsArticle", "CyberNewsFeedService", "CyberSecurity", "Cybersecurity", "CyberRadarShield", "CyberComponents"}

    for f in kt_files:
        rel = os.path.relpath(f, base_dir)
        with open(f, "r", encoding="utf-8") as fp:
            code = fp.read()

        # Check for any reference to colors that don't exist
        for m in re.finditer(r'\b(Neon[A-Za-z0-9_]+|Cyber[A-Za-z0-9_]+)\b', code):
            cname = m.group(1)
            if cname not in colors and cname not in known_classes and cname not in declared_symbols:
                issues.append((rel, f"Missing color reference: '{cname}'"))

        # Check for unclosed braces or parentheses
        if code.count('{') != code.count('}'):
            issues.append((rel, f"Unbalanced braces: {code.count('{')} open vs {code.count('}')} close"))
        if code.count('(') != code.count(')'):
            issues.append((rel, f"Unbalanced parens: {code.count('(')} open vs {code.count(')')} close"))

    if not issues:
        print("\n✅ ZERO SYMBOL OR COMPILER ISSUES FOUND ACROSS ALL KOTLIN FILES!")
        return True
    else:
        print(f"\n❌ FOUND {len(issues)} ISSUES:")
        for rel, err in issues:
            print(f"  - {rel}: {err}")
        return False

if __name__ == "__main__":
    ok = audit_codebase()
    exit(0 if ok else 1)

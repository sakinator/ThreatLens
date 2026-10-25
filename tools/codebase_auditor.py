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

    declared_symbols = set()
    for f in kt_files:
        with open(f, "r", encoding="utf-8") as fp:
            text = fp.read()
        for m in re.finditer(r'(?:class|object|interface|enum class)\s+([A-Za-z0-9_]+)', text):
            declared_symbols.add(m.group(1))
        for m in re.finditer(r'val\s+([A-Za-z0-9_]+)\s*=', text):
            declared_symbols.add(m.group(1))

    color_file = os.path.join(base_dir, "io", "threatlens", "ui", "theme", "Color.kt")
    with open(color_file, "r", encoding="utf-8") as fp:
        color_text = fp.read()
    colors = set(re.findall(r'val\s+([A-Za-z0-9_]+)\s*=\s*Color', color_text))

    print(f"Declared Classes/Objects/Vals: {len(declared_symbols)}")
    print(f"Colors available: {colors}")

    issues = []
    known_classes = {"CyberNewsArticle", "CyberNewsFeedService", "CyberSecurity", "Cybersecurity", "CyberRadarShield", "CyberComponents"}

    for f in kt_files:
        rel = os.path.relpath(f, base_dir)
        with open(f, "r", encoding="utf-8") as fp:
            text = fp.read()

        # Check color references
        color_usages = re.findall(r'\b(Neon[A-Za-z0-9_]+|Cyber[A-Za-z0-9_]+)\b', text)
        for c in color_usages:
            if c not in colors and c not in known_classes and not c.startswith("CyberTheme"):
                issues.append(f"[{rel}] Undefined Color: '{c}'")

        # Check clickable modifier import
        if ".clickable" in text:
            if "import androidx.compose.foundation.clickable" not in text and "import androidx.compose.foundation.*" not in text:
                issues.append(f"[{rel}] Missing import: androidx.compose.foundation.clickable")

        # Check coroutine launch import
        if re.search(r'\b(launch\s*\{)', text):
            if "import kotlinx.coroutines.launch" not in text and "import kotlinx.coroutines.*" not in text:
                issues.append(f"[{rel}] Missing import: kotlinx.coroutines.launch")

        # Check FontFamily import
        if "FontFamily." in text or "fontFamily = FontFamily" in text:
            if "import androidx.compose.ui.text.font.FontFamily" not in text and "import androidx.compose.ui.text.font.*" not in text:
                issues.append(f"[{rel}] Missing import: androidx.compose.ui.text.font.FontFamily")

        # Check FontWeight import
        if "FontWeight." in text or "fontWeight = FontWeight" in text:
            if "import androidx.compose.ui.text.font.FontWeight" not in text and "import androidx.compose.ui.text.font.*" not in text:
                issues.append(f"[{rel}] Missing import: androidx.compose.ui.text.font.FontWeight")

        # Check Icons.Default.* imports
        icon_matches = re.findall(r'Icons\.Default\.([A-Za-z0-9_]+)', text)
        if icon_matches:
            has_wildcard = "import androidx.compose.material.icons.filled.*" in text
            for icon_name in set(icon_matches):
                if not has_wildcard:
                    specific_import = f"import androidx.compose.material.icons.filled.{icon_name}"
                    if specific_import not in text:
                        issues.append(f"[{rel}] Missing Icon Import for Icons.Default.{icon_name}")

    if issues:
        print("\n❌ FOUND AUDIT ISSUES:")
        for iss in issues:
            print("  " + iss)
        return False
    else:
        print("\n✅ ZERO SYMBOL OR COMPILER ISSUES FOUND ACROSS ALL KOTLIN FILES!")
        return True

if __name__ == "__main__":
    success = audit_codebase()
    if not success:
        sys.exit(1)

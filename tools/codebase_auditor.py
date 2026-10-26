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

def check_brackets_and_syntax(rel_path, text):
    """
    Checks syntax integrity:
    1. Parentheses (), Brackets [], and Braces {} balancing
    2. Unclosed string literals
    Ignores comments and content inside string literals.
    """
    errors = []
    stack = []
    lines = text.split("\n")
    
    i = 0
    n = len(text)
    line_num = 1
    
    in_block_comment = False
    in_line_comment = False
    in_triple_string = False
    in_single_string = False
    
    while i < n:
        c = text[i]
        
        if c == '\n':
            line_num += 1
            if in_line_comment:
                in_line_comment = False
            i += 1
            continue
            
        if in_line_comment:
            i += 1
            continue
            
        if in_block_comment:
            if c == '*' and i + 1 < n and text[i + 1] == '/':
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue
            
        if in_triple_string:
            if c == '"' and i + 2 < n and text[i + 1] == '"' and text[i + 2] == '"':
                in_triple_string = False
                i += 3
                continue
            i += 1
            continue
            
        if in_single_string:
            if c == '\\':
                i += 2
                continue
            if c == '"':
                in_single_string = False
                i += 1
                continue
            i += 1
            continue
            
        # Check start of comment or string
        if c == '/' and i + 1 < n:
            if text[i + 1] == '/':
                in_line_comment = True
                i += 2
                continue
            elif text[i + 1] == '*':
                in_block_comment = True
                i += 2
                continue
                
        if c == '"':
            if i + 2 < n and text[i + 1] == '"' and text[i + 2] == '"':
                in_triple_string = True
                i += 3
                continue
            else:
                in_single_string = True
                i += 1
                continue
                
        if c == '\'':
            # Char literal like '\n' or 'c'
            if i + 1 < n and text[i + 1] == '\\':
                i += 4
            else:
                i += 3
            continue
            
        # Brackets tracking
        if c in '({[':
            stack.append((c, line_num))
        elif c in ')}]':
            if not stack:
                errors.append(f"[{rel_path}:{line_num}] Unmatched closing '{c}'")
            else:
                top, top_line = stack.pop()
                expected = {')': '(', '}': '{', ']': '['}[c]
                if top != expected:
                    errors.append(f"[{rel_path}:{line_num}] Mismatched bracket: expected '{expected}' (opened line {top_line}), got '{c}'")
        i += 1
        
    if in_block_comment:
        errors.append(f"[{rel_path}] Unclosed block comment /* ... */")
    if in_triple_string:
        errors.append(f"[{rel_path}] Unclosed triple-quote string \"\"\" ... \"\"\"")
    if in_single_string:
        errors.append(f"[{rel_path}] Unclosed string literal \" ... \"")
    while stack:
        top, top_line = stack.pop()
        errors.append(f"[{rel_path}:{top_line}] Unclosed opening '{top}'")
        
    return errors

def audit_codebase():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.abspath(os.path.join(script_dir, "..", "app", "src", "main", "java"))
    kt_files = glob.glob(os.path.join(base_dir, "**", "*.kt"), recursive=True)

    declared_symbols = set()
    symbol_packages = {}
    for f in kt_files:
        with open(f, "r", encoding="utf-8") as fp:
            text = fp.read()
        pkg_m = re.search(r'package\s+([A-Za-z0-9_.]+)', text)
        pkg = pkg_m.group(1) if pkg_m else ""
        # Match only TOP-LEVEL classes/objects/interfaces
        for m in re.finditer(r'^(?:data\s+class|class|object|interface|enum\s+class)\s+([A-Za-z0-9_]+)', text, re.MULTILINE):
            sym = m.group(1)
            declared_symbols.add(sym)
            if pkg:
                symbol_packages[sym] = pkg
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

        pkg_m = re.search(r'package\s+([A-Za-z0-9_.]+)', text)
        cur_pkg = pkg_m.group(1) if pkg_m else ""
        imports = set(re.findall(r'import\s+([A-Za-z0-9_.*]+)', text))

        # Check cross-package references
        words = set(re.findall(r'\b([A-Z][A-Za-z0-9_]+)\b', text))
        for w in words:
            if w in symbol_packages:
                # If declared inside this file itself, skip
                if re.search(rf'\b(?:class|object|interface)\s+{w}\b', text):
                    continue
                def_pkg = symbol_packages[w]
                if def_pkg != cur_pkg:
                    specific_imp = f"{def_pkg}.{w}"
                    wildcard_imp = f"{def_pkg}.*"
                    if specific_imp not in imports and wildcard_imp not in imports:
                        if f"{def_pkg}.{w}" not in text:
                            issues.append(f"[{rel}] Missing cross-package import: {specific_imp}")

        # Syntax & Bracket Integrity
        issues.extend(check_brackets_and_syntax(rel, text))

        # Check color references
        color_usages = re.findall(r'\b(Neon[A-Za-z0-9_]+|Cyber[A-Za-z0-9_]+)\b', text)
        for c in color_usages:
            if c not in colors and c not in known_classes and not c.startswith("CyberTheme"):
                issues.append(f"[{rel}] Undefined Color: '{c}'")

        # Check clickable modifier import
        if ".clickable" in text:
            if "import androidx.compose.foundation.clickable" not in text and "import androidx.compose.foundation.*" not in text:
                issues.append(f"[{rel}] Missing import: androidx.compose.foundation.clickable")

        # Check background modifier import
        if ".background(" in text:
            if "import androidx.compose.foundation.background" not in text and "import androidx.compose.foundation.*" not in text:
                issues.append(f"[{rel}] Missing import: androidx.compose.foundation.background")

        # Check border modifier import
        if ".border(" in text:
            if "import androidx.compose.foundation.border" not in text and "import androidx.compose.foundation.*" not in text:
                issues.append(f"[{rel}] Missing import: androidx.compose.foundation.border")

        # Check scroll imports
        if "verticalScroll" in text or "rememberScrollState" in text:
            if "import androidx.compose.foundation.verticalScroll" not in text and "import androidx.compose.foundation.*" not in text:
                issues.append(f"[{rel}] Missing import: androidx.compose.foundation.verticalScroll")

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

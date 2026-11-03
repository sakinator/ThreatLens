#!/usr/bin/env python3
import sys
import os
import re

def extract_notes(tag_name, changelog_path="CHANGELOG.md", output_path="release_notes.md"):
    clean_tag = tag_name.strip()
    if clean_tag.startswith("refs/tags/"):
        clean_tag = clean_tag.replace("refs/tags/", "")
    
    if not os.path.exists(changelog_path):
        print(f"Error: {changelog_path} not found.")
        sys.exit(1)
        
    with open(changelog_path, "r", encoding="utf-8") as f:
        content = f.read()

    pattern = re.compile(
        rf"##\s*\[{re.escape(clean_tag)}\](?:[^\n]*\n)(.*?)(?=\n##\s*\[|\Z)",
        re.DOTALL
    )
    match = pattern.search(content)

    if match:
        notes = match.group(1).strip()
    else:
        # Fallback to the latest release block in the changelog
        fallback_pattern = re.compile(r"##\s*\[.*?\](?:[^\n]*\n)(.*?)(?=\n##\s*\[|\Z)", re.DOTALL)
        fallback_match = fallback_pattern.search(content)
        notes = fallback_match.group(1).strip() if fallback_match else f"Release {clean_tag}"

    full_body = f"## 🛡️ ThreatLens {clean_tag}\n\n{notes}\n"
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(full_body)
        
    print(f"Successfully generated release notes for {clean_tag} at {output_path}")

if __name__ == "__main__":
    tag = sys.argv[1] if len(sys.argv) > 1 else "v1.5.6"
    extract_notes(tag)

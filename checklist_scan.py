#!/usr/bin/env python3
import os
import re
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime, timezone

# Mapping of OWASP Checklist categories to common code patterns/keywords
# Each rule entry: (rule_id, regex, short_description)
# Design based on https://github.com/0xRadi/OWASP-Web-Checklist

RULES = {
    "Sensitive Data Exposure": [
        ("OWASP001", r"(?i)(api[_-]?key|secret|password|passwd|auth[_-]?token)\s*=\s*['\"][^'\"]{8,}['\"]", "Hardcoded API key or password"),
        ("OWASP002", r"AWS_SECRET_ACCESS_KEY|PRIVATE_KEY", "Potential hardcoded credentials/private key"),
        ("OWASP003", r"(?i)http://", "Insecure HTTP connection string"),
    ],
    "Injection Vulnerabilities (SQL/Command/Code)": [
        ("OWASP101", r"(?i)(SELECT|INSERT|UPDATE|DELETE).*\+.*\$", "Potential SQL string concatenation"),
        ("OWASP102", r"\b(eval|exec|passthru|system|shell_exec)\b\s*\(", "Dangerous code execution function"),
        ("OWASP103", r"\bchild_process\.exec\b", "Potential Command Injection (NodeJS)"),
        ("OWASP104", r"\b(subprocess\.Popen|os\.system)\b", "Potential Command Injection (Python)"),
    ],
    "Cross-Site Scripting (XSS)": [
        ("OWASP201", r"dangerouslySetInnerHTML", "Unsafe React innerHTML rendering"),
        ("OWASP202", r"document\.write\s*\(", "Direct DOM manipulation via document.write"),
        ("OWASP203", r"innerHTML\s*=", "Unsanitized innerHTML assignment"),
        ("OWASP204", r"\{\{\s*.*\|safe\s*\}\}", "Unescaped template rendering (Jinja/Django)"),
    ],
    "Weak Cryptography & Randomness": [
        ("OWASP301", r"\b(md5|sha1)\b", "Weak hash function (MD5/SHA-1)"),
        ("OWASP302", r"\bMath\.random\(\)", "Insecure random number generator (JS)"),
        ("OWASP303", r"\brandom\.random\(\)|\brandom\.randint\(", "Insecure pseudo-random generator (Python)"),
        ("OWASP304", r"\bDES\b|\b3DES\b|\bRC4\b", "Weak encryption algorithm"),
    ],
    "Insecure File Uploads & Path Traversal": [
        ("OWASP401", r"\.\.\/", "Path traversal sequence"),
        ("OWASP402", r"\bmove_uploaded_file\b", "File upload handling (PHP)"),
        ("OWASP403", r"send_from_directory|send_file", "File serving route check required"),
    ],
    "Authorization & Session Issues": [
        ("OWASP501", r"(?i)setHeader\s*\(\s*['\"]Access-Control-Allow-Origin['\"]\s*,\s*['\"]\*['\"]", "Wildcard CORS policy"),
        ("OWASP502", r"secure\s*:\s*false", "Cookie missing Secure flag"),
        ("OWASP503", r"httpOnly\s*:\s*false", "Cookie missing HttpOnly flag"),
    ]
}

# File extensions to scan
TARGET_EXTENSIONS = {'.js', '.ts', '.py', '.php', '.java', '.rb', '.go', '.html', '.jsx', '.tsx', '.json'}
IGNORE_DIRS = {'.git', 'node_modules', '__pycache__', 'venv', 'dist', 'build'}

def sarif_level_for_category(category: str) -> str:
    # Basic severity mapping (tune as needed)
    if "Injection" in category:
        return "error"
    if "Sensitive Data" in category or "Authorization" in category:
        return "warning"
    return "note"

def build_rules_index():
    """Create SARIF rule metadata + quick lookup map by rule_id."""
    rules = []
    index = {}
    for category, patterns in RULES.items():
        for rule_id, pattern, description in patterns:
            rule_obj = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": description},
                "fullDescription": {"text": f"{description} ({category})"},
                "properties": {
                    "category": category,
                    "precision": "medium",
                    "tags": ["security", "owasp-checklist"]
                }
            }
            rules.append(rule_obj)
            index[rule_id] = {
                "category": category,
                "description": description,
                "pattern": pattern
            }
    return rules, index

CONTEXT_LINES = 2  # lines before/after finding for code snippets 

def scan_directory(target_dir):
    findings = []
    target_dir = os.path.abspath(target_dir)

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]

        for file in files:
            ext = Path(file).suffix.lower()
            if ext not in TARGET_EXTENSIONS:
                continue

            filepath = os.path.join(root, file)

            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()

                for line_num, line in enumerate(lines, start=1):
                    for category, patterns in RULES.items():
                        for rule_id, pattern, description in patterns:
                            if re.search(pattern, line):
                                i = line_num - 1
                                ctx_start_idx = max(0, i - CONTEXT_LINES)
                                ctx_end_idx = min(len(lines), i + CONTEXT_LINES + 1)

                                context_slice = lines[ctx_start_idx:ctx_end_idx]
                                context_text = "".join(context_slice).rstrip("\n")

                                findings.append({
                                    'file': filepath,
                                    'line': line_num,
                                    'end_line': line_num,
                                    'category': category,
                                    'rule_id': rule_id,
                                    'issue': description,
                                    'content': line.rstrip("\n"),
                                    'context_start_line': ctx_start_idx + 1,
                                    'context_end_line': ctx_end_idx,
                                    'context_text': context_text
                                })
            except Exception as e:
                print(f"[!] Error reading {filepath}: {e}")

    return findings

def print_report(findings):
    if not findings:
        print("\n✅ No suspicious patterns found based on the checklist rules.")
        return

    print(f"\n==================================================")
    print(f"       OWASP CHECKLIST SCAN REPORT ({len(findings)} Findings)")
    print(f"==================================================\n")

    by_category = {}
    for item in findings:
        by_category.setdefault(item['category'], []).append(item)

    for category, items in by_category.items():
        print(f"## [{category}] ({len(items)} hits)")
        for item in items:
            print(f"  • {item['file']}:{item['line']} ({item['rule_id']})")
            print(f"    Issue:   {item['issue']}")
            print(f"    Snippet: {item['content'][:120]}")
            print("-" * 50)
        print()

# Add Sarif output modeled after https://github.com/PyCQA/bandit

def to_sarif(findings, base_dir):
    base_dir = os.path.abspath(base_dir)
    rules, _ = build_rules_index()

    results = []
    for f in findings:
        abs_path = os.path.abspath(f["file"])
        rel_path = os.path.relpath(abs_path, base_dir).replace("\\", "/")

        level = sarif_level_for_category(f["category"])
        message = f"{f['issue']} [{f['category']}]"

        # Pull snippet + nearby lines (already captured during scan)
        snippet_text = f.get("content", "")
        start_line = f["line"]
        end_line = f.get("end_line", start_line)

        # Optional context window
        context_start = f.get("context_start_line")
        context_end = f.get("context_end_line")
        context_text = f.get("context_text")  # multiline string

        region = {
            "startLine": start_line,
            "endLine": end_line,
            "snippet": {"text": snippet_text}
        }

        physical_location = {
            "artifactLocation": {"uri": rel_path},
            "region": region
        }

        # Add SARIF context region when available (closest to Bandit style)
        if context_start and context_end and context_text:
            physical_location["contextRegion"] = {
                "startLine": context_start,
                "endLine": context_end,
                "snippet": {"text": context_text}
            }

        results.append({
            "ruleId": f["rule_id"],
            "level": level,
            "message": {"text": message},
            "locations": [{"physicalLocation": physical_location}],
            "properties": {
                "category": f["category"],
                "snippet": snippet_text[:200]
            }
        })

    sarif_doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "owasp-checklist-scan",
                    "organization": "local",
                    "informationUri": "https://owasp.org/",
                    "semanticVersion": "0.1.0",
                    "rules": rules
                }
            },
            "automationDetails": {
                "id": "owasp-checklist/manual"
            },
            "invocations": [
                {
                    "executionSuccessful": True,
                    "endTimeUtc": datetime.now(timezone.utc).isoformat()
                }
            ],
            "results": results
        }]
    }
    return sarif_doc

def main():
    parser = argparse.ArgumentParser(description="OWASP checklist regex scanner")
    parser.add_argument("path", nargs="?", default=".", help="Directory to scan (default: current dir)")
    parser.add_argument("--sarif", dest="sarif_path", help="Write SARIF output to this file (e.g. results.sarif)")
    parser.add_argument("--no-text", action="store_true", help="Do not print text report")
    args = parser.parse_args()

    scan_path = args.path
    print(f"Scanning directory: {os.path.abspath(scan_path)}...")
    findings = scan_directory(scan_path)

    if not args.no_text:
        print_report(findings)

    if args.sarif_path:
        sarif_doc = to_sarif(findings, scan_path)
        with open(args.sarif_path, "w", encoding="utf-8") as f:
            json.dump(sarif_doc, f, indent=2)
        print(f"\nSARIF report written to: {args.sarif_path}")

if __name__ == "__main__":
    main()

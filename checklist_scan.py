#!/usr/bin/env python3
import os
import re
import sys
from pathlib import Path

# Mapping of OWASP Checklist categories to common code patterns/keywords
RULES = {
    "Sensitive Data Exposure": [
        (r"(?i)(api[_-]?key|secret|password|passwd|auth[_-]?token)\s*=\s*['\"][^'\"]{8,}['\"]", "Hardcoded API key or password"),
        (r"AWS_SECRET_ACCESS_KEY|PRIVATE_KEY", "Potential hardcoded credentials/private key"),
        (r"(?i)http://", "Insecure HTTP connection string"),
    ],
    "Injection Vulnerabilities (SQL/Command/Code)": [
        (r"(?i)(SELECT|INSERT|UPDATE|DELETE).*\+.*\$", "Potential SQL string concatenation"),
        (r"\b(eval|exec|passthru|system|shell_exec)\b\s*\(", "Dangerous code execution function"),
        (r"\bchild_process\.exec\b", "Potential Command Injection (NodeJS)"),
        (r"\b(subprocess\.Popen|os\.system)\b", "Potential Command Injection (Python)"),
    ],
    "Cross-Site Scripting (XSS)": [
        (r"dangerouslySetInnerHTML", "Unsafe React innerHTML rendering"),
        (r"document\.write\s*\(", "Direct DOM manipulation via document.write"),
        (r"innerHTML\s*=", "Unsanitized innerHTML assignment"),
        (r"\{\{\s*.*\|safe\s*\}\}", "Unescaped template rendering (Jinja/Django)"),
    ],
    "Weak Cryptography & Randomness": [
        (r"\b(md5|sha1)\b", "Weak hash function (MD5/SHA-1)"),
        (r"\bMath\.random\(\)", "Insecure random number generator (JS)"),
        (r"\brandom\.random\(\)|\brandom\.randint\(", "Insecure pseudo-random generator (Python)"),
        (r"\bDES\b|\b3DES\b|\bRC4\b", "Weak encryption algorithm"),
    ],
    "Insecure File Uploads & Path Traversal": [
        (r"\.\.\/", "Path traversal sequence"),
        (r"\bmove_uploaded_file\b", "File upload handling (PHP)"),
        (r"send_from_directory|send_file", "File serving route check required"),
    ],
    "Authorization & Session Issues": [
        (r"(?i)setHeader\s*\(\s*['\"]Access-Control-Allow-Origin['\"]\s*,\s*['\"]\*['\"]", "Wildcard CORS policy"),
        (r"secure\s*:\s*false", "Cookie missing Secure flag"),
        (r"httpOnly\s*:\s*false", "Cookie missing HttpOnly flag"),
    ]
}

# File extensions to scan
TARGET_EXTENSIONS = {'.js', '.ts', '.py', '.php', '.java', '.rb', '.go', '.html', '.jsx', '.tsx', '.json'}
IGNORE_DIRS = {'.git', 'node_modules', '__pycache__', 'venv', 'dist', 'build'}

def scan_directory(target_dir):
    findings = []
    
    for root, dirs, files in os.walk(target_dir):
        # Skip ignored directories
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
                        for pattern, description in patterns:
                            if re.search(pattern, line):
                                findings.append({
                                    'file': filepath,
                                    'line': line_num,
                                    'category': category,
                                    'issue': description,
                                    'content': line.strip()
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
            print(f"  • {item['file']}:{item['line']}")
            print(f"    Issue:   {item['issue']}")
            print(f"    Snippet: {item['content'][:80]}")
            print("-" * 50)
        print()

if __name__ == "__main__":
    scan_path = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"Scanning directory: {os.path.abspath(scan_path)}...")
    results = scan_directory(scan_path)
    print_report(results)

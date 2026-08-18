# WebAppSecurityTests

A suite of simplified and experimental scripts for web application security testing.

![OWASP Checklist](https://img.shields.io/badge/OWASP-Web_Checklist-darkred?logo=owasp&logoColor=white)
![Threat Modeling](https://img.shields.io/badge/Threat_Modeling-Threat_Composer_%2B_Threat_Dragon-blue)
![Bandit](https://img.shields.io/badge/Python_SAST-Bandit-yellow?logo=python&logoColor=black)
![SARIF Viewer](https://img.shields.io/badge/SARIF-Viewer-success)
![Languages](https://img.shields.io/badge/Languages-Shell%20%7C%20Python-informational)

---

## Table of Contents

- [Overview](#overview)
- [Quick Workflow](#quick-workflow)
- [Custom / Modified Scripts and Attributions](#custom--modified-scripts-and-attributions)
- [Security Workflow (Detailed)](#security-workflow-detailed)
- [Repository Structure](#repository-structure)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
- [Output and Reporting](#output-and-reporting)
- [Toolchain References](#toolchain-references)
- [Limitations](#limitations)
- [Legal and Ethical Notice](#legal-and-ethical-notice)
- [Contributing](#contributing)

---

## Overview

`WebAppSecurityTests` is a practical testing workspace focused on combining:

1. **Checklist-driven testing** from OWASP guidance  
2. **Threat modeling** for prioritizing attack surfaces  
3. **Static analysis** for Python scripts  
4. **SARIF-based output review** for consistent result handling

This repository is intended for **simplified and experimental** workflows that help accelerate manual and semi-automated security testing.

---

## Quick Workflow

1. Use the [OWASP Web Checklist](https://github.com/0xRadi/OWASP-Web-Checklist) as the control baseline.
2. Translate checklist controls into scripted checks in `checklist_scan.py`.
3. Model threats using [AWSLabs Threat Composer](https://github.com/awslabs/threat-composer) and [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon).
4. Run [Bandit](https://github.com/PyCQA/bandit) on Python scripts to detect common security issues.
5. Export findings as SARIF and review in [AperExanimus/neurowall-sarifviewer](https://github.com/AperExanimus/neurowall-sarifviewer).

---

## Custom / Modified Scripts and Attributions

This repository includes custom and/or adapted scripting logic inspired by established security testing and threat modeling resources.

### Custom / Modified Scripts

- `checklist_scan.py`  
  A custom script derived from and aligned with OWASP checklist methodology for simplified, script-based web security checks.

### Upstream References and Attribution

The following repositories informed workflow design, methodology, or tooling integration:

- **OWASP checklist baseline**  
  [0xRadi/OWASP-Web-Checklist](https://github.com/0xRadi/OWASP-Web-Checklist)  
  Referenced for checklist categories and testing control structure used in `checklist_scan.py`.

- **Threat modeling reference tools**  
  [awslabs/threat-composer](https://github.com/awslabs/threat-composer)  
  [OWASP/threat-dragon](https://github.com/OWASP/threat-dragon)  
  Referenced for threat modeling process, prioritization, and model-driven test planning.

- **Python SAST scanning**  
  [PyCQA/bandit](https://github.com/PyCQA/bandit)  
  Used for static analysis of Python scripts.

- **SARIF visualization**  
  [AperExanimus/neurowall-sarifviewer](https://github.com/AperExanimus/neurowall-sarifviewer)  
  Fork used for offline SARIF review and triage.

- **SSL/TLS testing reference**  
  [testssl.sh](https://github.com/testssl/testssl.sh)  
  Referenced for SSL/TLS-oriented testing patterns.

### Attribution Note

All referenced projects remain the work of their respective maintainers and communities.  
This repository does not claim ownership of upstream tools or standards; it documents how they are used together in this experimental workflow.

---

## Security Workflow (Detailed)

### 1) Checklist-Driven Test Generation (OWASP)

- Baseline reference: [0xRadi/OWASP-Web-Checklist](https://github.com/0xRadi/OWASP-Web-Checklist)
- Checklist categories are mapped into script-friendly checks in `checklist_scan.py`.
- The script can be evolved as checklist controls or testing scope changes.

### 2) Threat Modeling

Threat modeling is used to identify and prioritize probable abuse paths and weak trust boundaries before and during testing.

- [awslabs/threat-composer](https://github.com/awslabs/threat-composer)
- [OWASP/threat-dragon](https://github.com/OWASP/threat-dragon)

Use these models to:
- Identify critical assets and trust boundaries
- Prioritize high-risk test cases
- Improve coverage for likely attacker paths

### 3) Python Security Scanning (Bandit)

- Static analysis is performed with [PyCQA/bandit](https://github.com/PyCQA/bandit).
- Bandit helps detect common Python security issues in scripts and supporting utilities.
- Findings should be triaged for context and exploitability.

### 4) SARIF Review and Triage

- Export findings in SARIF format.
- Review SARIF results in: [AperExanimus/neurowall-sarifviewer](https://github.com/AperExanimus/neurowall-sarifviewer)
- Use SARIF as a portable format for repeatable analysis and reporting.

---

## Repository Structure

> Update this section to match your exact file layout.

```text
.
├── checklist_scan.py
├── (shell scripts)
├── (python scripts)
└── README.md
```

---

## Prerequisites

- Python 3.9+ (recommended)
- pip
- Bandit
- (Optional) Threat modeling tools:
  - Threat Composer
  - Threat Dragon

Install Bandit:

```bash
pip install bandit
```

---

## Usage

### 1. Run checklist-derived scans

```bash
python3 checklist_scan.py
```

### 2. Run Bandit against repository scripts

```bash
bandit -r . -f sarif -o bandit-results.sarif
```

Optional (human-readable terminal report):

```bash
bandit -r .
```

### 3. Review SARIF output

Open your SARIF file (`bandit-results.sarif`) with:

- [AperExanimus/neurowall-sarifviewer](https://github.com/AperExanimus/neurowall-sarifviewer)

---

## Output and Reporting

Typical outputs may include:

- Script-level scan outputs from checklist-based checks
- Bandit findings in terminal format
- SARIF reports for structured issue triage

Recommended triage process:

1. Deduplicate findings  
2. Validate exploitability/context  
3. Prioritize by risk and impact  
4. Track remediation and retest

---

## Toolchain References

- OWASP checklist baseline:  
  [0xRadi/OWASP-Web-Checklist](https://github.com/0xRadi/OWASP-Web-Checklist)

- Threat modeling tools:  
  [OWASP/threat-dragon](https://github.com/OWASP/threat-dragon)  
  [awslabs/threat-composer](https://github.com/awslabs/threat-composer)

- Python SAST scanner:  
  [PyCQA/bandit](https://github.com/PyCQA/bandit)

- SARIF viewer fork:  
  [AperExanimus/neurowall-sarifviewer](https://github.com/AperExanimus/neurowall-sarifviewer)

---

## Limitations

- Scripts are experimental and may not provide exhaustive coverage.
- Automated checks do not replace manual verification.
- Threat models become stale if not updated with architecture changes.
- Some findings may be false positives and require analyst review.

---

## Legal and Ethical Notice

Use these scripts **only** on systems and applications you own or are explicitly authorized to test.  
Unauthorized testing may violate laws, policies, and terms of service.

---

## Contributing

Contributions are welcome. Suggested contribution areas:

- Additional checklist mappings
- Improved script reliability and safety checks
- Better reporting formats and SARIF enrichment
- Expanded documentation and reproducible workflows

If contributing, include:
- Clear reproduction steps
- Expected vs actual behavior
- Sample output (sanitized)

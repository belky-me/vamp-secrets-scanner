<h1 align="center">vamp-secrets-scanner</h1>
<p align="center">
  <strong>Static secrets and credential scanner with Git history analysis and SARIF export</strong><br>
  <em>VampSecure Labs · Security Research Division</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey?style=flat-square">
  <img src="https://img.shields.io/badge/license-research%20only-red?style=flat-square">
  <img src="https://img.shields.io/badge/VampSecure-Labs-8B0000?style=flat-square">
</p>

---

## Overview

`vamp-secrets-scanner` is a static analysis tool that detects hardcoded secrets, credentials, and sensitive data across source code repositories, configuration files, and directory trees. It combines a database of 80+ regex patterns covering cloud keys, payment tokens, PKI material, and PII with Shannon entropy analysis to surface high-entropy strings that elude pattern matching. A dedicated Git history scanner surfaces secrets that were removed from the working tree but remain reachable in commit history.

Designed for pre-deployment code reviews, penetration testing engagements, and CI/CD pipeline integration. All analysis is fully local — no data leaves the machine.

## Features

- **80+ secret patterns** across cloud providers (AWS, GCP, Azure), VCS tokens (GitHub PAT, GitLab PAT), payment gateways (Stripe, PayPal, Braintree), messaging platforms (Slack, Telegram, Discord, Twilio), database DSNs, JWT secrets, PEM private keys, and WireGuard private keys
- **PII detection** for credit/debit card PANs (Visa, Mastercard, Amex, Discover), IBAN/BIC, CVV codes, US SSN, Spanish DNI/NIE/CIF/NUSS, and NHS numbers
- **Shannon entropy analysis** on assignment-context strings — catches generated secrets with no known format (configurable threshold, default 4.5 bits/symbol)
- **Git history scanning** — walks all commits across all branches, including deleted content, via `git log --all` + per-commit diffs
- **Four-tier severity model**: CRITICAL / HIGH / MEDIUM / LOW with deduplication by SHA-256 fingerprint
- **Allowlist support** to suppress known false positives by fingerprint, pattern name, or file prefix; also generates baseline allowlist JSON from current findings
- **SARIF 2.1.0 export** for direct integration with GitHub Advanced Security and VS Code SARIF Viewer
- **Dark-theme HTML report** — standalone, zero external dependencies, collapsible context rows per finding
- **Pre-commit hook installer** — blocks commits when MEDIUM+ findings are detected
- **Semgrep rule export** — converts the full pattern database to a Semgrep-compatible YAML ruleset
- **Unified VSL client report** (HTML/PDF) via the shared `vampsec_report` module

## Requirements

```
pip install -r requirements.txt
```

Runtime dependencies:

| Package | Version |
|---------|---------|
| `rich`  | >= 13.7.0 |

Standard library only beyond `rich`: `re`, `os`, `math`, `pathlib`, `hashlib`, `json`, `argparse`, `subprocess`.

## Installation

```bash
git clone https://github.com/belky-me/vamp-secrets-scanner.git
cd vamp-secrets-scanner
pip install -r requirements.txt
```

## Usage

```bash
python vamp_secrets_scanner.py --help
```

```
usage: vamp-secrets-scanner [-h] [-o FICHERO] [--html FICHERO] [--sarif FICHERO]
                             [--min-severity {CRITICAL,HIGH,MEDIUM,LOW}] [--only-critical]
                             [--all-extensions] [--max-depth N] [--no-entropy]
                             [--entropy-threshold BITS] [--exclude-dir DIR]
                             [--git-history] [--max-commits N]
                             [--allowlist FICHERO] [--generate-allowlist FICHERO]
                             [--install-hook] [--export-semgrep FICHERO]
                             DIRECTORIO
```

### Examples

**Scan the current directory (all severities):**
```bash
python vamp_secrets_scanner.py .
```

**Scan a repository including full Git commit history:**
```bash
python vamp_secrets_scanner.py /path/to/repo --git-history
```

**Report only CRITICAL and HIGH findings, export SARIF for GitHub Actions:**
```bash
python vamp_secrets_scanner.py . --min-severity HIGH --sarif results.sarif
```

**Generate a baseline allowlist to suppress known false positives in CI:**
```bash
python vamp_secrets_scanner.py . --generate-allowlist baseline.json
```

**Apply allowlist, export JSON and standalone HTML report:**
```bash
python vamp_secrets_scanner.py . --allowlist baseline.json -o findings.json --html report.html
```

**Limit Git history scan to the 100 most recent commits:**
```bash
python vamp_secrets_scanner.py . --git-history --max-commits 100
```

**Install a pre-commit hook that blocks commits on MEDIUM+ findings:**
```bash
python vamp_secrets_scanner.py . --install-hook
```

**Export all patterns as a Semgrep YAML ruleset:**
```bash
python vamp_secrets_scanner.py . --export-semgrep vampsec_rules.yaml
```

**Scan only CRITICAL findings, raising entropy threshold to reduce noise:**
```bash
python vamp_secrets_scanner.py . --only-critical --entropy-threshold 5.2
```

## Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| Console (Rich) | _(default)_ | Colored table + detailed panels for CRITICAL findings |
| JSON | `-o FILE` | Structured findings with summary counts, full context, and Git metadata |
| HTML | `--html FILE` | Dark-theme standalone report; rows expand to show source context |
| SARIF 2.1.0 | `--sarif FILE` | Compatible with GitHub Advanced Security, VS Code SARIF Viewer |
| Semgrep YAML | `--export-semgrep FILE` | Importable ruleset: `semgrep --config FILE DIR` |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No findings at the selected severity level |
| `1` | One or more HIGH findings detected |
| `2` | One or more CRITICAL findings detected |
| `130` | Interrupted by user (Ctrl+C) |

## Part of VampSecure Labs Toolkit

This tool is part of the **VampSecure Labs Security Toolkit** — a collection of research-grade security tools for authorized penetration testing and red/blue team exercises.

- Full toolkit: [github.com/belky-me](https://github.com/belky-me)
- Orchestrator: [github.com/belky-me/vamp-orchestrator](https://github.com/belky-me/vamp-orchestrator)

---

© VampSecure Studios — VampSecure Labs Security Research Division  
For authorized security testing only.

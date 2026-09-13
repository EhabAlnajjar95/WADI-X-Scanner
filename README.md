# WADI-X Security Scanner Orchestrator (v3.1.0)

<p align="center">
  <b>Automated Multi-Tool Security Assessment, Fingerprinting & Reconnaissance Framework</b><br>
  Developed by <b>WADI-X Team</b>
</p>

---

> [!WARNING]
> **Legal & Ethical Disclaimer**: This tool is designed strictly for authorized penetration testing, security auditing, and educational purposes on systems you own or have explicit, written permission to test. Unauthorized scanning or attacking of remote targets is strictly illegal.

---

## 🚀 Key Features

- **Adaptive Smart Scan Mode**: Probes the target web stack using `whatweb` fingerprinting and automatically adapts the scanning pipeline (e.g., triggering `wpscan` and WordPress CVE templates only if WordPress is detected, `droopescan` if Drupal is detected, `testssl` for HTTPS, `nikto` for web servers, etc.).
- **Robust Multi-Profile Orchestration**:
  - **`Smart Scan` (`-p smart`)**: Technology-aware, context-sensitive automated scanning.
  - **`Fast Scan` (`-p fast`)**: Rapid reconnaissance and high-priority vulnerability detection.
  - **`Full Scan` (`-p full`)**: Comprehensive auditing across all integrated modules.
  - **`Custom Scan` (`-p custom --tools ...`)**: Hand-pick specific modules.
- **Unified Tri-Format Reporting**:
  - 📄 **`REPORT.md`**: Executive summary, severity breakdowns, finding details, and raw logs.
  - 📊 **`report.json`**: Machine-readable structured JSON format for CI/CD and SIEM ingestion.
  - 🌐 **`report.html`**: Self-contained, responsive offline dark-mode HTML dashboard with metrics and cards.
- **Automated Tool Dependency & Version Checker**:
  - Detects installed binary versions for all 12 tools (`--list-tools`).
  - Automated package installer via `apt`, `pipx`, `go`, or `gem`.
- **Hardened Subprocess Layer**:
  - Command-injection-resistant execution (never `shell=True`).
  - Configurable execution timeouts per module.
  - Graceful interrupt handling (`Ctrl+C` preserves completed findings and generates partial reports).
  - Dry-run simulation mode (`--dry-run`).
- **Target Normalization & Input Validation**:
  - Robust URL, domain, IPv4, IPv6 parsing and sanitization.
  - Safe timestamped output folders.
- **Built-in Fallback Wordlists**:
  - Ships with `wordlists/common.txt` for directory discovery on systems lacking standard wordlists.

---

## 🛠️ Integrated Security Modules

| # | Tool | Purpose | Primary Output |
|---|------|---------|----------------|
| 1 | **nmap** | Port & service discovery with banner grabbing (`-sV -sC`) | `nmap.txt` |
| 2 | **whatweb** | Next-generation web stack fingerprinting & CMS detection | `whatweb.txt` |
| 3 | **testssl.sh** | Deep SSL/TLS cipher, certificate, and protocol audit | `testssl.txt` |
| 4 | **gobuster** | High-speed directory and sensitive file brute-forcing | `gobuster.txt` |
| 5 | **droopescan** | Drupal & Silverstripe CMS vulnerability scanner | `droopescan.txt` |
| 6 | **nuclei** (Fast) | Exposure, misconfiguration & high/critical CVE scanner | `nuclei.txt` / `.json` |
| 7 | **nuclei** (Full) | Comprehensive multi-template vulnerability scanner | `nuclei_full.txt` |
| 8 | **nikto** | Web server misconfiguration and dangerous file audit | `nikto.txt` |
| 9 | **wpscan** | WordPress user, plugin, and theme vulnerability audit | `wpscan.txt` |
| 10 | **ffuf** | High-speed web fuzzer and endpoint tester | `ffuf.txt` |
| 11 | **subfinder** | Fast passive subdomain enumeration | `subfinder.txt` |
| 12 | **amass** | In-depth attack surface mapping and network discovery | `amass.txt` |

---

## 📋 Requirements & Supported Environments

- **Operating System**: Linux (Kali Linux, Parrot OS, Ubuntu, Debian recommended)
- **Python**: 3.8 or higher
- **Sudo / Root privileges**: Required if automated tool installation is enabled

---

## ⚡ Quick Start & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/WADI-X-Team/WADI-X-Scanner.git
cd WADI-X-Scanner
```

### 2. Set Permissions
```bash
chmod +x wadix.py
```

### 3. Check Available Tools
Inspect your system to see which tools are currently installed and detect their versions:
```bash
python3 wadix.py --list-tools
```

---

## 🎮 Usage Guide

### Mode A: Interactive Mode (Terminal Menu)
Simply run the script without arguments to open the interactive guided menu:
```bash
python3 wadix.py
```
1. Automatic verification of required tools (prompting auto-install if missing).
2. Confirmation of legal authorization.
3. Input target domain/IP (e.g. `example.com`).
4. Select profile:
   - `[S] Smart Scan` (Adaptive stack analysis)
   - `[B] Fast Scan` (Quick essentials)
   - `[A] Full Scan` (All 12 modules)
   - `[C] Custom Scan` (Numbered selection: `1,3,6` or `1-5` or `all`)

---

### Mode B: CLI Automation Mode (Non-Interactive)
Ideal for scripted pipelines, automation, or CI/CD:

#### 1. Adaptive Smart Scan
```bash
python3 wadix.py -t https://example.com -p smart -y
```

#### 2. Fast Scan
```bash
python3 wadix.py -t https://example.com -p fast -y
```

#### 3. Custom Tools Selection
```bash
python3 wadix.py -t https://example.com -p custom --tools nmap,whatweb,nuclei -y
```

#### 4. Safe Dry-Run (Simulation Mode)
Verify the pipeline and report generation without sending network packets:
```bash
python3 wadix.py -t https://example.com -p smart --dry-run -y
```

#### 5. Custom Output Directory and Timeout
```bash
python3 wadix.py -t https://example.com -p smart -o my_scan_results --timeout 300 -y
```

---

## 📁 Output Directory & Report Structure

Each scan creates a clean directory containing structured reports and raw logs:
```text
wadix_scan_<target>_<timestamp>/
├── REPORT.md          # Comprehensive executive & technical Markdown report
├── report.json        # Machine-readable structured findings (JSON)
├── report.html        # Interactive offline HTML security dashboard
├── nmap.txt           # Raw Nmap output
├── whatweb.txt        # Raw WhatWeb output
├── nuclei.txt         # Raw Nuclei text output
├── nuclei.json        # Nuclei structured finding logs
├── testssl.txt        # Raw SSL/TLS test results
├── gobuster.txt       # Discovered endpoints
└── ...
```

### Viewing Reports:
```bash
# View summary in terminal
cat wadix_scan_<target>_<timestamp>/REPORT.md

# Open offline HTML dashboard in browser
firefox wadix_scan_<target>_<timestamp>/report.html
```

---

## 🧪 Running Automated Unit Tests

WADI-X includes a built-in test suite covering target normalization, command execution, reporting generation, and smart scan logic:
```bash
python3 -m unittest discover -s tests
```

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).
<br>
Developed by **WADI-X Team** • Stay Legal. Stay Ethical.

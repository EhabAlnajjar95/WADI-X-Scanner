# WADI-X Security Scanner Orchestrator (v3.0)

<p align="center">
  <b>Automated Security Scanning & Reconnaissance Framework</b><br>
  Developed by <b>WADI-X</b>
</p>

---

> [!WARNING]
> **Legal & Ethical Disclaimer**: This tool is designed strictly for authorized penetration testing, security auditing, and educational purposes on systems you own or have explicit, written permission to test. Unauthorized scanning or attacking of remote targets is illegal.

---

## 🚀 Features

- **Automated Tool Dependency Checker & Installer**: Automatically verifies and installs missing tools via `apt`, `pipx`, `go`, or `gem`.
- **Pre-flight Legal Authorization Verification**: Strict confirmation prompt before scanning.
- **Interactive Scan Modes**:
  - **Full Scan**: Comprehensive multi-tool scanning.
  - **Fast Scan**: Quick reconnaissance and critical vulnerability scan.
  - **Custom Scan**: Tailored tool selection (e.g., `1,3,5` or `1-4` or `all`).
- **Integrated Security Tools**:
  1. `nmap` — Port & service scanning
  2. `whatweb` — Web technology fingerprinting
  3. `testssl.sh` — SSL/TLS cipher and certificate auditing
  4. `gobuster` — Fast directory and file brute-forcing
  5. `droopescan` — CMS vulnerability scanner (Drupal/Silverstripe)
  6. `nuclei` (Fast) — Vulnerability scanning targeting misconfigurations & exposures
  7. `nuclei` (Full) — Deep vulnerability scanning
  8. `nikto` — Comprehensive web server misconfiguration scanning
  9. `wpscan` — WordPress security auditing
  10. `ffuf` — High-speed web fuzzing
  11. `subfinder` — Passive subdomain enumeration
  12. `amass` — In-depth subdomain and network mapping
- **Automated Markdown Reporting**: Produces clean, readable `REPORT.md` summaries with tool outputs and timestamped directories.

---

## 📋 Requirements & Supported OS

- **OS**: Linux (Kali Linux, Ubuntu, Debian recommended)
- **Python**: 3.8+
- Root / Sudo privileges (for automatic package installation)

---

## ⚡ Quick Start & Installation Guide

Follow these simple steps to set up and run the scanner on your Linux machine (Kali Linux, Parrot OS, Ubuntu, Debian):

### 1. Prerequisites
Make sure `git` and `python3` are installed:
```bash
sudo apt update && sudo apt install -y git python3
```

---

### 2. Clone the Repository
Download the project source code to your machine:
```bash
git clone https://github.com/EhabAlnajjar95/WADI-X-Scanner.git
```

---

### 3. Navigate into the Directory
Move into the project folder:
```bash
cd WADI-X-Scanner
```

---

### 4. Set Execution Permissions (Optional but Recommended)
Grant executable permissions to the main script:
```bash
chmod +x wadix.py
```

---

### 5. Launch the Scanner
Run the orchestrator with Python 3:
```bash
python3 wadix.py
```
*(Or `./wadix.py` if made executable)*

---

### 📖 Step-by-Step Runtime Walkthrough

Once launched, the interactive assistant will guide you through the process:

#### Step 1: Automatic Tool Verification & Installation
- The scanner will scan your system for required tools (`nmap`, `whatweb`, `nuclei`, `testssl.sh`, `gobuster`, `droopescan`, `nikto`, `wpscan`, `ffuf`, `subfinder`, `amass`).
- If any tool is missing, it will ask:
  ```text
  Install missing tools automatically? (yes/no):
  ```
  Type `yes` or `y` to have the script auto-install them via `apt`, `pipx`, `go`, or `gem`.

#### Step 2: Legal Authorization Check
- Confirm that you have legal permission to test the target system:
  ```text
  Confirm authorization (yes/no):
  ```
  Type `yes` or `y` to proceed.

#### Step 3: Enter Your Target
- Type the domain or IP address you want to scan:
  ```text
  Target URL: example.com
  ```
  *(If you don't enter `https://`, the script will automatically prepend it for you).*

#### Step 4: Choose Scan Mode
Select from three flexible scanning profiles:
- **`[A] Full Scan`**: Runs all 12 tools in sequence for deep reconnaissance (recommended for full audits).
- **`[B] Fast Scan`**: Runs essential reconnaissance tools (`nmap`, `whatweb`, `testssl`, `gobuster`, `nuclei`, `nikto`, `ffuf`, `subfinder`).
- **`[C] Custom Scan`**: Lets you hand-pick individual tools:
  - Single tool: `1`
  - Comma-separated: `1,3,6`
  - Range: `1-5`
  - All: `all`

#### Step 5: View Scan Reports
Once finished, an output directory named `wadix_scan_<target>_<timestamp>` is created with:
- Individual raw log files for each tool (`nmap.txt`, `nuclei.txt`, etc.).
- A unified Markdown report `REPORT.md`.
- View the report directly in terminal:
  ```bash
  cat wadix_scan_<target>_<timestamp>/REPORT.md
  ```
  Or open it in a browser / markdown viewer:
  ```bash
  firefox wadix_scan_<target>_<timestamp>/REPORT.md
  ```

---

## 📁 Output Structure

Scans automatically create a dedicated timestamped folder:
```text
wadix_scan_<target>_<timestamp>/
├── REPORT.md
├── nmap.txt
├── whatweb.txt
├── nuclei.txt
└── ...
```

---

## 📜 License

This project is released under the [MIT License](LICENSE).

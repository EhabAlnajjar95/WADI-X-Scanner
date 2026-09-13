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

## ⚡ Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/<YOUR_USERNAME>/<YOUR_REPO_NAME>.git
   cd <YOUR_REPO_NAME>
   ```

2. **Run the scanner:**
   ```bash
   python3 wadix.py
   ```

3. **Follow the interactive prompts:**
   - Confirm authorization.
   - Enter the target URL/host.
   - Choose scan mode (`A` Full, `B` Fast, `C` Custom).

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

#!/usr/bin/env python3
"""
WADI-X Security Scanner Orchestrator
Author : WADI-X
Version: 3.0

Auto-installs missing tools, interactive menu, full/fast scan options.
Use ONLY on systems you own or have written authorization to test.
"""

import subprocess
import os
import sys
import shutil
from datetime import datetime


# ============================================================
#                     ANSI COLOR CODES
# ============================================================
class C:
    RESET    = "\033[0m"
    BOLD     = "\033[1m"
    DIM      = "\033[2m"
    RED      = "\033[31m"
    GREEN    = "\033[32m"
    YELLOW   = "\033[33m"
    BLUE     = "\033[34m"
    MAGENTA  = "\033[35m"
    CYAN     = "\033[36m"
    WHITE    = "\033[37m"
    BRED     = "\033[91m"
    BGREEN   = "\033[92m"
    BYELLOW  = "\033[93m"
    BBLUE    = "\033[94m"
    BMAGENTA = "\033[95m"
    BCYAN    = "\033[96m"
    BWHITE   = "\033[97m"


# ============================================================
#                     CONFIGURATION
# ============================================================
AUTHOR       = "WADI-X"
VERSION      = "3.0"
TARGET       = None
OUTPUT_DIR   = None

TESTSSL_PATH = os.path.expanduser("~/testssl.sh/testssl.sh")
COMMON_DIRB  = "/usr/share/wordlists/dirb/common.txt"
COMMON_DIRB2 = "/usr/share/wordlists/dirb/big.txt"


# ============================================================
#                     BANNER
# ============================================================
def banner():
    line = f"{C.BCYAN}{'═' * 62}{C.RESET}"
    print()
    print(line)
    print(f"{C.BMAGENTA}{C.BOLD}  ██╗    ██╗ █████╗ ██████╗ ██╗       ██╗  ██╗{C.RESET}")
    print(f"{C.BMAGENTA}{C.BOLD}  ██║    ██║██╔══██╗██╔══██╗██║       ╚██╗██╔╝{C.RESET}")
    print(f"{C.BMAGENTA}{C.BOLD}  ██║ █╗ ██║███████║██║  ██║██║        ╚███╔╝ {C.RESET}")
    print(f"{C.BMAGENTA}{C.BOLD}  ██║███╗██║██╔══██║██║  ██║██║        ██╔██╗ {C.RESET}")
    print(f"{C.BMAGENTA}{C.BOLD}  ╚███╔███╔╝██║  ██║██████╔╝███████╗  ██╔╝ ██╗{C.RESET}")
    print(f"{C.BMAGENTA}{C.BOLD}   ╚══╝╚══╝ ╚═╝  ╚═╝╚═════╝ ╚══════╝  ╚═╝  ╚═╝{C.RESET}")
    print()
    print(f"{C.BCYAN}{C.BOLD}              WADI-X Security Scanner{C.RESET}")
    print(f"{C.BWHITE}              Author : {C.BYELLOW}{AUTHOR}{C.RESET}")
    print(f"{C.BWHITE}              Version: {C.BGREEN}{VERSION}{C.RESET}")
    print(f"{C.BWHITE}              Date   : {C.BCYAN}{datetime.now().strftime('%Y-%m-%d %H:%M')}{C.RESET}")
    print(line)
    print()


# ============================================================
#                     HELPERS
# ============================================================
def info(msg):    print(f"{C.BCYAN}[*]{C.RESET} {msg}")
def ok(msg):      print(f"{C.BGREEN}[+]{C.RESET} {msg}")
def warn(msg):    print(f"{C.BYELLOW}[!]{C.RESET} {msg}")
def error(msg):   print(f"{C.BRED}[-]{C.RESET} {msg}")
def running(msg): print(f"{C.BBLUE}[>]{C.RESET} {msg}")
def done(msg):    print(f"{C.BGREEN}[✓]{C.RESET} {msg}")


def section(title):
    print()
    print(f"{C.BCYAN}{'─' * 62}{C.RESET}")
    print(f"{C.BWHITE}{C.BOLD}  {title}{C.RESET}")
    print(f"{C.BCYAN}{'─' * 62}{C.RESET}")


# ============================================================
#                     AUTO-INSTALLER
# ============================================================
# Tool installation definitions
# Format: tool_name -> {
#   "check": command to check if installed,
#   "apt": apt package name (if available),
#   "pipx": pipx package name (if available),
#   "go": go package path (if available),
#   "gem": gem package name (if available),
#   "special": special install function name (if needed)
# }

TOOL_INSTALL = {
    "nmap": {
        "check": "nmap",
        "apt": "nmap",
    },
    "whatweb": {
        "check": "whatweb",
        "apt": "whatweb",
    },
    "testssl": {
        "check": TESTSSL_PATH,
        "apt": None,
        "special": "install_testssl",
    },
    "gobuster": {
        "check": "gobuster",
        "apt": "gobuster",
    },
    "droopescan": {
        "check": "droopescan",
        "apt": None,
        "pipx": "droopescan",
    },
    "nuclei": {
        "check": "nuclei",
        "apt": "nuclei",
    },
    "nikto": {
        "check": "nikto",
        "apt": "nikto",
    },
    "wpscan": {
        "check": "wpscan",
        "apt": "wpscan",
    },
    "ffuf": {
        "check": "ffuf",
        "apt": "ffuf",
    },
    "subfinder": {
        "check": "subfinder",
        "apt": "subfinder",
    },
    "amass": {
        "check": "amass",
        "apt": "amass",
    },
}


def is_installed(tool_name):
    """Check if a tool is installed and available in PATH"""
    tool_info = TOOL_INSTALL.get(tool_name)
    if not tool_info:
        return False

    check = tool_info["check"]
    if os.path.isabs(check):
        return os.path.exists(check)
    return shutil.which(check) is not None


def install_via_apt(package):
    """Install a package via apt"""
    running(f"Installing {package} via apt...")
    cmd = ["sudo", "apt", "install", "-y", package]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        done(f"{package} installed via apt")
        return True
    error(f"Failed to install {package} via apt")
    if result.stderr:
        print(f"    {C.DIM}{result.stderr[:200]}{C.RESET}")
    return False


def install_via_pipx(package):
    """Install a package via pipx"""
    running(f"Installing {package} via pipx...")
    # Check if pipx is installed
    if not shutil.which("pipx"):
        warn("pipx not found. Installing pipx...")
        subprocess.run(["sudo", "apt", "install", "-y", "pipx"], capture_output=True)
    cmd = ["pipx", "install", package]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        done(f"{package} installed via pipx")
        return True
    error(f"Failed to install {package} via pipx")
    return False


def install_via_go(package):
    """Install a package via go install"""
    running(f"Installing {package} via go...")
    if not shutil.which("go"):
        warn("Go not found. Installing Go...")
        subprocess.run(["sudo", "apt", "install", "-y", "golang-go"], capture_output=True)
    cmd = ["go", "install", "-v", package]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        done(f"{package} installed via go")
        return True
    error(f"Failed to install {package} via go")
    return False


def install_via_gem(package):
    """Install a package via gem"""
    running(f"Installing {package} via gem...")
    if not shutil.which("gem"):
        warn("gem not found. Installing Ruby...")
        subprocess.run(["sudo", "apt", "install", "-y", "ruby-full"], capture_output=True)
    cmd = ["sudo", "gem", "install", package]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        done(f"{package} installed via gem")
        return True
    error(f"Failed to install {package} via gem")
    return False


def install_testssl():
    """Special install for testssl.sh"""
    running("Cloning testssl.sh from GitHub...")
    home = os.path.expanduser("~")
    target_dir = os.path.join(home, "testssl.sh")

    if os.path.exists(target_dir):
        warn("testssl.sh directory already exists")
        return True

    cmd = ["git", "clone", "--depth", "1",
           "https://github.com/drwetter/testssl.sh.git", target_dir]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        # Make executable
        subprocess.run(["chmod", "+x", os.path.join(target_dir, "testssl.sh")])
        done(f"testssl.sh installed at {target_dir}")
        return True
    error("Failed to clone testssl.sh")
    return False


def install_tool(tool_name):
    """Try to install a tool using available methods"""
    tool_info = TOOL_INSTALL.get(tool_name)
    if not tool_info:
        error(f"Unknown tool: {tool_name}")
        return False

    # Special install
    if tool_info.get("special"):
        func_name = tool_info["special"]
        if func_name == "install_testssl":
            return install_testssl()

    # Try apt first
    if tool_info.get("apt"):
        if install_via_apt(tool_info["apt"]):
            return True

    # Try pipx
    if tool_info.get("pipx"):
        if install_via_pipx(tool_info["pipx"]):
            return True

    # Try go
    if tool_info.get("go"):
        if install_via_go(tool_info["go"]):
            return True

    # Try gem
    if tool_info.get("gem"):
        if install_via_gem(tool_info["gem"]):
            return True

    error(f"All installation methods failed for {tool_name}")
    return False


def check_and_install_tools():
    """Check all tools and install missing ones"""
    section("CHECKING REQUIRED TOOLS")

    missing = []
    for tool_name in TOOL_INSTALL:
        if is_installed(tool_name):
            done(f"{tool_name:<12} — installed")
        else:
            warn(f"{tool_name:<12} — MISSING")
            missing.append(tool_name)

    if not missing:
        ok("All tools are already installed!")
        return True

    print()
    info(f"Missing tools: {', '.join(missing)}")
    answer = input(f"{C.BYELLOW}Install missing tools automatically? (yes/no): {C.RESET}").strip().lower()

    if answer not in ("yes", "y"):
        warn("Skipping installation. Some tools may not work.")
        return False

    section("INSTALLING MISSING TOOLS")
    failed = []
    for tool_name in missing:
        print()
        if not install_tool(tool_name):
            failed.append(tool_name)

    print()
    if failed:
        warn(f"Failed to install: {', '.join(failed)}")
        return False

    ok("All tools installed successfully!")
    return True


# ============================================================
#                     AUTHORIZATION
# ============================================================
def confirm_authorization():
    section("LEGAL AUTHORIZATION CHECK")
    print(f"{C.BYELLOW}This tool scans target systems.{C.RESET}")
    print(f"{C.BYELLOW}You MUST either:{C.RESET}")
    print(f"  {C.BWHITE}1.{C.RESET} Own the target system, OR")
    print(f"  {C.BWHITE}2.{C.RESET} Have written authorization to test it.")
    print()
    answer = input(f"{C.BCYAN}Confirm authorization (yes/no): {C.RESET}").strip().lower()
    if answer not in ("yes", "y"):
        error("Scan aborted. Authorization not confirmed.")
        sys.exit(1)
    ok("Authorization confirmed. Proceeding...")
    print()


# ============================================================
#                     TARGET
# ============================================================
def ask_target():
    section("SELECT TARGET")
    print(f"{C.BYELLOW}Enter the target URL you own or have written authorization to test.{C.RESET}")
    print()

    while True:
        target = input(f"{C.BCYAN}Target URL : {C.RESET}").strip()

        if not target:
            error("Target cannot be empty. Try again.")
            continue

        if not target.startswith(("http://", "https://")):
            warn("No scheme detected. Adding https:// automatically.")
            target = "https://" + target

        print()
        print(f"{C.BWHITE}  Target : {C.BCYAN}{target}{C.RESET}")
        confirm = input(f"{C.BYELLOW}  Is this correct? (yes/no): {C.RESET}").strip().lower()

        if confirm in ("yes", "y"):
            ok(f"Target confirmed: {target}")
            print()
            return target
        else:
            print(f"{C.BYELLOW}Let's try again.{C.RESET}\n")


# ============================================================
#                     TOOL RUNNERS
# ============================================================
def run_nmap(target, outdir):
    running("nmap — port & service scan...")
    output = f"{outdir}/nmap.txt"
    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    subprocess.run(["nmap", "-sV", "-sC", "-oN", output, host],
                   capture_output=True, text=True)
    done(f"nmap -> {output}")
    return output


def run_whatweb(target, outdir):
    running("whatweb — technology fingerprinting...")
    output = f"{outdir}/whatweb.txt"
    subprocess.run(["whatweb", "--log-brief", output, target],
                   capture_output=True, text=True)
    done(f"whatweb -> {output}")
    return output


def run_testssl(target, outdir):
    running("testssl.sh — SSL/TLS scan...")
    output = f"{outdir}/testssl.txt"

    if not os.path.exists(TESTSSL_PATH):
        error(f"testssl.sh not found at {TESTSSL_PATH}")
        return None

    result = subprocess.run([TESTSSL_PATH, "--quiet", "--color", "0", target],
                            capture_output=True, text=True)
    with open(output, "w") as f:
        f.write(result.stdout)
    done(f"testssl -> {output}")
    return output


def run_nuclei(target, outdir):
    running("nuclei — Drupal-focused scan...")
    output = f"{outdir}/nuclei.txt"
    cmd = ["nuclei", "-u", target, "-o", output, "-silent",
           "-tags", "drupal,exposure,misconfiguration",
           "-severity", "medium,high,critical",
           "-timeout", "5", "-retries", "1",
           "-rate-limit", "150", "-c", "25"]
    subprocess.run(cmd, capture_output=True, text=True)
    done(f"nuclei -> {output}")
    return output


def run_nuclei_full(target, outdir):
    running("nuclei — FULL scan (slow)...")
    output = f"{outdir}/nuclei_full.txt"
    cmd = ["nuclei", "-u", target, "-o", output, "-silent",
           "-severity", "low,medium,high,critical",
           "-rate-limit", "200", "-bulk-size", "50", "-c", "50",
           "-timeout", "5", "-retries", "1",
           "-exclude-tags", "fuzz,brute-force"]
    subprocess.run(cmd, capture_output=True, text=True)
    done(f"nuclei full -> {output}")
    return output


def run_gobuster(target, outdir):
    running("gobuster — directory discovery...")
    output = f"{outdir}/gobuster.txt"
    cmd = ["gobuster", "dir", "-u", target, "-w", COMMON_DIRB,
           "-o", output, "-q", "-t", "10"]
    subprocess.run(cmd, capture_output=True, text=True)
    done(f"gobuster -> {output}")
    return output


def run_droopescan(target, outdir):
    running("droopescan — Drupal scan...")
    output = f"{outdir}/droopescan.txt"
    result = subprocess.run(["droopescan", "scan", "drupal", "-u", target],
                            capture_output=True, text=True)
    with open(output, "w") as f:
        f.write(result.stdout)
    done(f"droopescan -> {output}")
    return output


def run_nikto(target, outdir):
    running("nikto — web server scan...")
    output = f"{outdir}/nikto.txt"
    subprocess.run(["nikto", "-h", target, "-o", output,
                    "-Format", "txt", "-nointeractive"],
                   capture_output=True, text=True)
    done(f"nikto -> {output}")
    return output


def run_wpscan(target, outdir):
    running("wpscan — WordPress scan...")
    output = f"{outdir}/wpscan.txt"
    cmd = ["wpscan", "--url", target,
           "--enumerate", "vp,vt,u",
           "--format", "cli-no-color",
           "--no-banner",
           "--output", output,
           "--disable-tls-checks"]
    subprocess.run(cmd, capture_output=True, text=True)
    done(f"wpscan -> {output}")
    return output


def run_ffuf(target, outdir):
    running("ffuf — advanced fuzzing...")
    output = f"{outdir}/ffuf.txt"
    wordlist = COMMON_DIRB if os.path.exists(COMMON_DIRB) else COMMON_DIRB2
    url_with_fuzz = target.rstrip("/") + "/FUZZ"
    cmd = ["ffuf", "-u", url_with_fuzz, "-w", wordlist,
           "-o", output, "-of", "text",
           "-mc", "200,204,301,302,307,401,403,500",
           "-t", "50", "-s"]
    subprocess.run(cmd, capture_output=True, text=True)
    done(f"ffuf -> {output}")
    return output


def run_subfinder(target, outdir):
    running("subfinder — subdomain enumeration...")
    output = f"{outdir}/subfinder.txt"
    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    subprocess.run(["subfinder", "-d", host, "-o", output, "-silent"],
                   capture_output=True, text=True)
    done(f"subfinder -> {output}")
    return output


def run_amass(target, outdir):
    running("amass — advanced enumeration...")
    output = f"{outdir}/amass.txt"
    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    subprocess.run(["amass", "enum", "-d", host, "-o", output, "-timeout", "10"],
                   capture_output=True, text=True)
    done(f"amass -> {output}")
    return output


# ============================================================
#                     REPORT GENERATOR
# ============================================================
def generate_report(outdir, results, target):
    running("Generating Markdown report...")
    report_path = f"{outdir}/REPORT.md"

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("# WADI-X Security Assessment Report\n\n")
        f.write(f"**Author:**  {AUTHOR}\n\n")
        f.write(f"**Version:** {VERSION}\n\n")
        f.write(f"**Date:**    {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n")
        f.write(f"**Target:**  {target}\n\n")
        f.write("---\n\n")

        f.write("## Scan Summary\n\n")
        f.write("| Tool | Output File | Status |\n")
        f.write("|------|-------------|--------|\n")
        for tool, path in results.items():
            if path is None:
                f.write(f"| {tool} | — | FAILED |\n")
            else:
                exists = "OK" if os.path.exists(path) else "MISSING"
                f.write(f"| {tool} | `{path}` | {exists} |\n")

        f.write("\n---\n\n")
        f.write("## Detailed Results\n\n")

        for tool, path in results.items():
            f.write(f"### {tool}\n\n")
            if path and os.path.exists(path):
                with open(path, "r", encoding="utf-8", errors="ignore") as rf:
                    content = rf.read()
                    f.write("```\n")
                    f.write(content[:5000])
                    if len(content) > 5000:
                        f.write("\n... (see full file for complete output)\n")
                    f.write("```\n\n")
            else:
                f.write("File not generated.\n\n")

    done(f"Report -> {report_path}")
    return report_path


# ============================================================
#                     TOOLS MENU
# ============================================================
TOOLS = {
    "1":  ("nmap",         run_nmap,         "Port & service scan"),
    "2":  ("whatweb",      run_whatweb,      "Technology fingerprinting"),
    "3":  ("testssl",      run_testssl,      "SSL/TLS scan"),
    "4":  ("gobuster",     run_gobuster,     "Directory discovery"),
    "5":  ("droopescan",   run_droopescan,   "Drupal scan"),
    "6":  ("nuclei",       run_nuclei,       "Vulnerability scan (fast)"),
    "7":  ("nuclei_full",  run_nuclei_full,  "Vulnerability scan (FULL)"),
    "8":  ("nikto",        run_nikto,        "Web server scan"),
    "9":  ("wpscan",       run_wpscan,       "WordPress scan"),
    "10": ("ffuf",         run_ffuf,         "Advanced fuzzing"),
    "11": ("subfinder",    run_subfinder,    "Subdomain enumeration"),
    "12": ("amass",        run_amass,        "Advanced enumeration"),
}


def show_menu():
    section("SELECT SCAN MODE")
    print(f"{C.BWHITE}  {C.BGREEN}[A]{C.RESET} {C.BWHITE}Full Scan{C.RESET}       — All tools (slow, complete)")
    print(f"{C.BWHITE}  {C.BBLUE}[B]{C.RESET} {C.BWHITE}Fast Scan{C.RESET}       — Essential tools only (quick)")
    print(f"{C.BWHITE}  {C.BYELLOW}[C]{C.RESET} {C.BWHITE}Custom Scan{C.RESET}     — Choose specific tools")
    print(f"{C.BWHITE}  {C.BRED}[Q]{C.RESET} {C.BWHITE}Quit{C.RESET}")
    print()


def show_tools_menu():
    section("SELECT TOOLS")
    print(f"{C.BWHITE}Available tools:{C.RESET}\n")

    for key, (name, _, desc) in TOOLS.items():
        print(f"  {C.BCYAN}{key:>2}{C.RESET}. {C.BWHITE}{name:<12}{C.RESET} — {C.DIM}{desc}{C.RESET}")

    print()
    print(f"{C.BYELLOW}Selection syntax:{C.RESET}")
    print(f"  {C.BWHITE}1{C.RESET}         — Single tool")
    print(f"  {C.BWHITE}1,3,5{C.RESET}     — Multiple tools")
    print(f"  {C.BWHITE}1-5{C.RESET}       — Range")
    print(f"  {C.BWHITE}all{C.RESET}       — All tools")
    print()
    print(f"{C.DIM}{'─' * 62}{C.RESET}")


def parse_selection(selection):
    """Parse user selection into list of tool keys"""
    selection = selection.strip().lower()

    if not selection:
        return []

    if selection == "all":
        return list(TOOLS.keys())

    keys = []

    # Handle comma-separated and ranges
    parts = selection.replace(" ", "").split(",")
    for part in parts:
        if "-" in part and part.replace("-", "").isdigit():
            # Range like 1-5
            start, end = part.split("-")
            for i in range(int(start), int(end) + 1):
                if str(i) in TOOLS:
                    keys.append(str(i))
        elif part in TOOLS:
            keys.append(part)
        else:
            warn(f"Invalid tool key: {part}")

    # Remove duplicates while preserving order
    seen = set()
    unique_keys = []
    for k in keys:
        if k not in seen:
            seen.add(k)
            unique_keys.append(k)

    return unique_keys


def run_selected_scans(keys, target, outdir):
    """Run the selected tools"""
    results = {}
    total = len(keys)

    section(f"RUNNING {total} SCAN(S)")

    for i, key in enumerate(keys, 1):
        name, func, desc = TOOLS[key]
        print()
        print(f"{C.BCYAN}[{i}/{total}]{C.RESET} {C.BWHITE}{name}{C.RESET} — {C.DIM}{desc}{C.RESET}")

        try:
            results[name] = func(target, outdir)
        except Exception as e:
            error(f"{name} failed: {e}")
            results[name] = None

    return results


# ============================================================
#                     MAIN
# ============================================================
def main():
    global TARGET, OUTPUT_DIR

    banner()

    # 1. Check and install missing tools
    check_and_install_tools()

    # 2. Legal authorization
    confirm_authorization()

    # 3. Ask for target
    TARGET = ask_target()

    # 4. Build output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = TARGET.replace("https://", "").replace("http://", "")
    safe_name = safe_name.replace("/", "_").replace(":", "_")
    OUTPUT_DIR = f"wadix_scan_{safe_name}_{timestamp}"

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    info(f"Output directory: {OUTPUT_DIR}")

    # 5. Show scan mode menu
    show_menu()
    mode = input(f"{C.BCYAN}Select mode [A/B/C/Q]: {C.RESET}").strip().upper()

    if mode == "Q":
        warn("Scan aborted by user.")
        sys.exit(0)

    elif mode == "A":
        # Full scan
        info("Full scan selected — running ALL tools")
        keys = list(TOOLS.keys())

    elif mode == "B":
        # Fast scan
        info("Fast scan selected — running essential tools")
        keys = ["1", "2", "3", "4", "6", "8", "10", "11"]

    elif mode == "C":
        # Custom scan
        show_tools_menu()
        selection = input(f"{C.BCYAN}Your selection: {C.RESET}").strip()
        keys = parse_selection(selection)

        if not keys:
            error("No valid tools selected. Aborting.")
            sys.exit(1)

    else:
        error(f"Invalid mode: {mode}")
        sys.exit(1)

    # 6. Run selected scans
    results = run_selected_scans(keys, TARGET, OUTPUT_DIR)

    # 7. Generate report
    report = generate_report(OUTPUT_DIR, results, TARGET)

    # 8. Summary
    section("SCAN COMPLETE")
    print(f"{C.BGREEN}  ✅ All selected scans completed{C.RESET}")
    print(f"{C.BWHITE}  📁 Directory : {C.BCYAN}{OUTPUT_DIR}{C.RESET}")
    print(f"{C.BWHITE}  📄 Report    : {C.BCYAN}{report}{C.RESET}")
    print()
    print(f"{C.BYELLOW}  To view the report:{C.RESET}")
    print(f"    {C.BGREEN}cat {report}{C.RESET}")
    print(f"    {C.BGREEN}firefox {report}{C.RESET}")
    print()
    print(f"{C.BCYAN}{'═' * 62}{C.RESET}")
    print(f"{C.BMAGENTA}{C.BOLD}         WADI-X — Stay Legal. Stay Ethical.{C.RESET}")
    print(f"{C.BCYAN}{'═' * 62}{C.RESET}")
    print()


if __name__ == "__main__":
    main()

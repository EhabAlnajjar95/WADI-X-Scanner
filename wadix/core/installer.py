"""
Tool dependency verification, version detection, and auto-installation.
"""

import os
import shutil
import subprocess
import re
from typing import Dict, List, Optional, Tuple
from wadix.core.config import (
    C, TESTSSL_PATH, info, ok, warn, error, running, done, section, debug
)

# Registry of supported tools
TOOLS_REGISTRY = {
    "nmap": {
        "binary": "nmap",
        "apt": "nmap",
        "version_cmd": ["nmap", "-V"],
        "desc": "Port & service scanner",
    },
    "whatweb": {
        "binary": "whatweb",
        "apt": "whatweb",
        "version_cmd": ["whatweb", "--version"],
        "desc": "Next-gen web scanner & tech fingerprinting",
    },
    "testssl": {
        "binary": "testssl.sh",
        "custom_path": TESTSSL_PATH,
        "special": "install_testssl",
        "version_cmd": [TESTSSL_PATH, "--version"],
        "desc": "TLS/SSL cipher and protocol security scanner",
    },
    "gobuster": {
        "binary": "gobuster",
        "apt": "gobuster",
        "go": "github.com/OJ/gobuster/v3@latest",
        "version_cmd": ["gobuster", "version"],
        "desc": "Fast directory & DNS brute-forcing",
    },
    "droopescan": {
        "binary": "droopescan",
        "pipx": "droopescan",
        "version_cmd": ["droopescan", "--version"],
        "desc": "Drupal & Silverstripe CMS vulnerability scanner",
    },
    "nuclei": {
        "binary": "nuclei",
        "apt": "nuclei",
        "go": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "version_cmd": ["nuclei", "-version"],
        "desc": "Fast and customizable vulnerability scanner",
    },
    "nikto": {
        "binary": "nikto",
        "apt": "nikto",
        "version_cmd": ["nikto", "-Version"],
        "desc": "Comprehensive web server security scanner",
    },
    "wpscan": {
        "binary": "wpscan",
        "apt": "wpscan",
        "gem": "wpscan",
        "version_cmd": ["wpscan", "--version"],
        "desc": "WordPress vulnerability scanner",
    },
    "ffuf": {
        "binary": "ffuf",
        "apt": "ffuf",
        "go": "github.com/ffuf/ffuf/v2@latest",
        "version_cmd": ["ffuf", "-V"],
        "desc": "Fast web fuzzer written in Go",
    },
    "subfinder": {
        "binary": "subfinder",
        "apt": "subfinder",
        "go": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "version_cmd": ["subfinder", "-version"],
        "desc": "Fast passive subdomain enumeration tool",
    },
    "amass": {
        "binary": "amass",
        "apt": "amass",
        "go": "github.com/owasp-amass/amass/v4/...@master",
        "version_cmd": ["amass", "-version"],
        "desc": "In-depth attack surface mapping and asset discovery",
    },
}


def find_tool_path(tool_name: str) -> Optional[str]:
    """Return path to executable if installed, else None."""
    meta = TOOLS_REGISTRY.get(tool_name)
    if not meta:
        return None

    custom_path = meta.get("custom_path")
    if custom_path and os.path.isfile(custom_path) and os.access(custom_path, os.X_OK):
        return custom_path

    binary = meta.get("binary", tool_name)
    found = shutil.which(binary)
    if found:
        return found

    # Check common fallbacks in user directories
    home = os.path.expanduser("~")
    common_locations = [
        os.path.join(home, "go", "bin", binary),
        os.path.join(home, ".local", "bin", binary),
        f"/usr/local/bin/{binary}",
        f"/usr/bin/{binary}",
    ]
    for loc in common_locations:
        if os.path.isfile(loc) and os.access(loc, os.X_OK):
            return loc

    return None


def get_tool_version(tool_name: str) -> str:
    """Attempt to detect version string of a tool."""
    path = find_tool_path(tool_name)
    if not path:
        return "Not installed"

    meta = TOOLS_REGISTRY.get(tool_name, {})
    version_cmd = meta.get("version_cmd")
    if not version_cmd:
        return "Installed"

    cmd = [path if i == 0 else arg for i, arg in enumerate(version_cmd)]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        raw_output = proc.stdout if proc.stdout else proc.stderr
        for line in raw_output.splitlines():
            line = line.strip()
            if line:
                # Extract clean version token
                match = re.search(r"v?\d+\.\d+(?:\.\d+)?(?:[-a-zA-Z0-9\._]+)?", line)
                if match:
                    return f"v{match.group(0).lstrip('v')}"
                return line[:30]
    except Exception:
        pass

    return "Installed"


def is_tool_installed(tool_name: str) -> bool:
    return find_tool_path(tool_name) is not None


def check_all_tools() -> Dict[str, Dict[str, str]]:
    """Inspect all tools and return their status and version."""
    status = {}
    for name, meta in TOOLS_REGISTRY.items():
        installed = is_tool_installed(name)
        ver = get_tool_version(name) if installed else "Missing"
        status[name] = {
            "installed": installed,
            "version": ver,
            "desc": meta.get("desc", ""),
            "path": find_tool_path(name) or "None",
        }
    return status


def print_tools_table():
    """Print an attractive summary table of tool availability and versions."""
    section("TOOL INVENTORY & AVAILABILITY")
    print(f"  {'Tool':<14} {'Status':<12} {'Version':<18} {'Description'}")
    print(f"  {'─'*14} {'─'*12} {'─'*18} {'─'*25}")

    statuses = check_all_tools()
    for name, data in statuses.items():
        if data["installed"]:
            status_str = f"{C.BGREEN}Installed{C.RESET}"
            ver_str = f"{C.BCYAN}{data['version']:<18}{C.RESET}"
        else:
            status_str = f"{C.BRED}MISSING{C.RESET}  "
            ver_str = f"{C.DIM}—                 {C.RESET}"
        print(f"  {C.BWHITE}{name:<14}{C.RESET} {status_str} {ver_str} {C.DIM}{data['desc']}{C.RESET}")
    print()


def install_via_apt(package: str) -> bool:
    running(f"Installing {package} via apt...")
    try:
        cmd = ["sudo", "apt", "install", "-y", package]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        if res.returncode == 0:
            done(f"{package} installed via apt")
            return True
        error(f"Failed to install {package} via apt")
    except Exception as e:
        error(f"APT install failed: {e}")
    return False


def install_via_pipx(package: str) -> bool:
    running(f"Installing {package} via pipx...")
    try:
        if not shutil.which("pipx"):
            warn("pipx not found. Installing pipx...")
            subprocess.run(["sudo", "apt", "install", "-y", "pipx"], capture_output=True)
        res = subprocess.run(["pipx", "install", package], capture_output=True, text=True, timeout=180)
        if res.returncode == 0:
            done(f"{package} installed via pipx")
            return True
    except Exception as e:
        error(f"pipx install failed: {e}")
    return False


def install_via_go(package: str) -> bool:
    running(f"Installing {package} via go...")
    try:
        if not shutil.which("go"):
            warn("Go compiler not found. Installing golang-go...")
            subprocess.run(["sudo", "apt", "install", "-y", "golang-go"], capture_output=True)
        res = subprocess.run(["go", "install", "-v", package], capture_output=True, text=True, timeout=300)
        if res.returncode == 0:
            done(f"{package} installed via go")
            return True
    except Exception as e:
        error(f"Go install failed: {e}")
    return False


def install_via_gem(package: str) -> bool:
    running(f"Installing {package} via gem...")
    try:
        if not shutil.which("gem"):
            warn("gem not found. Installing ruby-full...")
            subprocess.run(["sudo", "apt", "install", "-y", "ruby-full"], capture_output=True)
        res = subprocess.run(["sudo", "gem", "install", package], capture_output=True, text=True, timeout=180)
        if res.returncode == 0:
            done(f"{package} installed via gem")
            return True
    except Exception as e:
        error(f"Gem install failed: {e}")
    return False


def install_testssl() -> bool:
    running("Installing testssl.sh from GitHub...")
    home = os.path.expanduser("~")
    target_dir = os.path.join(home, "testssl.sh")

    if os.path.exists(target_dir):
        warn("testssl.sh directory already exists")
        return True

    try:
        cmd = ["git", "clone", "--depth", "1", "https://github.com/drwetter/testssl.sh.git", target_dir]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if res.returncode == 0:
            sh_path = os.path.join(target_dir, "testssl.sh")
            try:
                os.chmod(sh_path, 0o755)
            except Exception:
                pass
            done(f"testssl.sh installed at {target_dir}")
            return True
    except Exception as e:
        error(f"Failed to clone testssl.sh: {e}")
    return False


def install_single_tool(tool_name: str) -> bool:
    """Attempt installation of a specific tool through available channels."""
    meta = TOOLS_REGISTRY.get(tool_name)
    if not meta:
        error(f"Unknown tool: {tool_name}")
        return False

    if meta.get("special") == "install_testssl":
        return install_testssl()

    if meta.get("apt") and shutil.which("apt"):
        if install_via_apt(meta["apt"]):
            return True

    if meta.get("pipx") and shutil.which("pipx"):
        if install_via_pipx(meta["pipx"]):
            return True

    if meta.get("go") and shutil.which("go"):
        if install_via_go(meta["go"]):
            return True

    if meta.get("gem") and shutil.which("gem"):
        if install_via_gem(meta["gem"]):
            return True

    error(f"All automated installation methods failed for {tool_name}")
    return False


def auto_install_missing(interactive: bool = True) -> bool:
    """Check missing tools and optionally trigger auto-installation."""
    statuses = check_all_tools()
    missing = [name for name, data in statuses.items() if not data["installed"]]

    if not missing:
        ok("All security tools are verified and ready!")
        return True

    print()
    warn(f"Missing tools detected: {', '.join(missing)}")

    if interactive:
        ans = input(f"{C.BYELLOW}Install missing tools automatically? (yes/no): {C.RESET}").strip().lower()
        if ans not in ("yes", "y"):
            warn("Skipping tool installation. Uninstalled tools will be omitted during scans.")
            return False

    section("INSTALLING MISSING SECURITY TOOLS")
    failed = []
    for tool_name in missing:
        print()
        if not install_single_tool(tool_name):
            failed.append(tool_name)

    print()
    if failed:
        warn(f"Failed to install: {', '.join(failed)}")
        return False

    ok("All missing tools installed successfully!")
    return True

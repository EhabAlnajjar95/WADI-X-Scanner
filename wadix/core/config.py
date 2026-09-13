"""
Configuration, constants, ANSI colors and banners for WADI-X.
"""

import os
import sys
from datetime import datetime

# ============================================================
#                     METADATA
# ============================================================
AUTHOR  = "WADI-X"
VERSION = "3.1.0"
BANNER_YEAR = "2026"

# ============================================================
#                     ANSI COLOR CODES
# ============================================================
class C:
    # Check if terminal supports color (or if NO_COLOR env is set)
    is_atty = sys.stdout.isatty() and "NO_COLOR" not in os.environ

    RESET    = "\033[0m" if is_atty else ""
    BOLD     = "\033[1m" if is_atty else ""
    DIM      = "\033[2m" if is_atty else ""
    RED      = "\033[31m" if is_atty else ""
    GREEN    = "\033[32m" if is_atty else ""
    YELLOW   = "\033[33m" if is_atty else ""
    BLUE     = "\033[34m" if is_atty else ""
    MAGENTA  = "\033[35m" if is_atty else ""
    CYAN     = "\033[36m" if is_atty else ""
    WHITE    = "\033[37m" if is_atty else ""
    BRED     = "\033[91m" if is_atty else ""
    BGREEN   = "\033[92m" if is_atty else ""
    BYELLOW  = "\033[93m" if is_atty else ""
    BBLUE    = "\033[94m" if is_atty else ""
    BMAGENTA = "\033[95m" if is_atty else ""
    BCYAN    = "\033[96m" if is_atty else ""
    BWHITE   = "\033[97m" if is_atty else ""


# ============================================================
#                     WORDLISTS PATHS
# ============================================================
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
LOCAL_WORDLIST = os.path.join(PROJECT_ROOT, "wordlists", "common.txt")

WORDLIST_CANDIDATES = [
    LOCAL_WORDLIST,
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/big.txt",
]

def get_best_wordlist():
    """Return the first existing wordlist from candidates, fallback to local."""
    for path in WORDLIST_CANDIDATES:
        if path and os.path.isfile(path) and os.path.getsize(path) > 0:
            return path
    return LOCAL_WORDLIST

TESTSSL_PATH = os.path.expanduser("~/testssl.sh/testssl.sh")

# Default command execution timeouts in seconds
DEFAULT_TIMEOUTS = {
    "nmap": 600,
    "whatweb": 120,
    "testssl": 900,
    "gobuster": 300,
    "droopescan": 300,
    "nuclei": 600,
    "nuclei_full": 1800,
    "nikto": 600,
    "wpscan": 600,
    "ffuf": 300,
    "subfinder": 180,
    "amass": 600,
}

# Ensure console supports UTF-8 on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

def _safe_print(text: str = ""):
    try:
        print(text)
    except UnicodeEncodeError:
        # Replace non-ascii box characters with safe ascii
        clean = text.encode(sys.stdout.encoding or "ascii", errors="replace").decode(sys.stdout.encoding or "ascii")
        print(clean)

def banner():
    line = f"{C.BCYAN}{'=' * 62}{C.RESET}"
    _safe_print()
    _safe_print(line)
    _safe_print(f"{C.BMAGENTA}{C.BOLD}  ██╗    ██╗ █████╗ ██████╗ ██╗       ██╗  ██╗{C.RESET}")
    _safe_print(f"{C.BMAGENTA}{C.BOLD}  ██║    ██║██╔══██╗██╔══██╗██║       ╚██╗██╔╝{C.RESET}")
    _safe_print(f"{C.BMAGENTA}{C.BOLD}  ██║ █╗ ██║███████║██║  ██║██║        ╚███╔╝ {C.RESET}")
    _safe_print(f"{C.BMAGENTA}{C.BOLD}  ██║███╗██║██╔══██║██║  ██║██║        ██╔██╗ {C.RESET}")
    _safe_print(f"{C.BMAGENTA}{C.BOLD}  ╚███╔███╔╝██║  ██║██████╔╝███████╗  ██╔╝ ██╗{C.RESET}")
    _safe_print(f"{C.BMAGENTA}{C.BOLD}   ╚══╝╚══╝ ╚═╝  ╚═╝╚═════╝ ╚══════╝  ╚═╝  ╚═╝{C.RESET}")
    _safe_print()
    _safe_print(f"{C.BCYAN}{C.BOLD}              WADI-X Security Scanner Orchestrator{C.RESET}")
    _safe_print(f"{C.BWHITE}              Author : {C.BYELLOW}{AUTHOR}{C.RESET}")
    _safe_print(f"{C.BWHITE}              Version: {C.BGREEN}{VERSION}{C.RESET}")
    _safe_print(f"{C.BWHITE}              Date   : {C.BCYAN}{datetime.now().strftime('%Y-%m-%d %H:%M')}{C.RESET}")
    _safe_print(line)
    _safe_print()

def info(msg):    _safe_print(f"{C.BCYAN}[*]{C.RESET} {msg}")
def ok(msg):      _safe_print(f"{C.BGREEN}[+]{C.RESET} {msg}")
def warn(msg):    _safe_print(f"{C.BYELLOW}[!]{C.RESET} {msg}")
def error(msg):   _safe_print(f"{C.BRED}[-]{C.RESET} {msg}")
def running(msg): _safe_print(f"{C.BBLUE}[>]{C.RESET} {msg}")
def done(msg):    _safe_print(f"{C.BGREEN}[✓]{C.RESET} {msg}")
def debug(msg):
    if os.environ.get("WADIX_DEBUG") == "1":
        _safe_print(f"{C.DIM}[DEBUG]{C.RESET} {msg}")

def section(title):
    _safe_print()
    _safe_print(f"{C.BCYAN}{'-' * 62}{C.RESET}")
    _safe_print(f"{C.BWHITE}{C.BOLD}  {title}{C.RESET}")
    _safe_print(f"{C.BCYAN}{'-' * 62}{C.RESET}")

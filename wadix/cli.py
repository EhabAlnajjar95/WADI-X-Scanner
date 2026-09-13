"""
Command-line interface (CLI) for WADI-X Security Scanner.
Supports both non-interactive CLI flags and interactive terminal menus.
"""

import argparse
import sys
import os
from typing import List, Optional
from wadix.core.config import (
    C, VERSION, AUTHOR, banner, section, info, ok, warn, error
)
from wadix.core.target import normalize_target, TargetInfo
from wadix.core.executor import CommandExecutor
from wadix.core.installer import check_all_tools, print_tools_table, auto_install_missing
from wadix.engine.orchestrator import ScanOrchestrator
from wadix.scanners import SCANNER_CLASSES

# Tool numbering for custom interactive menu
TOOLS_MENU_INDEX = {
    "1":  ("nmap",         "Port & service scan"),
    "2":  ("whatweb",      "Technology fingerprinting"),
    "3":  ("testssl",      "SSL/TLS scan"),
    "4":  ("gobuster",     "Directory discovery"),
    "5":  ("droopescan",   "Drupal scan"),
    "6":  ("nuclei",       "Vulnerability scan (fast)"),
    "7":  ("nuclei_full",  "Vulnerability scan (FULL)"),
    "8":  ("nikto",        "Web server scan"),
    "9":  ("wpscan",       "WordPress scan"),
    "10": ("ffuf",         "Advanced fuzzing"),
    "11": ("subfinder",    "Subdomain enumeration"),
    "12": ("amass",        "Advanced enumeration"),
}


def confirm_authorization_interactive():
    section("LEGAL AUTHORIZATION CHECK")
    print(f"{C.BYELLOW}This tool performs security assessments against target systems.{C.RESET}")
    print(f"{C.BYELLOW}You MUST either:{C.RESET}")
    print(f"  {C.BWHITE}1.{C.RESET} Own the target system, OR")
    print(f"  {C.BWHITE}2.{C.RESET} Have explicit, written authorization to test it.")
    print()
    answer = input(f"{C.BCYAN}Confirm legal authorization (yes/no): {C.RESET}").strip().lower()
    if answer not in ("yes", "y"):
        error("Scan aborted. Authorization was not confirmed.")
        sys.exit(1)
    ok("Authorization confirmed. Proceeding...")


def prompt_target_interactive() -> TargetInfo:
    section("TARGET SELECTION")
    print(f"{C.BYELLOW}Enter the domain, IP, or URL you are authorized to test.{C.RESET}\n")

    while True:
        raw = input(f"{C.BCYAN}Target [e.g. example.com]: {C.RESET}").strip()
        if not raw:
            error("Target cannot be empty. Try again.")
            continue
        try:
            target_info = normalize_target(raw)
            print()
            print(f"{C.BWHITE}  Target URL: {C.BCYAN}{target_info.url}{C.RESET}")
            print(f"{C.BWHITE}  Host:       {C.BCYAN}{target_info.host}{C.RESET} (Port: {target_info.port})")
            confirm = input(f"{C.BYELLOW}  Is this correct? (yes/no): {C.RESET}").strip().lower()
            if confirm in ("yes", "y"):
                ok(f"Target locked: {target_info.url}")
                return target_info
        except ValueError as e:
            error(f"Invalid target: {e}")
            print(f"{C.DIM}Please check format and enter a valid domain or IP address.{C.RESET}\n")


def parse_custom_selection(selection_str: str) -> List[str]:
    """Parse user selection such as '1,3,5' or '1-4' or 'all' or tool names."""
    cleaned = selection_str.strip().lower()
    if not cleaned:
        return []

    if cleaned == "all":
        return [meta[0] for meta in TOOLS_MENU_INDEX.values()]

    selected_tools = []
    parts = cleaned.replace(" ", "").split(",")
    for part in parts:
        if "-" in part and part.replace("-", "").isdigit():
            s, e = part.split("-")
            for i in range(int(s), int(e) + 1):
                key = str(i)
                if key in TOOLS_MENU_INDEX:
                    selected_tools.append(TOOLS_MENU_INDEX[key][0])
        elif part in TOOLS_MENU_INDEX:
            selected_tools.append(TOOLS_MENU_INDEX[part][0])
        elif part in SCANNER_CLASSES:
            selected_tools.append(part)
        else:
            warn(f"Unrecognized tool identifier: '{part}'")

    # Preserve order and eliminate duplicates
    seen = set()
    result = []
    for t in selected_tools:
        if t not in seen:
            seen.add(t)
            result.append(t)
    return result


def prompt_mode_interactive() -> tuple:
    section("SELECT SCAN PROFILE")
    print(f"{C.BWHITE}  {C.BMAGENTA}[S]{C.RESET} {C.BWHITE}Smart Scan{C.RESET}     — Technology-aware adaptive scan ({C.BGREEN}Recommended{C.RESET})")
    print(f"{C.BWHITE}  {C.BBLUE}[B]{C.RESET} {C.BWHITE}Fast Scan{C.RESET}      — Essential reconnaissance & fast vulns")
    print(f"{C.BWHITE}  {C.BGREEN}[A]{C.RESET} {C.BWHITE}Full Scan{C.RESET}      — Deep audit across all 12 modules")
    print(f"{C.BWHITE}  {C.BYELLOW}[C]{C.RESET} {C.BWHITE}Custom Scan{C.RESET}    — Handpick specific scanners")
    print(f"{C.BWHITE}  {C.BRED}[Q]{C.RESET} {C.BWHITE}Quit{C.RESET}")
    print()

    mode = input(f"{C.BCYAN}Select mode [S/B/A/C/Q]: {C.RESET}").strip().upper()

    if mode == "Q":
        warn("Execution aborted by user.")
        sys.exit(0)
    elif mode == "S":
        return "SMART", None
    elif mode == "B":
        return "FAST", None
    elif mode == "A":
        return "FULL", None
    elif mode == "C":
        section("CUSTOM TOOLS SELECTION")
        for key, (tname, tdesc) in TOOLS_MENU_INDEX.items():
            print(f"  {C.BCYAN}{key:>2}{C.RESET}. {C.BWHITE}{tname:<12}{C.RESET} — {C.DIM}{tdesc}{C.RESET}")
        print(f"\n{C.BYELLOW}Syntax: 1 | 1,3,6 | 1-5 | all{C.RESET}")
        sel = input(f"{C.BCYAN}Your selection: {C.RESET}").strip()
        custom_tools = parse_custom_selection(sel)
        if not custom_tools:
            error("No valid tools selected. Aborting.")
            sys.exit(1)
        return "CUSTOM", custom_tools
    else:
        error(f"Invalid mode: '{mode}'")
        sys.exit(1)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wadix",
        description="WADI-X Security Scanner Orchestrator: Multi-tool automated security assessment.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("-t", "--target", help="Target URL, domain, or IP address to scan")
    parser.add_argument(
        "-p", "--profile",
        choices=["smart", "fast", "full", "custom"],
        default=None,
        help="Scan profile: 'smart' (adaptive), 'fast', 'full', or 'custom'",
    )
    parser.add_argument(
        "--tools",
        help="Comma-separated list of tools for custom profile (e.g. nmap,whatweb,nuclei)",
    )
    parser.add_argument("-o", "--output-dir", help="Custom output directory path for logs and reports")
    parser.add_argument("--dry-run", action="store_true", help="Simulate tool execution without sending network requests")
    parser.add_argument("--no-install", action="store_true", help="Skip missing tool verification and installation")
    parser.add_argument("--list-tools", action="store_true", help="Display all supported tools, versions and status, then exit")
    parser.add_argument("-y", "--yes", action="store_true", help="Automatically accept legal authorization check")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logs")
    parser.add_argument("--timeout", type=int, help="Global default timeout per tool in seconds")
    parser.add_argument("--version", action="version", version=f"WADI-X Orchestrator v{VERSION} by {AUTHOR}")

    return parser


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    # If user ran --list-tools
    if args.list_tools:
        banner()
        print_tools_table()
        sys.exit(0)

    if args.verbose:
        os.environ["WADIX_DEBUG"] = "1"

    banner()

    # Step 1: Tool dependency check
    if not args.no_install:
        interactive_install = args.target is None
        auto_install_missing(interactive=interactive_install)

    # Step 2: Authorization check
    if not args.yes:
        confirm_authorization_interactive()

    # Step 3: Target acquisition
    if args.target:
        try:
            target_info = normalize_target(args.target)
            ok(f"Target: {target_info.url} ({target_info.host}:{target_info.port})")
        except ValueError as e:
            error(f"Target validation failed: {e}")
            sys.exit(1)
    else:
        target_info = prompt_target_interactive()

    # Step 4: Profile selection
    if args.profile:
        profile = args.profile.upper()
        custom_tools = parse_custom_selection(args.tools) if args.tools else None
    else:
        profile, custom_tools = prompt_mode_interactive()

    # Step 5: Execute pipeline
    executor = CommandExecutor(dry_run=args.dry_run, verbose=args.verbose)
    orchestrator = ScanOrchestrator(executor=executor)

    try:
        orchestrator.run_pipeline(
            target=target_info,
            profile=profile,
            custom_tool_names=custom_tools,
            output_dir=args.output_dir,
        )
    except KeyboardInterrupt:
        warn("\nScan aborted by user.")
        sys.exit(130)
    except Exception as e:
        error(f"Execution error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

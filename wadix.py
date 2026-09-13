#!/usr/bin/env python3
"""
WADI-X Security Scanner Orchestrator
Author : WADI-X Team
Version: 3.1.0

Automated multi-tool security assessment framework.
Supports Smart, Fast, Full, and Custom profiles with Markdown, JSON, and HTML reports.
Use ONLY on systems you own or have explicit written authorization to test.
"""

import sys
from wadix.cli import main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Process terminated by user.")
        sys.exit(130)

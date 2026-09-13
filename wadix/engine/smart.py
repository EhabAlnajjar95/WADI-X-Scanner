"""
Smart Scan Engine: Context-aware and technology-adaptive scan orchestration.
"""

from typing import List, Set, Dict, Tuple
from wadix.core.target import TargetInfo
from wadix.core.executor import CommandExecutor
from wadix.core.config import info, ok, section, C
from wadix.scanners.base import BaseScanner
from wadix.scanners.recon import WhatWebScanner, NmapScanner, SubfinderScanner
from wadix.scanners.web import NiktoScanner, TestSSLScanner, GobusterScanner
from wadix.scanners.cms import WPScanScanner, DroopescanScanner
from wadix.scanners.vuln import NucleiScanner
from wadix.reporting.models import ToolResult

class SmartScanEngine:
    """
    Intelligently analyzes target stack in initial recon phase
    and triggers targeted vulnerability scanners accordingly.
    """

    def __init__(self, executor: CommandExecutor):
        self.executor = executor

    def plan_smart_scan(self, target: TargetInfo, outdir: str) -> Tuple[List[BaseScanner], Set[str]]:
        """
        Phase 1: Probe target with WhatWeb fingerprinting.
        Phase 2: Dynamically assemble tailored tool list.
        """
        section("SMART SCAN — PHASE 1: FINGERPRINTING & DISCOVERY")
        info(f"Analyzing technology stack for {target.url}...")

        whatweb = WhatWebScanner()
        ww_res = whatweb.run(target, outdir, self.executor)

        detected_techs = set()
        raw_text = (ww_res.stdout or "") + " " + " ".join([f.description for f in ww_res.findings])
        detected_techs = WhatWebScanner.extract_technologies(raw_text)

        if detected_techs:
            ok(f"Identified Technologies: {C.BYELLOW}{', '.join(sorted(detected_techs))}{C.RESET}")
        else:
            info("Generic web stack detected. Applying standard security suite.")

        # Phase 2: Assemble tool list based on discovered stack
        selected_scanners: List[BaseScanner] = []

        # 1. Always run Nmap port & service probe
        selected_scanners.append(NmapScanner())

        # 2. Subdomain discovery if target is domain (skip if raw IP)
        if not target.is_ip:
            selected_scanners.append(SubfinderScanner())

        # 3. SSL/TLS check if HTTPS
        if target.scheme == "https" or target.port in (443, 8443):
            selected_scanners.append(TestSSLScanner())

        # 4. Web server configuration check (Nikto)
        selected_scanners.append(NiktoScanner())

        # 5. Directory brute-forcing
        selected_scanners.append(GobusterScanner())

        # 6. CMS-Specific Targeted Audits
        nuclei_tags = ["exposure", "misconfiguration", "cve"]

        if "wordpress" in detected_techs:
            ok("WordPress detected! Enqueuing WPScan and WordPress CVE templates.")
            selected_scanners.append(WPScanScanner())
            nuclei_tags.extend(["wordpress", "wp-plugin"])

        if "drupal" in detected_techs:
            ok("Drupal detected! Enqueuing Droopescan and Drupal CVE templates.")
            selected_scanners.append(DroopescanScanner())
            nuclei_tags.extend(["drupal"])

        if "apache" in detected_techs:
            nuclei_tags.append("apache")
        if "nginx" in detected_techs:
            nuclei_tags.append("nginx")
        if "php" in detected_techs:
            nuclei_tags.append("php")

        # 7. Add context-tailored Nuclei scan
        selected_scanners.append(NucleiScanner(custom_tags=nuclei_tags))

        return selected_scanners, detected_techs

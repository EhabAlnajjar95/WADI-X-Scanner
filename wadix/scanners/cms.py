"""
CMS-specific scanners: WPScan (WordPress) and Droopescan (Drupal).
"""

import os
import re
from typing import List
from wadix.core.target import TargetInfo
from wadix.core.executor import ExecutionResult
from wadix.scanners.base import BaseScanner
from wadix.reporting.models import Finding, Severity

class WPScanScanner(BaseScanner):
    name = "wpscan"
    description = "WordPress security auditing & vulnerability scan"
    default_timeout = 600

    def build_command(self, target: TargetInfo, outdir: str) -> List[str]:
        output = os.path.join(outdir, "wpscan.txt")
        bin_path = self.get_executable() or "wpscan"
        return [
            bin_path,
            "--url", target.url,
            "--enumerate", "vp,vt,u",
            "--format", "cli-no-color",
            "--no-banner",
            "--output", output,
            "--disable-tls-checks",
        ]

    def parse_findings(self, exec_result: ExecutionResult, target: TargetInfo) -> List[Finding]:
        findings = []
        raw = exec_result.stdout or ""
        # Identify interesting findings like vulnerabilities and exposed users
        for line in raw.splitlines():
            line = line.strip()
            if "[!]" in line and not any(skip in line for skip in ["No WPVulnDB", "API Token"]):
                findings.append(Finding(
                    tool=self.name,
                    title=f"WordPress Alert: {line.replace('[!]', '').strip()[:80]}",
                    severity=Severity.HIGH if "vulnerability" in line.lower() else Severity.MEDIUM,
                    description=line,
                    matched_at=target.url,
                ))
            elif "[+]" in line and "User(s) Identified:" in line:
                findings.append(Finding(
                    tool=self.name,
                    title="WordPress Users Enumerated",
                    severity=Severity.LOW,
                    description=line,
                    matched_at=target.url,
                ))
        return findings


class DroopescanScanner(BaseScanner):
    name = "droopescan"
    description = "Drupal CMS vulnerability scanner"
    default_timeout = 300

    def build_command(self, target: TargetInfo, outdir: str) -> List[str]:
        output = os.path.join(outdir, "droopescan.txt")
        bin_path = self.get_executable() or "droopescan"
        return [bin_path, "scan", "drupal", "-u", target.url]

    def parse_findings(self, exec_result: ExecutionResult, target: TargetInfo) -> List[Finding]:
        findings = []
        raw = exec_result.stdout or ""
        for line in raw.splitlines():
            line = line.strip()
            if "Plugins found:" in line or "Interesting urls found:" in line:
                findings.append(Finding(
                    tool=self.name,
                    title=f"Drupal Discovery: {line}",
                    severity=Severity.LOW,
                    description=line,
                    matched_at=target.url,
                ))
        return findings

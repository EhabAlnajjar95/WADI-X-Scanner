"""
Reconnaissance and network mapping scanners: Nmap, WhatWeb, Subfinder, Amass.
"""

import os
import re
from typing import List, Set
from wadix.core.target import TargetInfo
from wadix.core.executor import ExecutionResult
from wadix.scanners.base import BaseScanner
from wadix.reporting.models import Finding, Severity

class NmapScanner(BaseScanner):
    name = "nmap"
    description = "Port & service scan"
    default_timeout = 600

    def build_command(self, target: TargetInfo, outdir: str) -> List[str]:
        output = os.path.join(outdir, "nmap.txt")
        bin_path = self.get_executable() or "nmap"
        # Scan target host with version detection and default safe scripts
        cmd = [bin_path, "-sV", "-sC", "-oN", output]
        if target.port not in (80, 443):
            cmd.extend(["-p", str(target.port)])
        cmd.append(target.host)
        return cmd

    def parse_findings(self, exec_result: ExecutionResult, target: TargetInfo) -> List[Finding]:
        findings = []
        raw = exec_result.stdout or ""
        # Look for open ports: e.g. "80/tcp open http"
        port_matches = re.findall(r"(\d+/(?:tcp|udp))\s+open\s+([^\n\r]+)", raw)
        for port_proto, service in port_matches:
            findings.append(Finding(
                tool=self.name,
                title=f"Open Port: {port_proto} ({service.strip()})",
                severity=Severity.INFO,
                description=f"Service detected on {target.host}:{port_proto} -> {service.strip()}",
                matched_at=f"{target.host}:{port_proto.split('/')[0]}",
            ))
        return findings


class WhatWebScanner(BaseScanner):
    name = "whatweb"
    description = "Technology fingerprinting & CMS detection"
    default_timeout = 180

    def build_command(self, target: TargetInfo, outdir: str) -> List[str]:
        output = os.path.join(outdir, "whatweb.txt")
        bin_path = self.get_executable() or "whatweb"
        return [bin_path, "--log-brief", output, target.url]

    def parse_findings(self, exec_result: ExecutionResult, target: TargetInfo) -> List[Finding]:
        findings = []
        raw = exec_result.stdout or ""
        # Match detected technologies inside brackets [Tech, Tech2]
        tech_matches = re.findall(r"\[(.*?)\]", raw)
        detected_techs = set()
        for group in tech_matches:
            items = [item.strip() for item in group.split(",") if item.strip()]
            for item in items:
                # Exclude HTTP status code entries like 200 OK
                if not re.match(r"^\d{3}", item):
                    detected_techs.add(item)

        if detected_techs:
            findings.append(Finding(
                tool=self.name,
                title="Web Technologies Identified",
                severity=Severity.INFO,
                description=f"Detected stack: {', '.join(sorted(detected_techs))}",
                matched_at=target.url,
            ))
        return findings

    @staticmethod
    def extract_technologies(raw_output: str) -> Set[str]:
        """Utility for Smart Scanner to detect specific technologies (e.g. WordPress, Drupal)."""
        tags = set()
        raw_lower = raw_output.lower()
        keywords = ["wordpress", "drupal", "joomla", "apache", "nginx", "iis", "php", "cloudflare", "node.js", "express", "laravel"]
        for kw in keywords:
            if kw in raw_lower:
                tags.add(kw)
        return tags


class SubfinderScanner(BaseScanner):
    name = "subfinder"
    description = "Subdomain enumeration"
    default_timeout = 180

    def build_command(self, target: TargetInfo, outdir: str) -> List[str]:
        output = os.path.join(outdir, "subfinder.txt")
        bin_path = self.get_executable() or "subfinder"
        return [bin_path, "-d", target.host, "-o", output, "-silent"]

    def parse_findings(self, exec_result: ExecutionResult, target: TargetInfo) -> List[Finding]:
        findings = []
        # If target is an IP, subfinder won't return domain results
        if target.is_ip:
            return findings

        output_file = exec_result.output_file
        subdomains = []
        if output_file and os.path.isfile(output_file):
            try:
                with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
                    subdomains = [line.strip() for line in f if line.strip()]
            except Exception:
                pass

        if subdomains:
            findings.append(Finding(
                tool=self.name,
                title=f"Discovered {len(subdomains)} Subdomain(s)",
                severity=Severity.INFO,
                description=f"Subdomains identified for {target.host}: {', '.join(subdomains[:10])}{' ...' if len(subdomains) > 10 else ''}",
                matched_at=target.host,
            ))
        return findings


class AmassScanner(BaseScanner):
    name = "amass"
    description = "Advanced attack surface mapping"
    default_timeout = 600

    def build_command(self, target: TargetInfo, outdir: str) -> List[str]:
        output = os.path.join(outdir, "amass.txt")
        bin_path = self.get_executable() or "amass"
        return [bin_path, "enum", "-passive", "-d", target.host, "-o", output, "-timeout", "10"]

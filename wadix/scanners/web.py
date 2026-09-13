"""
Web application security and fuzzing scanners: Nikto, TestSSL, Gobuster, Ffuf.
"""

import os
import re
from typing import List
from wadix.core.target import TargetInfo
from wadix.core.executor import ExecutionResult
from wadix.core.config import get_best_wordlist, TESTSSL_PATH
from wadix.scanners.base import BaseScanner
from wadix.reporting.models import Finding, Severity

class NiktoScanner(BaseScanner):
    name = "nikto"
    description = "Web server vulnerability & configuration scan"
    default_timeout = 600

    def build_command(self, target: TargetInfo, outdir: str) -> List[str]:
        output = os.path.join(outdir, "nikto.txt")
        bin_path = self.get_executable() or "nikto"
        return [bin_path, "-h", target.url, "-o", output, "-Format", "txt", "-nointeractive"]

    def parse_findings(self, exec_result: ExecutionResult, target: TargetInfo) -> List[Finding]:
        findings = []
        raw = exec_result.stdout or ""
        # Nikto flags items with "+ "
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("+ ") and not any(skip in line for skip in ["Target IP:", "Target Hostname:", "Target Port:", "Start Time:", "End Time:"]):
                text = line.lstrip("+ ").strip()
                # Determine severity heuristics based on keywords
                sev = Severity.INFO
                lower_text = text.lower()
                if any(kw in lower_text for kw in ["vulnerability", "remote code", "sql injection", "rce", "exploit"]):
                    sev = Severity.HIGH
                elif any(kw in lower_text for kw in ["outdated", "leak", "disclosure", "unprotected", "directory indexing", "backup"]):
                    sev = Severity.MEDIUM
                elif any(kw in lower_text for kw in ["header", "cookie", "x-frame-options", "x-content-type"]):
                    sev = Severity.LOW

                findings.append(Finding(
                    tool=self.name,
                    title=text[:100],
                    severity=sev,
                    description=text,
                    matched_at=target.url,
                ))
        return findings


class TestSSLScanner(BaseScanner):
    name = "testssl"
    description = "SSL/TLS cryptographic assessment"
    default_timeout = 900

    def get_executable(self) -> str:
        # Check custom testssl path or binary
        if os.path.isfile(TESTSSL_PATH) and os.access(TESTSSL_PATH, os.X_OK):
            return TESTSSL_PATH
        return super().get_executable() or "testssl.sh"

    def build_command(self, target: TargetInfo, outdir: str) -> List[str]:
        output = os.path.join(outdir, "testssl.txt")
        bin_path = self.get_executable()
        # Non-colored, quiet output
        return [bin_path, "--quiet", "--color", "0", "--logfile", output, target.url]

    def parse_findings(self, exec_result: ExecutionResult, target: TargetInfo) -> List[Finding]:
        findings = []
        raw = exec_result.stdout or ""
        # Look for vulnerabilities like Heartbleed, POODLE, Robot, DROWN, SSLv2/SSLv3 enabled
        vuln_keywords = [
            ("Heartbleed", Severity.CRITICAL),
            ("ROBOT", Severity.HIGH),
            ("POODLE", Severity.MEDIUM),
            ("DROWN", Severity.HIGH),
            ("SWEET32", Severity.MEDIUM),
            ("BEAST", Severity.LOW),
            ("LOGJAM", Severity.MEDIUM),
            ("FREAK", Severity.HIGH),
            ("CRIME", Severity.MEDIUM),
            ("BREACH", Severity.LOW),
        ]
        for vname, sev in vuln_keywords:
            pattern = re.compile(rf"{vname}.*?(vulnerable|NOT ok)", re.IGNORECASE)
            if pattern.search(raw):
                findings.append(Finding(
                    tool=self.name,
                    title=f"SSL/TLS Vulnerability: {vname}",
                    severity=sev,
                    description=f"Target appears vulnerable to {vname} based on testssl audit.",
                    matched_at=target.url,
                ))
        return findings


class GobusterScanner(BaseScanner):
    name = "gobuster"
    description = "Directory & path brute-forcing"
    default_timeout = 300

    def build_command(self, target: TargetInfo, outdir: str) -> List[str]:
        output = os.path.join(outdir, "gobuster.txt")
        bin_path = self.get_executable() or "gobuster"
        wordlist = get_best_wordlist()
        return [
            bin_path, "dir",
            "-u", target.url,
            "-w", wordlist,
            "-o", output,
            "-q",
            "-t", "20",
            "-b", "404",
        ]

    def parse_findings(self, exec_result: ExecutionResult, target: TargetInfo) -> List[Finding]:
        findings = []
        raw = exec_result.stdout or ""
        # Lines usually: /admin (Status: 301) [Size: 123]
        matches = re.findall(r"(\S+)\s+\(Status:\s*(\d{3})\)", raw)
        for path, status_code in matches:
            sev = Severity.INFO
            if status_code in ("200", "301", "302"):
                if any(sensitive in path.lower() for sensitive in ["admin", "login", "config", ".env", ".git", "backup", "db"]):
                    sev = Severity.MEDIUM
            findings.append(Finding(
                tool=self.name,
                title=f"Exposed Path: {path} (HTTP {status_code})",
                severity=sev,
                description=f"Accessible endpoint found at {path} with HTTP status code {status_code}",
                matched_at=f"{target.url.rstrip('/')}{path}",
            ))
        return findings


class FfufScanner(BaseScanner):
    name = "ffuf"
    description = "High-speed web fuzzing"
    default_timeout = 300

    def build_command(self, target: TargetInfo, outdir: str) -> List[str]:
        output = os.path.join(outdir, "ffuf.txt")
        bin_path = self.get_executable() or "ffuf"
        wordlist = get_best_wordlist()
        url_with_fuzz = target.url.rstrip("/") + "/FUZZ"
        return [
            bin_path,
            "-u", url_with_fuzz,
            "-w", wordlist,
            "-o", output,
            "-of", "text",
            "-mc", "200,204,301,302,307,401,403,500",
            "-t", "40",
            "-s",
        ]

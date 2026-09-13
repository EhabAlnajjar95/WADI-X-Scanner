"""
Vulnerability scanning with Nuclei, including JSON export and structured finding parsing.
"""

import os
import json
from typing import List, Optional
from wadix.core.target import TargetInfo
from wadix.core.executor import ExecutionResult
from wadix.scanners.base import BaseScanner
from wadix.reporting.models import Finding, Severity

class NucleiScanner(BaseScanner):
    name = "nuclei"
    description = "Vulnerability & misconfiguration scanner (Fast)"
    default_timeout = 600

    def __init__(self, full: bool = False, custom_tags: Optional[List[str]] = None, timeout: Optional[int] = None):
        super().__init__(timeout=timeout)
        self.full = full
        self.custom_tags = custom_tags or []
        if self.full:
            self.name = "nuclei_full"
            self.description = "Deep vulnerability scan (Full)"
            self.default_timeout = 1800

    def build_command(self, target: TargetInfo, outdir: str) -> List[str]:
        output_txt = os.path.join(outdir, f"{self.name}.txt")
        output_json = os.path.join(outdir, f"{self.name}.json")
        bin_path = self.get_executable() or "nuclei"

        cmd = [
            bin_path,
            "-u", target.url,
            "-o", output_txt,
            "-json-export", output_json,
            "-silent",
            "-timeout", "6",
            "-retries", "1",
        ]

        if self.custom_tags:
            cmd.extend(["-tags", ",".join(self.custom_tags)])
        elif not self.full:
            cmd.extend([
                "-tags", "exposure,misconfiguration,cve,tech",
                "-severity", "medium,high,critical",
                "-rate-limit", "150",
                "-c", "25",
            ])
        else:
            # Full scan
            cmd.extend([
                "-severity", "low,medium,high,critical",
                "-rate-limit", "200",
                "-c", "40",
                "-exclude-tags", "fuzz,brute-force",
            ])

        return cmd

    def parse_findings(self, exec_result: ExecutionResult, target: TargetInfo) -> List[Finding]:
        findings = []
        outdir = os.path.dirname(exec_result.output_file) if exec_result.output_file else "."
        json_file = os.path.join(outdir, f"{self.name}.json")

        if os.path.isfile(json_file):
            try:
                with open(json_file, "r", encoding="utf-8", errors="ignore") as jf:
                    for line in jf:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            item = json.loads(line)
                            info = item.get("info", {})
                            sev_str = info.get("severity", "info").upper()
                            cve_list = []
                            classification = info.get("classification", {})
                            cves = classification.get("cve-id")
                            if isinstance(cves, list):
                                cve_list = cves
                            elif isinstance(cves, str):
                                cve_list = [cves]

                            cwe_list = classification.get("cwe-id", [])
                            if isinstance(cwe_list, str):
                                cwe_list = [cwe_list]

                            findings.append(Finding(
                                tool=self.name,
                                title=info.get("name", item.get("template-id", "Nuclei Finding")),
                                severity=Severity.from_string(sev_str),
                                description=info.get("description", "") or f"Detected by template {item.get('template-id')}",
                                matched_at=item.get("matched-at", target.url),
                                template_id=item.get("template-id"),
                                cve_ids=cve_list,
                                cwe_ids=cwe_list,
                                remediation=info.get("remediation", ""),
                                raw=item,
                            ))
                        except json.JSONDecodeError:
                            continue
            except Exception:
                pass

        # Fallback to parsing text output if JSON export had no entries or failed
        if not findings and exec_result.output_file and os.path.isfile(exec_result.output_file):
            try:
                with open(exec_result.output_file, "r", encoding="utf-8", errors="ignore") as tf:
                    for line in tf:
                        line = line.strip()
                        # Formats like: [template-id] [protocol] [severity] url
                        if line.startswith("["):
                            parts = line.split(" ")
                            t_id = parts[0].strip("[]") if len(parts) > 0 else "Finding"
                            sev = Severity.INFO
                            for p in parts:
                                p_clean = p.strip("[]").upper()
                                if p_clean in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                                    sev = Severity.from_string(p_clean)
                                    break
                            findings.append(Finding(
                                tool=self.name,
                                title=f"Nuclei: {t_id}",
                                severity=sev,
                                description=line,
                                matched_at=target.url,
                                template_id=t_id,
                            ))
            except Exception:
                pass

        return findings

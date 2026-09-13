"""
Scan orchestration engine: executes profiles, handles interruption, and generates reports.
"""

import os
import time
import signal
from datetime import datetime
from typing import List, Dict, Optional, Set
from wadix.core.target import TargetInfo
from wadix.core.config import (
    C, info, ok, warn, error, running, done, section, debug
)
from wadix.core.executor import CommandExecutor
from wadix.scanners.base import BaseScanner
from wadix.scanners import get_scanner, SCANNER_CLASSES
from wadix.engine.smart import SmartScanEngine
from wadix.reporting.models import ScanSummary, ToolResult, Finding
from wadix.reporting import generate_markdown_report, generate_json_report, generate_html_report

# Profile presets
PROFILE_TOOLS = {
    "FAST": ["nmap", "whatweb", "testssl", "gobuster", "nuclei", "nikto", "ffuf", "subfinder"],
    "FULL": ["nmap", "whatweb", "testssl", "gobuster", "droopescan", "nuclei_full", "nikto", "wpscan", "ffuf", "subfinder", "amass"],
}


class ScanOrchestrator:
    """Orchestrates security scanners, pipeline execution, and reporting."""

    def __init__(self, executor: Optional[CommandExecutor] = None):
        self.executor = executor or CommandExecutor()
        self._interrupted = False

    def deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Conservatively deduplicate identical findings across tools."""
        seen = set()
        deduped = []
        for f in findings:
            key = (f.tool.lower(), f.title.lower().strip(), f.matched_at.lower().strip())
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        return deduped

    def run_pipeline(
        self,
        target: TargetInfo,
        profile: str,
        custom_tool_names: Optional[List[str]] = None,
        output_dir: Optional[str] = None,
    ) -> ScanSummary:
        """Run the selected scan pipeline and write reports."""
        profile = profile.upper()

        if not output_dir:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = f"wadix_scan_{target.safe_name}_{timestamp}"

        os.makedirs(output_dir, exist_ok=True)
        start_dt = datetime.now()
        start_time_str = start_dt.strftime("%Y-%m-%d %H:%M:%S")

        scanners_to_run: List[BaseScanner] = []
        smart_detected_techs: Set[str] = set()

        if profile == "SMART":
            smart_engine = SmartScanEngine(self.executor)
            scanners_to_run, smart_detected_techs = smart_engine.plan_smart_scan(target, output_dir)

        elif profile == "CUSTOM":
            tool_names = custom_tool_names or []
            for tname in tool_names:
                if tname in SCANNER_CLASSES:
                    scanners_to_run.append(get_scanner(tname))
                else:
                    warn(f"Unknown custom scanner requested: '{tname}' — skipping")

        elif profile in PROFILE_TOOLS:
            for tname in PROFILE_TOOLS[profile]:
                scanners_to_run.append(get_scanner(tname))
        else:
            raise ValueError(f"Unknown scan profile: '{profile}'")

        tool_results: Dict[str, ToolResult] = {}
        all_findings: List[Finding] = []
        total = len(scanners_to_run)

        section(f"RUNNING {profile} SCAN ({total} MODULES)")
        info(f"Target: {C.BWHITE}{target.url}{C.RESET}")
        info(f"Output Directory: {C.BCYAN}{output_dir}{C.RESET}")

        start_perf = time.time()

        for idx, scanner in enumerate(scanners_to_run, 1):
            if self._interrupted or self.executor._interrupted:
                warn("Scan execution halted due to user cancellation.")
                break

            print()
            running(f"[{idx}/{total}] {C.BWHITE}{scanner.name}{C.RESET} — {C.DIM}{scanner.description}{C.RESET}")

            try:
                result = scanner.run(target, output_dir, self.executor)
                tool_results[scanner.name] = result

                if result.status == "SUCCESS":
                    fcount_str = f"({len(result.findings)} finding(s))" if result.findings else ""
                    done(f"{scanner.name} completed in {result.duration:.1f}s {fcount_str} -> {result.output_file}")
                    all_findings.extend(result.findings)
                elif result.status == "SKIPPED":
                    warn(f"{scanner.name} skipped: {result.error_message}")
                elif result.status == "TIMEOUT":
                    error(f"{scanner.name} timed out after {scanner.timeout}s")
                else:
                    error(f"{scanner.name} failed (exit code {result.return_code})")
                    if result.error_message:
                        debug(f"Details: {result.error_message}")

            except KeyboardInterrupt:
                warn(f"\nInterrupt received during {scanner.name} execution.")
                self._interrupted = True
                self.executor.interrupt()
                break
            except Exception as e:
                error(f"Unexpected error running {scanner.name}: {e}")
                tool_results[scanner.name] = ToolResult(
                    tool_name=scanner.name,
                    description=scanner.description,
                    status="FAILED",
                    return_code=1,
                    output_file=os.path.join(output_dir, f"{scanner.name}.txt"),
                    error_message=str(e),
                )

        total_duration = round(time.time() - start_perf, 2)
        end_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        deduped_findings = self.deduplicate_findings(all_findings)

        summary = ScanSummary(
            target_url=target.url,
            target_host=target.host,
            target_port=target.port,
            scan_profile=profile,
            start_time=start_time_str,
            end_time=end_time_str,
            total_duration_seconds=total_duration,
            output_directory=output_dir,
            tool_results=tool_results,
            all_findings=deduped_findings,
        )
        summary.calculate_counts()

        # Generate all 3 report formats
        section("GENERATING ASSESSMENT REPORTS")
        md_path = os.path.join(output_dir, "REPORT.md")
        json_path = os.path.join(output_dir, "report.json")
        html_path = os.path.join(output_dir, "report.html")

        try:
            generate_markdown_report(summary, md_path)
            done(f"Markdown Report: {C.BCYAN}{md_path}{C.RESET}")
        except Exception as e:
            error(f"Failed to generate Markdown report: {e}")

        try:
            generate_json_report(summary, json_path)
            done(f"JSON Report:     {C.BCYAN}{json_path}{C.RESET}")
        except Exception as e:
            error(f"Failed to generate JSON report: {e}")

        try:
            generate_html_report(summary, html_path)
            done(f"HTML Dashboard:  {C.BCYAN}{html_path}{C.RESET}")
        except Exception as e:
            error(f"Failed to generate HTML report: {e}")

        # Summary printout
        section("SCAN COMPLETE SUMMARY")
        ok(f"Total Duration : {total_duration}s")
        ok(f"Modules Run    : {len(tool_results)}/{total}")
        ok(f"Total Findings : {len(deduped_findings)}")
        print(f"  • Critical: {summary.severity_counts.get('CRITICAL', 0)}")
        print(f"  • High    : {summary.severity_counts.get('HIGH', 0)}")
        print(f"  • Medium  : {summary.severity_counts.get('MEDIUM', 0)}")
        print(f"  • Low     : {summary.severity_counts.get('LOW', 0)}")
        print(f"  • Info    : {summary.severity_counts.get('INFO', 0)}")
        print()
        info(f"Open dashboard: {C.BGREEN}firefox {html_path}{C.RESET}")

        return summary

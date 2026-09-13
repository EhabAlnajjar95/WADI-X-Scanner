"""
Markdown report generator for WADI-X security assessments.
"""

import os
from datetime import datetime
from wadix.reporting.models import ScanSummary, Severity

def generate_markdown_report(summary: ScanSummary, file_path: str) -> str:
    """Generate a clean, structured Markdown assessment report."""
    summary.calculate_counts()
    os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)

    with open(file_path, "w", encoding="utf-8") as f:
        # Title & Metadata
        f.write("# WADI-X Security Assessment Report\n\n")
        f.write(f"**Target URL:** `{summary.target_url}`  \n")
        f.write(f"**Host:** `{summary.target_host}` | **Port:** `{summary.target_port}`  \n")
        f.write(f"**Scan Profile:** `{summary.scan_profile}`  \n")
        f.write(f"**Date:** {summary.start_time}  \n")
        f.write(f"**Total Duration:** {summary.total_duration_seconds}s  \n\n")
        f.write("---\n\n")

        # Executive Summary & Severity Counts
        f.write("## 1. Executive Summary\n\n")
        f.write("| Severity | Findings Count |\n")
        f.write("|----------|----------------|\n")
        f.write(f"| 🔴 **CRITICAL** | **{summary.severity_counts.get(Severity.CRITICAL.value, 0)}** |\n")
        f.write(f"| 🟠 **HIGH**     | **{summary.severity_counts.get(Severity.HIGH.value, 0)}** |\n")
        f.write(f"| 🟡 **MEDIUM**   | **{summary.severity_counts.get(Severity.MEDIUM.value, 0)}** |\n")
        f.write(f"| 🔵 **LOW**      | **{summary.severity_counts.get(Severity.LOW.value, 0)}** |\n")
        f.write(f"| ⚪ **INFO**     | **{summary.severity_counts.get(Severity.INFO.value, 0)}** |\n")
        f.write(f"| 📊 **TOTAL**    | **{len(summary.all_findings)}** |\n\n")

        # Tool Execution Status Table
        f.write("## 2. Security Tool Status\n\n")
        f.write("| Tool | Status | Duration | Findings | Output File |\n")
        f.write("|------|--------|----------|----------|-------------|\n")
        for name, res in summary.tool_results.items():
            status_icon = "✅" if res.status == "SUCCESS" else ("⚠️" if res.status == "TIMEOUT" else "❌")
            output_rel = os.path.basename(res.output_file) if res.output_file else "—"
            f.write(f"| `{name}` | {status_icon} {res.status} | {res.duration}s | {len(res.findings)} | `{output_rel}` |\n")

        f.write("\n---\n\n")

        # Findings Detail
        f.write("## 3. Discovered Vulnerabilities & Findings\n\n")
        if not summary.all_findings:
            f.write("_No critical or high-risk vulnerabilities were identified by the executed modules._\n\n")
        else:
            sorted_findings = sorted(summary.all_findings, key=lambda x: x.severity.score, reverse=True)
            for i, fnd in enumerate(sorted_findings, 1):
                sev_badge = f"**[{fnd.severity.value}]**"
                f.write(f"### {i}. {sev_badge} {fnd.title}\n\n")
                f.write(f"- **Source Tool:** `{fnd.tool}`\n")
                if fnd.matched_at:
                    f.write(f"- **Location / Target:** `{fnd.matched_at}`\n")
                if fnd.template_id:
                    f.write(f"- **Template / Rule ID:** `{fnd.template_id}`\n")
                if fnd.cve_ids:
                    f.write(f"- **CVE Identifiers:** {', '.join([f'`{c}`' for c in fnd.cve_ids])}\n")
                if fnd.remediation:
                    f.write(f"- **Remediation Recommendation:** {fnd.remediation}\n")
                f.write(f"\n> {fnd.description}\n\n")

        f.write("---\n\n")

        # Detailed Raw Tool Outputs
        f.write("## 4. Raw Scanner Outputs\n\n")
        for name, res in summary.tool_results.items():
            f.write(f"### Scanner: {name}\n\n")
            if res.output_file and os.path.isfile(res.output_file):
                try:
                    with open(res.output_file, "r", encoding="utf-8", errors="ignore") as rf:
                        content = rf.read()
                        f.write("```\n")
                        f.write(content[:4000])
                        if len(content) > 4000:
                            f.write(f"\n... [Truncated: see {os.path.basename(res.output_file)} for full {len(content)} bytes]\n")
                        f.write("```\n\n")
                except Exception as e:
                    f.write(f"_Error reading output file: {e}_\n\n")
            elif res.stdout:
                f.write("```\n")
                f.write(res.stdout[:4000])
                f.write("\n```\n\n")
            else:
                f.write(f"_No output recorded ({res.status})_\n\n")

        f.write("---\n")
        f.write(f"\n*Report generated automatically by WADI-X v3.1.0 at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n")

    return file_path

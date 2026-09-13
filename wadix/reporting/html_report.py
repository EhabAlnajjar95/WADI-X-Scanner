"""
Offline, self-contained modern HTML security report dashboard.
"""

import os
import html
from datetime import datetime
from wadix.reporting.models import ScanSummary, Severity

def generate_html_report(summary: ScanSummary, file_path: str) -> str:
    """Produce a modern, offline-ready HTML assessment dashboard."""
    summary.calculate_counts()
    os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)

    crit_cnt = summary.severity_counts.get(Severity.CRITICAL.value, 0)
    high_cnt = summary.severity_counts.get(Severity.HIGH.value, 0)
    med_cnt  = summary.severity_counts.get(Severity.MEDIUM.value, 0)
    low_cnt  = summary.severity_counts.get(Severity.LOW.value, 0)
    info_cnt = summary.severity_counts.get(Severity.INFO.value, 0)
    total_cnt = len(summary.all_findings)

    # Prepare tools rows
    tools_rows = ""
    for name, res in summary.tool_results.items():
        badge_cls = "badge-success" if res.status == "SUCCESS" else ("badge-warning" if res.status == "TIMEOUT" else "badge-danger")
        tools_rows += f"""
        <tr>
            <td><strong>{html.escape(name)}</strong></td>
            <td>{html.escape(res.description)}</td>
            <td><span class="badge {badge_cls}">{html.escape(res.status)}</span></td>
            <td>{res.duration:.2f}s</td>
            <td><strong>{len(res.findings)}</strong></td>
            <td><code>{html.escape(os.path.basename(res.output_file) if res.output_file else 'None')}</code></td>
        </tr>
        """

    # Prepare findings cards
    findings_html = ""
    sorted_findings = sorted(summary.all_findings, key=lambda x: x.severity.score, reverse=True)
    if not sorted_findings:
        findings_html = "<div class='empty-state'>No security findings or vulnerabilities identified.</div>"
    else:
        for i, fnd in enumerate(sorted_findings, 1):
            sev_class = fnd.severity.value.lower()
            cve_badges = "".join([f"<span class='tag-cve'>{html.escape(c)}</span>" for c in fnd.cve_ids])
            tpl_badge = f"<span class='tag-tpl'>{html.escape(fnd.template_id)}</span>" if fnd.template_id else ""

            findings_html += f"""
            <div class="finding-card border-{sev_class}">
                <div class="finding-header">
                    <span class="severity-pill pill-{sev_class}">{fnd.severity.value}</span>
                    <h3 class="finding-title">{i}. {html.escape(fnd.title)}</h3>
                    <span class="tool-tag">{html.escape(fnd.tool)}</span>
                </div>
                <div class="finding-body">
                    <p class="finding-desc">{html.escape(fnd.description)}</p>
                    <div class="meta-row">
                        {f"<strong>Target:</strong> <code>{html.escape(fnd.matched_at)}</code>" if fnd.matched_at else ""}
                        {tpl_badge}
                        {cve_badges}
                    </div>
                    {f"<div class='remediation'><strong>Remediation:</strong> {html.escape(fnd.remediation)}</div>" if fnd.remediation else ""}
                </div>
            </div>
            """

    # Prepare raw tool tabs/sections
    raw_sections = ""
    for name, res in summary.tool_results.items():
        content = ""
        if res.output_file and os.path.isfile(res.output_file):
            try:
                with open(res.output_file, "r", encoding="utf-8", errors="ignore") as rf:
                    content = rf.read()[:8000]
            except Exception:
                content = res.stdout[:8000]
        else:
            content = res.stdout[:8000] if res.stdout else f"No logs available ({res.status})"

        raw_sections += f"""
        <details class="raw-details">
            <summary><strong>{html.escape(name)}</strong> ({html.escape(res.status)} - {res.duration}s)</summary>
            <pre class="raw-box"><code>{html.escape(content)}</code></pre>
        </details>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WADI-X Security Assessment Report — {html.escape(summary.target_host)}</title>
    <style>
        :root {{
            --bg: #0d1117;
            --surface: #161b22;
            --surface-hover: #21262d;
            --border: #30363d;
            --text: #c9d1d9;
            --text-heading: #f0f6fc;
            --cyan: #58a6ff;
            --magenta: #d2a8ff;
            --red: #f85149;
            --orange: #f0883e;
            --yellow: #d29922;
            --blue: #388bfd;
            --green: #3fb950;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, monospace; }}
        body {{ background-color: var(--bg); color: var(--text); padding: 2rem; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        
        /* Header */
        .header {{ background: linear-gradient(135deg, #161b22 0%, #1f1b2e 100%); border: 1px solid var(--border); border-radius: 12px; padding: 2rem; margin-bottom: 2rem; box-shadow: 0 8px 24px rgba(0,0,0,0.4); }}
        .logo-title {{ font-size: 2rem; color: var(--cyan); margin-bottom: 0.5rem; display: flex; align-items: center; gap: 10px; font-weight: 800; }}
        .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-top: 1.5rem; }}
        .meta-item {{ background: var(--surface); padding: 0.75rem 1rem; border-radius: 6px; border: 1px solid var(--border); font-size: 0.9rem; }}
        .meta-item span {{ color: #8b949e; display: block; font-size: 0.8rem; text-transform: uppercase; }}

        /* Stats Cards */
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .stat-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; text-align: center; }}
        .stat-number {{ font-size: 2.2rem; font-weight: bold; margin-bottom: 0.25rem; }}
        .stat-label {{ font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600; }}
        .critical {{ color: var(--red); }}
        .high {{ color: var(--orange); }}
        .medium {{ color: var(--yellow); }}
        .low {{ color: var(--cyan); }}
        .info {{ color: var(--blue); }}
        .total {{ color: var(--magenta); }}

        /* Section */
        .section-title {{ font-size: 1.4rem; color: var(--text-heading); margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}

        /* Table */
        table {{ width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; border: 1px solid var(--border); margin-bottom: 2rem; }}
        th, td {{ padding: 0.9rem 1.2rem; text-align: left; border-bottom: 1px solid var(--border); }}
        th {{ background: #1f242c; color: var(--text-heading); font-weight: 600; font-size: 0.9rem; }}
        tr:hover {{ background: var(--surface-hover); }}

        /* Badges */
        .badge {{ display: inline-block; padding: 0.25rem 0.6rem; font-size: 0.75rem; font-weight: bold; border-radius: 20px; }}
        .badge-success {{ background: rgba(63, 185, 80, 0.2); color: var(--green); border: 1px solid var(--green); }}
        .badge-warning {{ background: rgba(210, 153, 34, 0.2); color: var(--yellow); border: 1px solid var(--yellow); }}
        .badge-danger {{ background: rgba(248, 81, 73, 0.2); color: var(--red); border: 1px solid var(--red); }}

        /* Findings */
        .finding-card {{ background: var(--surface); border-radius: 8px; margin-bottom: 1rem; padding: 1.25rem; border: 1px solid var(--border); border-left: 5px solid var(--border); }}
        .border-critical {{ border-left-color: var(--red); }}
        .border-high {{ border-left-color: var(--orange); }}
        .border-medium {{ border-left-color: var(--yellow); }}
        .border-low {{ border-left-color: var(--cyan); }}
        .border-info {{ border-left-color: var(--blue); }}

        .finding-header {{ display: flex; align-items: center; gap: 12px; margin-bottom: 0.75rem; }}
        .finding-title {{ font-size: 1.1rem; color: var(--text-heading); flex-grow: 1; }}
        .severity-pill {{ padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; }}
        .pill-critical {{ background: var(--red); color: #fff; }}
        .pill-high {{ background: var(--orange); color: #fff; }}
        .pill-medium {{ background: var(--yellow); color: #000; }}
        .pill-low {{ background: var(--cyan); color: #000; }}
        .pill-info {{ background: var(--blue); color: #fff; }}

        .tool-tag {{ background: #21262d; border: 1px solid var(--border); padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; }}
        .meta-row {{ margin-top: 0.75rem; font-size: 0.85rem; display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }}
        .tag-cve {{ background: rgba(248, 81, 73, 0.15); border: 1px solid var(--red); color: var(--red); padding: 0.15rem 0.4rem; border-radius: 3px; font-size: 0.75rem; }}
        .tag-tpl {{ background: rgba(88, 166, 255, 0.15); border: 1px solid var(--cyan); color: var(--cyan); padding: 0.15rem 0.4rem; border-radius: 3px; font-size: 0.75rem; }}
        .remediation {{ margin-top: 0.75rem; background: rgba(63, 185, 80, 0.1); border-left: 3px solid var(--green); padding: 0.6rem 1rem; border-radius: 4px; font-size: 0.85rem; }}

        /* Raw box */
        .raw-details {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px; margin-bottom: 0.75rem; }}
        .raw-details summary {{ padding: 0.8rem 1.2rem; cursor: pointer; user-select: none; color: var(--cyan); }}
        .raw-box {{ padding: 1rem; background: #090d13; overflow-x: auto; font-family: monospace; font-size: 0.8rem; max-height: 400px; color: #7ee787; border-top: 1px solid var(--border); }}

        footer {{ text-align: center; margin-top: 3rem; color: #8b949e; font-size: 0.85rem; }}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="logo-title">
                <span>🛡️ WADI-X Security Assessment</span>
            </div>
            <p>Automated vulnerability assessment, technology fingerprinting & service enumeration dashboard.</p>
            <div class="meta-grid">
                <div class="meta-item"><span>Target URL</span><strong>{html.escape(summary.target_url)}</strong></div>
                <div class="meta-item"><span>Host / Port</span><strong>{html.escape(summary.target_host)}:{summary.target_port}</strong></div>
                <div class="meta-item"><span>Scan Profile</span><strong>{html.escape(summary.scan_profile)}</strong></div>
                <div class="meta-item"><span>Date & Duration</span><strong>{summary.start_time} ({summary.total_duration_seconds}s)</strong></div>
            </div>
        </header>

        <!-- Stats Overview -->
        <div class="stats-grid">
            <div class="stat-card"><div class="stat-number critical">{crit_cnt}</div><div class="stat-label critical">Critical</div></div>
            <div class="stat-card"><div class="stat-number high">{high_cnt}</div><div class="stat-label high">High</div></div>
            <div class="stat-card"><div class="stat-number medium">{med_cnt}</div><div class="stat-label medium">Medium</div></div>
            <div class="stat-card"><div class="stat-number low">{low_cnt}</div><div class="stat-label low">Low</div></div>
            <div class="stat-card"><div class="stat-number info">{info_cnt}</div><div class="stat-label info">Info</div></div>
            <div class="stat-card"><div class="stat-number total">{total_cnt}</div><div class="stat-label total">Total Findings</div></div>
        </div>

        <!-- Tool Execution Summary -->
        <h2 class="section-title">Security Modules Execution Status</h2>
        <table>
            <thead>
                <tr>
                    <th>Module</th>
                    <th>Description</th>
                    <th>Status</th>
                    <th>Duration</th>
                    <th>Findings</th>
                    <th>Log File</th>
                </tr>
            </thead>
            <tbody>
                {tools_rows}
            </tbody>
        </table>

        <!-- Findings List -->
        <h2 class="section-title">Discovered Findings & Exposures</h2>
        <div class="findings-list">
            {findings_html}
        </div>

        <!-- Raw Scanner Logs -->
        <h2 class="section-title">Raw Scanner Output Logs</h2>
        {raw_sections}

        <footer>
            WADI-X Security Scanner Orchestrator v3.1.0 • Stay Legal. Stay Ethical. • Report Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </footer>
    </div>
</body>
</html>
"""
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    return file_path

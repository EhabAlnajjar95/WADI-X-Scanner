"""
Unit tests for report generation (Markdown, JSON, HTML).
"""

import unittest
import os
import json
import tempfile
from wadix.reporting.models import ScanSummary, ToolResult, Finding, Severity
from wadix.reporting.markdown import generate_markdown_report
from wadix.reporting.json_report import generate_json_report
from wadix.reporting.html_report import generate_html_report

class TestReporting(unittest.TestCase):

    def setUp(self):
        self.findings = [
            Finding(
                tool="nuclei",
                title="Git Repository Directory Traversal",
                severity=Severity.CRITICAL,
                description="Sensitive .git folder exposed to unauthenticated users.",
                matched_at="https://example.com/.git/",
                template_id="http-git-exposure",
                cve_ids=["CVE-2021-1234"],
            ),
            Finding(
                tool="nikto",
                title="Missing X-Frame-Options Header",
                severity=Severity.LOW,
                description="Clickjacking vulnerability due to missing header.",
                matched_at="https://example.com/",
            ),
        ]
        self.summary = ScanSummary(
            target_url="https://example.com/",
            target_host="example.com",
            target_port=443,
            scan_profile="SMART",
            start_time="2026-09-13 10:00:00",
            end_time="2026-09-13 10:05:00",
            total_duration_seconds=300.0,
            output_directory="",
            tool_results={
                "nuclei": ToolResult(
                    tool_name="nuclei",
                    description="Vulnerability scanner",
                    status="SUCCESS",
                    return_code=0,
                    duration=45.2,
                    findings=[self.findings[0]],
                ),
                "nikto": ToolResult(
                    tool_name="nikto",
                    description="Web server scanner",
                    status="SUCCESS",
                    return_code=0,
                    duration=60.0,
                    findings=[self.findings[1]],
                ),
            },
            all_findings=self.findings,
        )

    def test_markdown_report(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "REPORT.md")
            generate_markdown_report(self.summary, out_file)
            self.assertTrue(os.path.exists(out_file))

            with open(out_file, "r", encoding="utf-8") as f:
                content = f.read()

            self.assertIn("# WADI-X Security Assessment Report", content)
            self.assertIn("CRITICAL", content)
            self.assertIn("Git Repository Directory Traversal", content)
            self.assertIn("CVE-2021-1234", content)

    def test_json_report(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "report.json")
            generate_json_report(self.summary, out_file)
            self.assertTrue(os.path.exists(out_file))

            with open(out_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            self.assertEqual(data["metadata"]["target_host"], "example.com")
            self.assertEqual(data["summary"]["total_findings"], 2)
            self.assertEqual(data["summary"]["severity_breakdown"]["CRITICAL"], 1)
            self.assertEqual(len(data["findings"]), 2)

    def test_html_report(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "report.html")
            generate_html_report(self.summary, out_file)
            self.assertTrue(os.path.exists(out_file))

            with open(out_file, "r", encoding="utf-8") as f:
                content = f.read()

            self.assertIn("WADI-X Security Assessment", content)
            self.assertIn("Git Repository Directory Traversal", content)
            self.assertIn("badge-success", content)
            self.assertIn("CVE-2021-1234", content)


if __name__ == "__main__":
    unittest.main()

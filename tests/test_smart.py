"""
Unit tests for Smart Scan technology detection and planner.
"""

import unittest
import tempfile
from wadix.core.target import normalize_target
from wadix.core.executor import CommandExecutor
from wadix.scanners.recon import WhatWebScanner
from wadix.engine.smart import SmartScanEngine

class TestSmartScan(unittest.TestCase):

    def test_extract_technologies(self):
        sample_output = "http://example.com [200 OK] Apache[2.4.41], WordPress[6.1.1], PHP[8.0], JQuery"
        techs = WhatWebScanner.extract_technologies(sample_output)
        self.assertIn("wordpress", techs)
        self.assertIn("apache", techs)
        self.assertIn("php", techs)
        self.assertNotIn("drupal", techs)

    def test_smart_plan_dry_run(self):
        executor = CommandExecutor(dry_run=True)
        engine = SmartScanEngine(executor)
        target = normalize_target("https://example.com")

        with tempfile.TemporaryDirectory() as tmpdir:
            scanners, detected_techs = engine.plan_smart_scan(target, tmpdir)
            scanner_names = [s.name for s in scanners]

            # Common baseline scanners should be present
            self.assertIn("nmap", scanner_names)
            self.assertIn("subfinder", scanner_names)
            self.assertIn("testssl", scanner_names)
            self.assertIn("nikto", scanner_names)
            self.assertIn("gobuster", scanner_names)
            self.assertIn("nuclei", scanner_names)


if __name__ == "__main__":
    unittest.main()

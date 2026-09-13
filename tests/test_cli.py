"""
Unit tests for CLI argument parsing and custom tools parser.
"""

import unittest
from wadix.cli import build_arg_parser, parse_custom_selection

class TestCLI(unittest.TestCase):

    def setUp(self):
        self.parser = build_arg_parser()

    def test_cli_arguments(self):
        args = self.parser.parse_args([
            "--target", "https://example.com",
            "--profile", "smart",
            "--dry-run",
            "--yes",
            "--no-install",
            "--verbose",
        ])
        self.assertEqual(args.target, "https://example.com")
        self.assertEqual(args.profile, "smart")
        self.assertTrue(args.dry_run)
        self.assertTrue(args.yes)
        self.assertTrue(args.no_install)
        self.assertTrue(args.verbose)

    def test_parse_custom_selection(self):
        # Numeric single
        res1 = parse_custom_selection("1")
        self.assertEqual(res1, ["nmap"])

        # Numeric comma-separated
        res2 = parse_custom_selection("1, 2, 6")
        self.assertEqual(res2, ["nmap", "whatweb", "nuclei"])

        # Range
        res3 = parse_custom_selection("1-3")
        self.assertEqual(res3, ["nmap", "whatweb", "testssl"])

        # Tool names
        res4 = parse_custom_selection("nikto, ffuf")
        self.assertEqual(res4, ["nikto", "ffuf"])

        # 'all'
        res5 = parse_custom_selection("all")
        self.assertGreaterEqual(len(res5), 10)


if __name__ == "__main__":
    unittest.main()

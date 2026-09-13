"""
Unit tests for target normalization and validation.
"""

import unittest
from wadix.core.target import normalize_target, is_valid_ip, is_valid_hostname

class TestTargetNormalization(unittest.TestCase):

    def test_domain_normalization(self):
        target = normalize_target("example.com")
        self.assertEqual(target.host, "example.com")
        self.assertEqual(target.scheme, "https")
        self.assertEqual(target.port, 443)
        self.assertEqual(target.url, "https://example.com/")
        self.assertFalse(target.is_ip)

    def test_http_scheme_and_custom_port(self):
        target = normalize_target("http://192.168.1.50:8080/test")
        self.assertEqual(target.host, "192.168.1.50")
        self.assertEqual(target.scheme, "http")
        self.assertEqual(target.port, 8080)
        self.assertEqual(target.path, "/test")
        self.assertTrue(target.is_ip)
        self.assertEqual(target.url, "http://192.168.1.50:8080/test")

    def test_localhost(self):
        target = normalize_target("localhost:3000")
        self.assertEqual(target.host, "localhost")
        self.assertEqual(target.port, 3000)

    def test_invalid_targets(self):
        invalid_inputs = [
            "",
            "   ",
            "example.com; rm -rf /",
            "example.com && whoami",
            "example.com|cat /etc/passwd",
            "http://example .com",
            "ftp://example.com",
            "999.999.999.999",
            "invalid..domain",
        ]
        for bad in invalid_inputs:
            with self.subTest(target=bad):
                with self.assertRaises(ValueError):
                    normalize_target(bad)

    def test_safe_name_generation(self):
        t1 = normalize_target("https://scanme.nmap.org")
        self.assertEqual(t1.safe_name, "scanme.nmap.org")

        t2 = normalize_target("http://test.local:8080")
        self.assertEqual(t2.safe_name, "test.local_8080")


if __name__ == "__main__":
    unittest.main()

"""
Unit tests for command executor and dry-run functionality.
"""

import unittest
import os
import sys
import tempfile
from wadix.core.executor import CommandExecutor

class TestCommandExecutor(unittest.TestCase):

    def test_dry_run_mode(self):
        executor = CommandExecutor(dry_run=True)
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "test.txt")
            cmd = ["nmap", "-sV", "localhost"]
            res = executor.run(cmd, output_file=out_file)

            self.assertTrue(res.success)
            self.assertEqual(res.returncode, 0)
            self.assertTrue(os.path.exists(out_file))
            with open(out_file, "r") as f:
                content = f.read()
            self.assertIn("[DRY-RUN]", content)

    def test_real_python_execution(self):
        executor = CommandExecutor(dry_run=False)
        cmd = [sys.executable, "-c", "print('hello wadix')"]
        res = executor.run(cmd)

        self.assertTrue(res.success)
        self.assertEqual(res.returncode, 0)
        self.assertIn("hello wadix", res.stdout)

    def test_timeout_handling(self):
        executor = CommandExecutor(dry_run=False)
        # Sleep for 5 seconds with a 1 second timeout
        cmd = [sys.executable, "-c", "import time; time.sleep(5)"]
        res = executor.run(cmd, timeout=1)

        self.assertFalse(res.success)
        self.assertTrue(res.timed_out)
        self.assertIn("timed out", (res.error_message or "").lower())


if __name__ == "__main__":
    unittest.main()

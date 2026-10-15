#!/usr/bin/env python3
# Copyright 2026 DNS Events contributors
# SPDX-License-Identifier: Apache-2.0
"""Offline regression tests for the opt-in integration harness."""
import os
import collections
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch

from integration import check_rows, delivery_summary, executable


class ExecutablePathTest(unittest.TestCase):
    def test_preserves_shell_symlink_name(self):
        with tempfile.TemporaryDirectory() as directory:
            daemon = Path(directory) / "osqueryd"
            daemon.write_text("#!/bin/sh\nexit 0\n")
            daemon.chmod(0o755)
            shell = Path(directory) / "osqueryi"
            shell.symlink_to(daemon)
            # Resolving this symlink would silently select daemon mode.
            self.assertEqual(executable(str(shell)), str(shell))
            self.assertNotEqual(executable(str(shell)), str(daemon))
            with patch.dict(os.environ, {"PATH": directory}):
                self.assertEqual(executable("osqueryi"), str(shell))

    def test_rejects_nonexecutable_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "osqueryi"
            path.write_text("not executable")
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                executable(str(path))


class DeliveryDiagnosticTest(unittest.TestCase):
    def test_large_failures_have_bounded_samples(self):
        ids = {str(number) for number in range(5000)}
        counts = {"fast": collections.Counter({"1": 2, "2": 1})}
        summary = delivery_summary(ids, counts)["fast"]
        self.assertEqual(summary["expected"], 5000)
        self.assertEqual(summary["received"], 2)
        self.assertEqual(summary["missing"], 4998)
        self.assertEqual(len(summary["missing_sample"]), 10)
        self.assertEqual(summary["duplicate_sample"], [("1", 2)])


class IntegrationAssertionTest(unittest.TestCase):
    def test_rejects_two_a_starts_instead_of_a_and_aaaa(self):
        common = {"domain": "example.com.", "redacted": "0", "correlated": "1"}
        rows = [dict(common, kind="query", query_type="A", answer=""),
                dict(common, kind="query", query_type="A", answer=""),
                dict(common, kind="answer", query_type="A", answer="192.0.2.1")]
        with self.assertRaises(AssertionError):
            check_rows(rows, 1, False)
        rows[1]["query_type"] = "AAAA"
        check_rows(rows, 1, False)

    def test_tagged_masked_rows_are_accepted_without_profile(self):
        common = {"domain": "<dn:v4mDGw>", "redacted": "1", "correlated": "1"}
        rows = [dict(common, kind="query", query_type="A", answer=""),
                dict(common, kind="query", query_type="AAAA", answer=""),
                dict(common, kind="answer", query_type="A", answer="<rd:qpFUdQ>")]
        check_rows(rows, 1, False)
        with self.assertRaises(AssertionError):
            check_rows(rows, 1, True)

    def test_optimized_cli_fails_before_launching_any_process(self):
        script = Path(__file__).with_name("integration.py")
        result = subprocess.run([sys.executable, "-O", "-B", str(script)],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertIn("Run without -O or PYTHONOPTIMIZE", result.stderr)
        self.assertNotIn("Isolated test state:", result.stderr)


if __name__ == "__main__":
    unittest.main()

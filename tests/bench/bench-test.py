#!/usr/bin/env python3
"""Benchmark tests for wolfCLU."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import run_wolfssl, test_main


class BenchTest(unittest.TestCase):

    def test_bench_aes_cbc(self):
        result = run_wolfssl("-bench", "aes-cbc", "-time", "1")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_bench_sha(self):
        result = run_wolfssl("-bench", "sha", "-time", "1")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_bench_md5(self):
        result = run_wolfssl("-bench", "md5", "-time", "1")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_bench_missing_time_value(self):
        """-time with no value must fail gracefully (no segfault)."""
        result = run_wolfssl("-bench", "-time")
        self.assertNotEqual(result.returncode, 0,
                            "expected failure for missing -time value")
        self.assertGreaterEqual(result.returncode, 0,
                                "-bench -time crashed with signal "
                                "{}".format(result.returncode))


if __name__ == "__main__":
    test_main()

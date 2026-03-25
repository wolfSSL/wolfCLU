#!/usr/bin/env python3
"""Random number generation tests for wolfCLU."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import run_wolfssl


class RandTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        config_log = os.path.join(".", "config.log")
        if os.path.isfile(config_log):
            with open(config_log, "r") as f:
                if "disable-filesystem" in f.read():
                    raise unittest.SkipTest("filesystem support disabled")

    def test_base64_random(self):
        r = run_wolfssl("rand", "-base64", "10")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_base64_not_repeated(self):
        r1 = run_wolfssl("rand", "-base64", "10")
        self.assertEqual(r1.returncode, 0, r1.stderr)

        r2 = run_wolfssl("rand", "-base64", "10")
        self.assertEqual(r2.returncode, 0, r2.stderr)

        self.assertNotEqual(r1.stdout, r2.stdout,
                            "back-to-back random calls should differ")

    def test_output_file(self):
        out = "entropy.txt"
        self.addCleanup(lambda: os.remove(out)
                        if os.path.exists(out) else None)

        r = run_wolfssl("rand", "-out", out, "20")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(out), "entropy.txt not created")


if __name__ == "__main__":
    unittest.main()

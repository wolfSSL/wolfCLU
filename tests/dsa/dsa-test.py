#!/usr/bin/env python3
"""DSA parameter tests for wolfCLU."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import CERTS_DIR, no_filesystem, run_wolfssl, test_main


# `dsaparam` generates to stdout without a filesystem, so only the tests that
# pass a file path are skipped on a --disable-filesystem build.
needs_filesystem = unittest.skipIf(no_filesystem(),
                                   "filesystem support disabled")


class DsaParamTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

        # Skip if DSA not compiled in
        r = run_wolfssl("dsaparam", "1024")
        combined = r.stdout + r.stderr
        if "DSA support not compiled into wolfSSL" in combined:
            raise unittest.SkipTest("DSA support not compiled in")

    def test_dsaparam_stdout(self):
        r = run_wolfssl("dsaparam", "1024")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("-----BEGIN DSA PARAMETERS-----", r.stdout)

    def test_dsaparam_zero_fails(self):
        r = run_wolfssl("dsaparam", "0")
        self.assertNotEqual(r.returncode, 0)

    @needs_filesystem
    def test_dsaparam_out_and_in(self):
        params_file = "dsa.params"
        self.addCleanup(lambda: os.remove(params_file)
                        if os.path.exists(params_file) else None)

        r = run_wolfssl("dsaparam", "-out", params_file, "1024")
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("dsaparam", "-in", params_file)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("-----BEGIN DSA PARAMETERS-----", r.stdout)

    @needs_filesystem
    def test_dsaparam_noout(self):
        params_file = "dsa.params"
        self.addCleanup(lambda: os.remove(params_file)
                        if os.path.exists(params_file) else None)

        r = run_wolfssl("dsaparam", "-out", params_file, "1024")
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("dsaparam", "-in", params_file, "-noout")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("-----BEGIN DSA PARAMETERS-----", r.stdout)

    @needs_filesystem
    def test_dsaparam_genkey(self):
        params_file = "dsa.params"
        self.addCleanup(lambda: os.remove(params_file)
                        if os.path.exists(params_file) else None)

        r = run_wolfssl("dsaparam", "-out", params_file, "1024")
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("dsaparam", "-in", params_file, "-genkey")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("-----BEGIN DSA PARAMETERS-----", r.stdout)
        self.assertIn("-----BEGIN DSA PRIVATE KEY-----", r.stdout)

    @needs_filesystem
    def test_dsaparam_genkey_noout(self):
        params_file = "dsa.params"
        self.addCleanup(lambda: os.remove(params_file)
                        if os.path.exists(params_file) else None)

        r = run_wolfssl("dsaparam", "-out", params_file, "1024")
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("dsaparam", "-in", params_file, "-genkey", "-noout")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("-----BEGIN DSA PARAMETERS-----", r.stdout)
        self.assertIn("-----BEGIN DSA PRIVATE KEY-----", r.stdout)

    @needs_filesystem
    def test_bad_input_fails(self):
        r = run_wolfssl("dsaparam", "-in",
                        os.path.join(CERTS_DIR, "server-cert.pem"),
                        "-genkey", "-noout")
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    test_main()

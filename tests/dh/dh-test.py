#!/usr/bin/env python3
"""DH parameter tests for wolfCLU."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import CERTS_DIR, run_wolfssl


class DhParamTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

        config_log = os.path.join(".", "config.log")
        if os.path.isfile(config_log):
            with open(config_log, "r") as f:
                if "disable-filesystem" in f.read():
                    raise unittest.SkipTest("filesystem support disabled")

        # Skip if DH not compiled in
        r = run_wolfssl("dhparam", "1024")
        combined = r.stdout + r.stderr
        if "DH support not compiled into wolfSSL" in combined:
            raise unittest.SkipTest("DH support not compiled in")

    def test_dhparam_stdout(self):
        r = run_wolfssl("dhparam", "1024")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("-----BEGIN DH PARAMETERS-----", r.stdout)

    def test_dhparam_zero_fails(self):
        r = run_wolfssl("dhparam", "0")
        self.assertNotEqual(r.returncode, 0)

    def test_dhparam_out_and_in(self):
        params_file = "dh.params"
        self.addCleanup(lambda: os.remove(params_file)
                        if os.path.exists(params_file) else None)

        r = run_wolfssl("dhparam", "-out", params_file, "1024")
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("dhparam", "-in", params_file)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("-----BEGIN DH PARAMETERS-----", r.stdout)

    def test_dhparam_out_after_size(self):
        """Test -out flag after the size argument."""
        params_file = "dh.params"
        self.addCleanup(lambda: os.remove(params_file)
                        if os.path.exists(params_file) else None)

        r = run_wolfssl("dhparam", "1024", "-out", params_file)
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("dhparam", "-in", params_file)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("-----BEGIN DH PARAMETERS-----", r.stdout)

    def test_dhparam_noout(self):
        params_file = "dh.params"
        self.addCleanup(lambda: os.remove(params_file)
                        if os.path.exists(params_file) else None)

        r = run_wolfssl("dhparam", "1024", "-out", params_file)
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("dhparam", "-in", params_file, "-noout")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("-----BEGIN DH PARAMETERS-----", r.stdout)

    def test_dhparam_genkey(self):
        params_file = "dh.params"
        self.addCleanup(lambda: os.remove(params_file)
                        if os.path.exists(params_file) else None)

        r = run_wolfssl("dhparam", "1024", "-out", params_file)
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("dhparam", "-in", params_file, "-genkey")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("-----BEGIN DH PARAMETERS-----", r.stdout)
        self.assertIn("-----BEGIN PRIVATE KEY-----", r.stdout)

    def test_dhparam_genkey_noout(self):
        params_file = "dh.params"
        self.addCleanup(lambda: os.remove(params_file)
                        if os.path.exists(params_file) else None)

        r = run_wolfssl("dhparam", "1024", "-out", params_file)
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("dhparam", "-in", params_file, "-genkey", "-noout")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("-----BEGIN DH PARAMETERS-----", r.stdout)
        self.assertIn("-----BEGIN PRIVATE KEY-----", r.stdout)

    def test_bad_input_fails(self):
        r = run_wolfssl("dhparam", "-in",
                        os.path.join(CERTS_DIR, "server-cert.pem"),
                        "-genkey", "-noout")
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()

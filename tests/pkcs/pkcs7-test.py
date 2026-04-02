#!/usr/bin/env python3
"""PKCS7 tests for wolfCLU."""

import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import WOLFSSL_BIN, CERTS_DIR, run_wolfssl, test_main


class Pkcs7Test(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

        config_log = os.path.join(".", "config.log")
        if os.path.isfile(config_log):
            with open(config_log, "r") as f:
                if "disable-filesystem" in f.read():
                    raise unittest.SkipTest("filesystem support disabled")

        r = run_wolfssl("pkcs7", "-inform", "DER", "-in",
                        os.path.join(CERTS_DIR, "signed.p7b"))
        combined = r.stdout + r.stderr
        if "Recompile wolfSSL with PKCS7 support" in combined:
            raise unittest.SkipTest("PKCS7 support not compiled in")

    def test_print_certs(self):
        r = run_wolfssl("pkcs7", "-inform", "DER", "-print_certs",
                        "-in", os.path.join(CERTS_DIR, "signed.p7b"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("CERTIFICATE", r.stdout)

    def test_der_to_pem(self):
        r = run_wolfssl("pkcs7", "-inform", "DER",
                        "-in", os.path.join(CERTS_DIR, "signed.p7b"),
                        "-outform", "PEM")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("BEGIN PKCS7", r.stdout)

    def test_pem_to_der(self):
        # Output is binary DER, so avoid text decoding
        r = subprocess.run(
            [WOLFSSL_BIN, "pkcs7", "-inform", "PEM",
             "-in", os.path.join(CERTS_DIR, "signed.p7s"),
             "-outform", "DER"],
            capture_output=True, stdin=subprocess.DEVNULL,
            timeout=60,
        )
        self.assertEqual(r.returncode, 0, r.stderr)

    @unittest.skipIf(sys.platform == "win32",
                      "binary DER stdin is unreliable on Windows")
    def test_stdin_input(self):
        p7b_path = os.path.join(CERTS_DIR, "signed.p7b")
        with open(p7b_path, "rb") as f:
            data = f.read()

        r = subprocess.run(
            [WOLFSSL_BIN, "pkcs7", "-inform", "DER"],
            input=data, capture_output=True, text=False,
            timeout=60,
        )
        self.assertIn(b"BEGIN PKCS7", r.stdout + r.stderr)


if __name__ == "__main__":
    test_main()

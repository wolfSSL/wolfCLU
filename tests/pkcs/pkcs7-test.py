#!/usr/bin/env python3
"""PKCS7 tests for wolfCLU."""

import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import WOLFSSL_BIN, CERTS_DIR, run_wolfssl, test_main


class Pkcs7Test(unittest.TestCase):

    def _cleanup(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: os.remove(p)
                            if os.path.exists(p) else None)


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

    def test_help(self):
        for flag in ("-help", "-h"):
            r = run_wolfssl("pkcs7", flag)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("wolfssl pkcs7", r.stdout + r.stderr)

    def test_bad_argument_shows_help(self):
        r = run_wolfssl("pkcs7", "-not-a-real-option")
        self.assertNotEqual(r.returncode, 0)

    def test_out_to_file(self):
        out = "pkcs7-out.pem"
        self.addCleanup(lambda: os.remove(out) if os.path.exists(out) else None)

        r = run_wolfssl("pkcs7", "-inform", "DER",
                        "-in", os.path.join(CERTS_DIR, "signed.p7b"),
                        "-outform", "PEM", "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(out), "pkcs7 -out did not create file")
        with open(out, "r") as f:
            self.assertIn("BEGIN PKCS7", f.read())

    def test_out_bad_path_fails(self):
        r = run_wolfssl("pkcs7", "-inform", "DER",
                        "-in", os.path.join(CERTS_DIR, "signed.p7b"),
                        "-out", os.path.join("no-such-dir", "out.pem"))
        self.assertNotEqual(r.returncode, 0)

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


    def test_out_without_filename_fails(self):
        """A trailing -out binds a NULL optarg; without the guard the output
        silently goes to stdout with a success exit code."""
        r = run_wolfssl("pkcs7", "-in",
                        os.path.join(CERTS_DIR, "signed.p7b"),
                        "-inform", "der", "-out")
        self.assertNotEqual(r.returncode, 0,
                            "-out without filename must fail")

    def test_in_out_same_file_refused(self):
        """-in and -out naming the same file must be refused."""
        same = "pkcs7_inplace.p7b"
        self._cleanup(same)
        with open(os.path.join(CERTS_DIR, "signed.p7b"), "rb") as src:
            original = src.read()
        with open(same, "wb") as f:
            f.write(original)

        r = run_wolfssl("pkcs7", "-in", same, "-inform", "der",
                        "-out", same, "-outform", "pem")
        self.assertNotEqual(r.returncode, 0,
                            "in-place update must fail")
        with open(same, "rb") as f:
            self.assertEqual(f.read(), original, "-in was modified")


if __name__ == "__main__":
    test_main()

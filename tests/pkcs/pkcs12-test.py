#!/usr/bin/env python3
"""PKCS12 tests for wolfCLU."""

import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import WOLFSSL_BIN, CERTS_DIR, is_fips, run_wolfssl, test_main

P12_FILE = os.path.join(CERTS_DIR, "test-servercert.p12")


class Pkcs12Test(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

        config_log = os.path.join(".", "config.log")
        if os.path.isfile(config_log):
            with open(config_log, "r") as f:
                if "disable-filesystem" in f.read():
                    raise unittest.SkipTest("filesystem support disabled")

        if is_fips():
            raise unittest.SkipTest("FIPS build")

        r = run_wolfssl("pkcs12", "-nodes", "-passin", 'pass:wolfSSL test',
                        "-passout", "pass:", "-in", P12_FILE)
        combined = r.stdout + r.stderr
        if "Recompile wolfSSL with PKCS12 support" in combined:
            raise unittest.SkipTest("PKCS12 support not compiled in")

    def test_nocerts(self):
        r = subprocess.run(
            [WOLFSSL_BIN, "pkcs12", "-nodes", "-nocerts",
             "-passin", "stdin", "-passout", "pass:", "-in", P12_FILE],
            input=b"wolfSSL test\n", capture_output=True, text=False,
            timeout=60,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn(b"CERTIFICATE", r.stdout)

    def test_nokeys(self):
        r = subprocess.run(
            [WOLFSSL_BIN, "pkcs12", "-nokeys",
             "-passin", "stdin", "-passout", "pass:", "-in", P12_FILE],
            input=b"wolfSSL test\n", capture_output=True, text=False,
            timeout=60,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn(b"KEY", r.stdout)

    def test_pass_on_cmdline(self):
        r = run_wolfssl("pkcs12", "-nodes", "-passin", 'pass:wolfSSL test',
                        "-passout", "pass:", "-in", P12_FILE)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_help(self):
        for flag in ("-help", "-h"):
            r = run_wolfssl("pkcs12", flag)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("wolfssl pkcs12", r.stdout + r.stderr)

    def test_bad_argument_fails(self):
        r = run_wolfssl("pkcs12", "-not-a-real-option", "-in", P12_FILE)
        self.assertNotEqual(r.returncode, 0)

    def test_out_to_file(self):
        out = "pkcs12-out.pem"
        self.addCleanup(lambda: os.remove(out) if os.path.exists(out) else None)
        r = run_wolfssl("pkcs12", "-nodes", "-passin", 'pass:wolfSSL test',
                        "-passout", "pass:", "-in", P12_FILE, "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(out), "pkcs12 -out did not create file")
        with open(out, "r") as f:
            self.assertIn("BEGIN ", f.read())

    def test_out_bad_path_fails(self):
        r = run_wolfssl("pkcs12", "-nodes", "-passin", 'pass:wolfSSL test',
                        "-passout", "pass:", "-in", P12_FILE,
                        "-out", os.path.join("no-such-dir", "out.pem"))
        self.assertNotEqual(r.returncode, 0)

    def test_nocerts_with_passout(self):
        r = subprocess.run(
            [WOLFSSL_BIN, "pkcs12", "-passin", "stdin", "-passout", "pass:",
             "-in", P12_FILE, "-nocerts"],
            input=b"wolfSSL test\n", capture_output=True, text=False,
            timeout=60,
        )
        self.assertEqual(r.returncode, 0, r.stderr)


    def test_out_without_filename_fails(self):
        """Trailing -out binds NULL, silently leaking bundle to stdout."""
        r = run_wolfssl("pkcs12", "-nodes", "-passin", 'pass:wolfSSL test',
                        "-passout", "pass:", "-in", P12_FILE, "-out")
        self.assertNotEqual(r.returncode, 0,
                            "-out without filename must fail")
        self.assertNotIn("-----BEGIN", r.stdout,
                         "bundle leaked to stdout")

    def test_in_out_same_file_refused(self):
        """-in and -out naming the same file must be refused."""
        same = "pkcs12_inplace.p12"
        self.addCleanup(
            lambda: os.remove(same) if os.path.exists(same) else None)
        with open(P12_FILE, "rb") as src:
            original = src.read()
        with open(same, "wb") as f:
            f.write(original)

        r = run_wolfssl("pkcs12", "-nodes", "-passin", 'pass:wolfSSL test',
                        "-passout", "pass:", "-in", same, "-out", same)
        self.assertNotEqual(r.returncode, 0,
                            "in-place update must fail")
        with open(same, "rb") as f:
            self.assertEqual(f.read(), original, "-in was modified")


if __name__ == "__main__":
    test_main()

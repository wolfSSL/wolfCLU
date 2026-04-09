#!/usr/bin/env python3
"""PKCS12 tests for wolfCLU."""

import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import WOLFSSL_BIN, CERTS_DIR, run_wolfssl, test_main

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

        # Skip FIPS builds
        r = run_wolfssl("-v")
        if "FIPS" in (r.stdout + r.stderr):
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

    def test_nocerts_with_passout(self):
        r = subprocess.run(
            [WOLFSSL_BIN, "pkcs12", "-passin", "stdin", "-passout", "pass:",
             "-in", P12_FILE, "-nocerts"],
            input=b"wolfSSL test\n", capture_output=True, text=False,
            timeout=60,
        )
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    test_main()

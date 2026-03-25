#!/usr/bin/env python3
"""PKCS8 tests for wolfCLU."""

import filecmp
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import WOLFSSL_BIN, CERTS_DIR, run_wolfssl


def _is_fips():
    r = run_wolfssl("-v")
    return "FIPS" in (r.stdout + r.stderr)


class Pkcs8Test(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

        config_log = os.path.join(".", "config.log")
        if os.path.isfile(config_log):
            with open(config_log, "r") as f:
                if "disable-filesystem" in f.read():
                    raise unittest.SkipTest("filesystem support disabled")

        r = run_wolfssl("pkcs8", "-in",
                        os.path.join(CERTS_DIR, "server-keyEnc.pem"),
                        "-passin", "pass:yassl123")
        combined = r.stdout + r.stderr
        if "Recompile wolfSSL with PKCS8 support" in combined:
            raise unittest.SkipTest("PKCS8 support not compiled in")

        cls.is_fips = _is_fips()

    def _cleanup(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: os.remove(p)
                            if os.path.exists(p) else None)

    def test_decrypt_and_convert(self):
        key_pem = "key.pem"
        pkcs1_pem = "pkcs1.pem"
        key_enc_der = "keyEnc.der"
        self._cleanup(key_pem, pkcs1_pem, key_enc_der)

        if not self.is_fips:
            r = run_wolfssl("pkcs8", "-in",
                            os.path.join(CERTS_DIR, "server-keyEnc.pem"),
                            "-passin", "pass:yassl123",
                            "-outform", "DER", "-out", key_enc_der)
            self.assertEqual(r.returncode, 0, r.stderr)

            r = run_wolfssl("pkcs8", "-in", key_enc_der, "-inform", "DER",
                            "-outform", "PEM", "-out", key_pem)
            self.assertEqual(r.returncode, 0, r.stderr)
        else:
            r = run_wolfssl("pkcs8", "-in",
                            os.path.join(CERTS_DIR, "server-key.pem"),
                            "-outform", "PEM", "-out", key_pem)
            self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("pkcs8", "-in", key_pem, "-topk8", "-nocrypt")
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("pkcs8", "-in", key_pem, "-traditional",
                        "-out", pkcs1_pem)
        self.assertEqual(r.returncode, 0, r.stderr)

        self.assertTrue(
            filecmp.cmp(os.path.join(CERTS_DIR, "server-key.pem"),
                        pkcs1_pem, shallow=False),
            "server-key.pem -traditional check failed")

    @unittest.skipIf(_is_fips(), "skipped in FIPS builds")
    def test_stdin_input(self):
        pem_path = os.path.join(CERTS_DIR, "server-keyEnc.pem")
        with open(pem_path, "rb") as f:
            data = f.read()

        r = subprocess.run(
            [WOLFSSL_BIN, "pkcs8", "-passin", "pass:yassl123"],
            input=data, capture_output=True, text=False,
            timeout=60,
        )
        self.assertIn(b"BEGIN PRIVATE", r.stdout + r.stderr)

    @unittest.skipIf(_is_fips(), "skipped in FIPS builds")
    def test_fail_wrong_input(self):
        r = run_wolfssl("pkcs8", "-in",
                        os.path.join(CERTS_DIR, "server-cert.pem"),
                        "-passin", "pass:yassl123")
        self.assertNotEqual(r.returncode, 0)

    @unittest.skipIf(_is_fips(), "skipped in FIPS builds")
    def test_fail_wrong_password(self):
        r = run_wolfssl("pkcs8", "-in",
                        os.path.join(CERTS_DIR, "server-keyEnc.pem"),
                        "-passin", "pass:wrongPass")
        self.assertNotEqual(r.returncode, 0)

    @unittest.skipIf(_is_fips(), "skipped in FIPS builds")
    def test_fail_wrong_format(self):
        r = run_wolfssl("pkcs8", "-in",
                        os.path.join(CERTS_DIR, "server-keyEnc.pem"),
                        "-inform", "DER", "-passin", "pass:yassl123")
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()

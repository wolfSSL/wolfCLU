#!/usr/bin/env python3
"""PKCS8 tests for wolfCLU."""

import filecmp
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import (WOLFSSL_BIN, CERTS_DIR, HAVE_PTY, is_fips,
                          run_wolfssl, run_wolfssl_pty, test_main)


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

        cls.is_fips = is_fips()

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

    @unittest.skipIf(os.name == "nt", "POSIX file permissions only")
    def test_out_file_owner_only(self):
        """-out holds a private key, so it must be created 0600 (F-9854)."""
        old_umask = os.umask(0o022)
        self.addCleanup(os.umask, old_umask)

        key = os.path.join(CERTS_DIR, "server-key.pem")
        cases = [
            ("perm-pkcs8.pem", ["-in", key, "-outform", "PEM"]),
            ("perm-pkcs8.der", ["-in", key, "-outform", "DER"]),
            ("perm-pkcs1.pem", ["-in", key, "-traditional"]),
        ]
        if not self.is_fips:
            cases.append(("perm-pkcs8-dec.pem",
                          ["-in", os.path.join(CERTS_DIR, "server-keyEnc.pem"),
                           "-passin", "pass:yassl123"]))

        for out, args in cases:
            with self.subTest(out=out):
                self._cleanup(out)
                # Start from a new file so the create mode applies.
                if os.path.exists(out):
                    os.remove(out)
                r = run_wolfssl("pkcs8", *(args + ["-out", out]))
                self.assertEqual(r.returncode, 0, r.stderr)
                mode = os.stat(out).st_mode & 0o777
                self.assertEqual(mode, 0o600,
                                 "{} mode is {:o}, expected 600".format(
                                     out, mode))

    def test_help(self):
        for flag in ("-help", "-h"):
            r = run_wolfssl("pkcs8", flag)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("wolfssl pkcs8", r.stdout + r.stderr)

    def test_bad_argument_fails(self):
        r = run_wolfssl("pkcs8", "-not-a-real-option")
        self.assertNotEqual(r.returncode, 0)

    @unittest.skipIf(is_fips(), "skipped in FIPS builds")
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

    @unittest.skipIf(is_fips(), "skipped in FIPS builds")
    def test_fail_wrong_input(self):
        r = run_wolfssl("pkcs8", "-in",
                        os.path.join(CERTS_DIR, "server-cert.pem"),
                        "-passin", "pass:yassl123")
        self.assertNotEqual(r.returncode, 0)

    @unittest.skipIf(is_fips(), "skipped in FIPS builds")
    def test_fail_wrong_password(self):
        r = run_wolfssl("pkcs8", "-in",
                        os.path.join(CERTS_DIR, "server-keyEnc.pem"),
                        "-passin", "pass:wrongPass")
        self.assertNotEqual(r.returncode, 0)

    @unittest.skipIf(is_fips(), "skipped in FIPS builds")
    def test_fail_wrong_format(self):
        r = run_wolfssl("pkcs8", "-in",
                        os.path.join(CERTS_DIR, "server-keyEnc.pem"),
                        "-inform", "DER", "-passin", "pass:yassl123")
        self.assertNotEqual(r.returncode, 0)

    @unittest.skipUnless(HAVE_PTY, "pty not available")
    def test_password_prompt_eof_fails(self):
        """EOF at the password prompt for an encrypted key must fail cleanly.

        The password buffer was measured with strlen after the failed read,
        although nothing had been written to it."""
        code, out = run_wolfssl_pty(
            "pkcs8", "-in", os.path.join(CERTS_DIR, "server-keyEnc.pem"),
            reply=b"\x04")
        self.assertIn(b"Input Password", out)
        self.assertIn(b"Unable to get password from stdin", out)
        self.assertGreater(code, 0, out)
        self.assertNotIn(b"PRIVATE KEY", out)
        self.assertNotIn(b"AddressSanitizer", out)


if __name__ == "__main__":
    test_main()

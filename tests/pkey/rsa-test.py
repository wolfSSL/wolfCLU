#!/usr/bin/env python3
"""RSA key tests for wolfCLU."""

import filecmp
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import CERTS_DIR, WOLFSSL_BIN, run_wolfssl, test_main

RSA_PUBKEY_PEM = """\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwJUI4VdB8nFtt9JFQScB
ZcZFrvK8JDC4lc4vTtb2HIi8fJ/7qGd//lycUXX3isoH5zUvj+G9e8AvfKtkqBf8
yl17uuAh5XIuby6G2JVz2qwbU7lfP9cZDSVP4WNjUYsLZD+tQ7ilHFw0s64AoGPF
9n8LWWh4c6aMGKkCba/DGQEuuBDjxsxAtGmjRjNph27Euxem8+jdrXO8ey8htf1m
UQy9VLPhbV8cvCNz0QkDiRTSELlkwyrQoZZKvOHUGlvHoMDBY3gPRDcwMpaAMiOV
oXe6E9KXc+JdJclqDcM5YKS0sGlCQgnp2Ai8MyCzWCKnquvE4eZhg8XSlt/Z0E+t
1wIDAQAB
-----END PUBLIC KEY-----"""


def _is_fips():
    r = run_wolfssl("-v")
    return "FIPS" in (r.stdout + r.stderr)


class RsaTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

        config_log = os.path.join(".", "config.log")
        if os.path.isfile(config_log):
            with open(config_log, "r") as f:
                if "disable-filesystem" in f.read():
                    raise unittest.SkipTest("filesystem support disabled")

        cls.is_fips = _is_fips()

    def _cleanup(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: os.remove(p)
                            if os.path.exists(p) else None)

    def test_pem_to_pem(self):
        out = "test-rsa.pem"
        self._cleanup(out)

        r = run_wolfssl("rsa", "-in",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-outform", "PEM", "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(
            filecmp.cmp(os.path.join(CERTS_DIR, "server-key.pem"),
                        out, shallow=False),
            "PEM to PEM mismatch")

    def test_pem_to_der(self):
        out = "test-rsa.der"
        self._cleanup(out)

        r = run_wolfssl("rsa", "-in",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-outform", "DER", "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(
            filecmp.cmp(os.path.join(CERTS_DIR, "server-key.der"),
                        out, shallow=False),
            "PEM to DER mismatch")

    def test_fail_cert_as_key(self):
        r = run_wolfssl("rsa", "-in",
                        os.path.join(CERTS_DIR, "server-cert.pem"))
        self.assertNotEqual(r.returncode, 0)

    def test_fail_rsapublickey_in_cert(self):
        r = run_wolfssl("rsa", "-in",
                        os.path.join(CERTS_DIR, "server-cert.pem"),
                        "-RSAPublicKey_in")
        self.assertNotEqual(r.returncode, 0)

    def test_fail_rsapublickey_in_privkey(self):
        r = run_wolfssl("rsa", "-in",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-RSAPublicKey_in")
        self.assertNotEqual(r.returncode, 0)

    def test_fail_pubin_cert(self):
        r = run_wolfssl("rsa", "-in",
                        os.path.join(CERTS_DIR, "server-cert.pem"),
                        "-pubin")
        self.assertNotEqual(r.returncode, 0)

    def test_fail_pubin_privkey(self):
        r = run_wolfssl("rsa", "-in",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-pubin")
        self.assertNotEqual(r.returncode, 0)

    def test_rsapublickey_in(self):
        r = run_wolfssl("rsa", "-in",
                        os.path.join(CERTS_DIR, "server-keyPub.pem"),
                        "-RSAPublicKey_in")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), RSA_PUBKEY_PEM)

    def test_pubin(self):
        r = run_wolfssl("rsa", "-in",
                        os.path.join(CERTS_DIR, "server-keyPub.pem"),
                        "-pubin")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), RSA_PUBKEY_PEM)

    @unittest.skipIf(_is_fips(), "skipped in FIPS builds")
    def test_encrypted_key(self):
        r = run_wolfssl("rsa", "-in",
                        os.path.join(CERTS_DIR, "server-keyEnc.pem"),
                        "-passin", "pass:yassl123")
        self.assertEqual(r.returncode, 0, r.stderr)

    @unittest.skipIf(_is_fips(), "skipped in FIPS builds")
    def test_fail_wrong_password(self):
        r = run_wolfssl("rsa", "-in",
                        os.path.join(CERTS_DIR, "server-keyEnc.pem"),
                        "-passin", "pass:yassl12")
        self.assertNotEqual(r.returncode, 0)

    @unittest.skipIf(_is_fips(), "skipped in FIPS builds")
    def test_modulus_noout(self):
        r = run_wolfssl("rsa", "-in",
                        os.path.join(CERTS_DIR, "server-keyEnc.pem"),
                        "-passin", "pass:yassl123", "-noout", "-modulus")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Modulus", r.stdout)
        self.assertNotIn("BEGIN", r.stdout)

    def test_invalid_outform_error_message(self):
        """Invalid -outform value must produce an outform-related error.

        When the output is redirected to a file/pipe the command may also
        emit the raw key bytes on stdout, so capture everything as bytes
        and search the combined output for a human-readable error mention.
        """
        r = subprocess.run(
            [WOLFSSL_BIN, "rsa", "-in",
             os.path.join(CERTS_DIR, "server-key.pem"),
             "-outform", "INVALID"],
            capture_output=True, stdin=subprocess.DEVNULL, timeout=60)
        combined = (r.stdout + r.stderr).lower()
        self.assertIn(b"outform", combined,
                      "Expected 'outform' in error output, got: {!r}".format(
                          combined[:200]))


if __name__ == "__main__":
    test_main()

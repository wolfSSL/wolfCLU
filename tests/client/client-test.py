#!/usr/bin/env python3
"""TLS client tests for wolfCLU."""

import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import WOLFSSL_BIN, CERTS_DIR, run_wolfssl, test_main


class ClientTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

        config_log = os.path.join(".", "config.log")
        if os.path.isfile(config_log):
            with open(config_log, "r") as f:
                if "disable-filesystem" in f.read():
                    raise unittest.SkipTest("filesystem support disabled")

    def test_s_client_x509(self):
        """Connect to a TLS server, extract cert, and verify PEM output."""
        tmp_crt = "tmp.crt"
        self.addCleanup(lambda: os.remove(tmp_crt)
                        if os.path.exists(tmp_crt) else None)

        # Run s_client with empty stdin so it connects then disconnects.
        # Verification may fail without a CA bundle, but the connection
        # still succeeds and the server certificate is printed to stdout.
        s_client = subprocess.run(
            [WOLFSSL_BIN, "s_client", "-connect", "www.google.com:443"],
            input=b"\n",
            capture_output=True,
            timeout=30,
        )

        self.assertIn(b"-----BEGIN CERTIFICATE-----", s_client.stdout,
                      f"s_client did not return a certificate: {s_client.stderr}")

        # Pipe s_client stdout into x509 to extract the cert as PEM
        x509_extract = subprocess.run(
            [WOLFSSL_BIN, "x509", "-outform", "pem", "-out", tmp_crt],
            input=s_client.stdout,
            capture_output=True,
            timeout=60,
        )
        self.assertEqual(x509_extract.returncode, 0,
                         f"x509 extraction failed: {x509_extract.stderr}")
        self.assertTrue(os.path.exists(tmp_crt),
                        f"x509 did not create output file: "
                        f"{x509_extract.stderr}")

        # Read back the cert
        result = run_wolfssl("x509", "-in", tmp_crt)
        self.assertIn("-----BEGIN CERTIFICATE-----", result.stdout,
                      "Expected x509 PEM output not found")

class ShellInjectionTest(unittest.TestCase):
    """Regression tests for shell command injection via hostname.

    Applies to the WOLFSSL_USE_POPEN_HOST path where peer is concatenated
    into a popen() shell command. On other builds, getaddrinfo /
    gethostbyname reject these hostnames before any shell is involved,
    so the tests pass either way -- the injected command must never run.
    """

    INJECTION_PROBE = "clu_injection_probe.txt"

    def setUp(self):
        if os.path.exists(self.INJECTION_PROBE):
            os.remove(self.INJECTION_PROBE)
        self.addCleanup(lambda: os.remove(self.INJECTION_PROBE)
                        if os.path.exists(self.INJECTION_PROBE) else None)

    def _assert_no_injection(self, peer, description):
        """Run s_client with the given -connect peer and verify that the
        injected `touch` command did not execute."""
        subprocess.run(
            [WOLFSSL_BIN, "s_client", "-connect", peer],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=30,
        )
        self.assertFalse(
            os.path.exists(self.INJECTION_PROBE),
            f"SECURITY FAILURE: command injection via hostname "
            f"({description})")

    def test_semicolon_injection(self):
        """evil.com;touch probe:443 must not execute the touch command."""
        self._assert_no_injection(
            f"evil.com;touch {self.INJECTION_PROBE}:443",
            "semicolon")

    def test_command_substitution_injection(self):
        """evil$(touch probe).com:443 must not execute the touch command."""
        self._assert_no_injection(
            f"evil$(touch {self.INJECTION_PROBE}).com:443",
            "command substitution")

    def test_pipe_injection(self):
        """evil.com|touch probe:443 must not execute the touch command."""
        self._assert_no_injection(
            f"evil.com|touch {self.INJECTION_PROBE}:443",
            "pipe")

if __name__ == "__main__":
    test_main()

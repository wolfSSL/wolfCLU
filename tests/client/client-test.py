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

        # Read back the cert
        result = run_wolfssl("x509", "-in", tmp_crt)
        self.assertIn("-----BEGIN CERTIFICATE-----", result.stdout,
                      "Expected x509 PEM output not found")


if __name__ == "__main__":
    test_main()

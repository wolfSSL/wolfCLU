#!/usr/bin/env python3
"""TLS client tests for wolfCLU."""

import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import (WOLFSSL_BIN, CERTS_DIR, run_wolfssl,
                          skip_if_no_filesystem, test_main)


class ClientTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

        skip_if_no_filesystem()

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

    def test_client_help(self):
        """ run help command for client """
        r = run_wolfssl("s_client", "-help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("s_client" , r.stderr, "help menu was not printed")

class PortArgTest(unittest.TestCase):
    """Regression tests for the port half of -connect <host>:<port>.

    -connect forwards the text after ':' to the client's -p handler, which
    used to be (word16)atoi(): "99999" silently truncated to 34463 and the
    client happily connected to the wrong port.  The port is now parsed with
    wolfCLU_parseDecimalBounded(), so anything outside 1-65535, and anything
    that is not a plain decimal number, is rejected before any connection is
    attempted.
    """

    PORT_ERROR = "port number must be between 1 and 65535"

    @classmethod
    def setUpClass(cls):
        # s_client is compiled out under --disable-filesystem, so it never
        # reaches the port parser and never prints PORT_ERROR.
        skip_if_no_filesystem()

    def _assert_rejected(self, port, description):
        """Run s_client against localhost:<port> and require that the port
        itself was rejected -- a non-zero exit alone is not enough, since a
        truncated port would also fail to connect."""
        r = run_wolfssl("s_client", "-connect", "localhost:" + port,
                        timeout=30)
        self.assertNotEqual(r.returncode, 0,
                            f"{description} port {port!r} was accepted")
        self.assertIn(self.PORT_ERROR, r.stdout + r.stderr,
                      f"{description} port {port!r} was not rejected as an "
                      f"out-of-range port: {r.stdout + r.stderr}")

    def test_port_zero(self):
        """0 must be rejected: it is not a port that can be connected to."""
        self._assert_rejected("0", "zero")

    def test_port_above_word16(self):
        """99999 must be rejected, not truncated to 34463."""
        self._assert_rejected("99999", "out-of-range")

    def test_port_just_above_word16(self):
        """65536 must be rejected, not truncated to 0."""
        self._assert_rejected("65536", "out-of-range")

    def test_port_negative(self):
        """A negative port must be rejected, not wrapped."""
        self._assert_rejected("-1", "negative")

    def test_port_non_numeric(self):
        """A non-numeric port must be rejected, not read as 0."""
        self._assert_rejected("abc", "non-numeric")

    def test_port_trailing_junk(self):
        """Trailing junk must be rejected, not silently ignored."""
        self._assert_rejected("443abc", "trailing junk")

    def test_port_empty(self):
        """An empty port must be rejected."""
        self._assert_rejected("", "empty")

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

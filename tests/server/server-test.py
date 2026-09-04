#!/usr/bin/env python3
"""TLS server/client communication test for wolfCLU."""

import os
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import WOLFSSL_BIN, CERTS_DIR, test_main, find_free_port


NAME_MISMATCH = b"peer subject name mismatch"
IP_MISMATCH = b"peer ip address mismatch"


class ServerClientTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

        config_log = os.path.join(".", "config.log")
        if os.path.isfile(config_log):
            with open(config_log, "r") as f:
                if "disable-filesystem" in f.read():
                    raise unittest.SkipTest("filesystem support disabled")

    def test_help(self):
        """s_server -help prints usage and exits cleanly."""
        for flag in ("-help", "-h"):
            r = subprocess.run(
                [WOLFSSL_BIN, "s_server", flag],
                capture_output=True, text=True, stdin=subprocess.DEVNULL,
                timeout=30,
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("s_server", r.stdout + r.stderr)

    def test_server_client(self):
        """Start s_server, connect with s_client, verify handshake.

        Exercises the -CAfile, -version, -naccept and -www argument-parsing
        branches in clu_server_setup.c in addition to the basic handshake.
        """
        readyfile = "readyfile"
        if os.path.exists(readyfile):
            os.remove(readyfile)

        port = find_free_port()

        # Start server in background
        server = subprocess.Popen(
            [WOLFSSL_BIN, "s_server", "-port", str(port),
             "-key", os.path.join(CERTS_DIR, "server-key.pem"),
             "-cert", os.path.join(CERTS_DIR, "server-cert.pem"),
             "-CAfile", os.path.join(CERTS_DIR, "ca-cert.pem"),
             "-version", "3", "-naccept", "1", "-www",
             "-noVerify", "-readyFile", readyfile],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )

        try:
            # Wait for server to be ready
            for _ in range(200):
                if os.path.exists(readyfile):
                    break
                time.sleep(0.01)
            else:
                self.fail("s_server did not become ready")

            if os.path.exists(readyfile):
                os.remove(readyfile)

            # Connect with client
            client = subprocess.run(
                [WOLFSSL_BIN, "s_client", "-connect",
                 "127.0.0.1:{}".format(port),
                 "-CAfile", os.path.join(CERTS_DIR, "ca-cert.pem"),
                 "-verify_return_error", "-disable_stdin_check"],
                capture_output=True, stdin=subprocess.DEVNULL, timeout=30,
            )
            self.assertEqual(client.returncode, 0,
                             f"s_client failed: {client.stderr}")
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()

    def _run_identity_check(self, extra_args):
        """Start s_server on 127.0.0.1 and connect with the given extra
        s_client arguments. Returns the s_client CompletedProcess."""
        readyfile = "readyfile_identity"
        if os.path.exists(readyfile):
            os.remove(readyfile)

        port = find_free_port()

        server = subprocess.Popen(
            [WOLFSSL_BIN, "s_server", "-port", str(port),
             "-key", os.path.join(CERTS_DIR, "server-key.pem"),
             "-cert", os.path.join(CERTS_DIR, "server-cert.pem"),
             "-CAfile", os.path.join(CERTS_DIR, "ca-cert.pem"),
             "-version", "3", "-naccept", "1", "-www",
             "-noVerify", "-readyFile", readyfile],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )

        try:
            for _ in range(200):
                if os.path.exists(readyfile):
                    break
                time.sleep(0.01)
            else:
                self.fail("s_server did not become ready")

            os.remove(readyfile)

            return subprocess.run(
                [WOLFSSL_BIN, "s_client", "-connect",
                 "127.0.0.1:{}".format(port),
                 "-CAfile", os.path.join(CERTS_DIR, "ca-cert.pem"),
                 "-disable_stdin_check"] + extra_args,
                capture_output=True, stdin=subprocess.DEVNULL, timeout=30,
            )
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()

    def _assert_rejected(self, r, reason, message):
        """Fail unless s_client rejected the peer for the stated reason.

        A non-zero exit alone can come from an unready server or a dropped
        connection, which would let a real regression pass.
        """
        self.assertNotEqual(r.returncode, 0, message)
        output = r.stdout + r.stderr
        self.assertIn(reason, output,
                      f"{message} -- rejected, but not for that reason: "
                      f"{output}")

    def test_verify_hostname_match(self):
        """-verify_hostname accepts a name the certificate carries.

        server-cert.pem has SAN DNS:example.com. Neither this nor the
        mismatch test passes -verify_return_error, so they also cover
        -verify_hostname enabling peer verification on its own.
        """
        r = self._run_identity_check(["-verify_hostname", "example.com"])
        self.assertEqual(r.returncode, 0,
                         f"s_client rejected a matching name: {r.stderr}")

    def test_verify_hostname_mismatch(self):
        """-verify_hostname rejects a CA-trusted cert issued for another name.

        server-cert.pem is signed by ca-cert.pem and so passes chain
        verification, but carries no name matching attacker.example.
        """
        r = self._run_identity_check(["-verify_hostname", "attacker.example"])
        self._assert_rejected(r, NAME_MISMATCH,
                              "SECURITY FAILURE: s_client accepted a "
                              "certificate issued for a different host")

    def test_verify_ip_match(self):
        """-verify_ip accepts an address the certificate carries.

        server-cert.pem has SAN IP:127.0.0.1.
        """
        r = self._run_identity_check(["-verify_ip", "127.0.0.1"])
        self.assertEqual(r.returncode, 0,
                         f"s_client rejected a matching IP: {r.stderr}")

    def test_verify_ip_mismatch(self):
        """-verify_ip rejects a certificate without that IP SAN."""
        r = self._run_identity_check(["-verify_ip", "10.0.0.1"])
        self._assert_rejected(r, IP_MISMATCH,
                              "SECURITY FAILURE: s_client accepted a "
                              "certificate issued for a different address")

    def test_verify_ip_unmatched_values(self):
        """-verify_ip fails closed on an IPv6 address the cert lacks and on
        a value that is not an address at all."""
        for value in ("::1", "not-an-ip"):
            with self.subTest(value=value):
                r = self._run_identity_check(["-verify_ip", value])
                self._assert_rejected(r, IP_MISMATCH,
                                      "SECURITY FAILURE: s_client accepted a "
                                      f"certificate for -verify_ip {value}")

    def test_verify_hostname_and_ip_together(self):
        """Both options at once: each is checked, either one can reject."""
        r = self._run_identity_check(["-verify_hostname", "example.com",
                                      "-verify_ip", "127.0.0.1"])
        self.assertEqual(r.returncode, 0,
                         f"s_client rejected a matching name and IP: {r.stderr}")

        r = self._run_identity_check(["-verify_hostname", "attacker.example",
                                      "-verify_ip", "127.0.0.1"])
        self._assert_rejected(r, NAME_MISMATCH,
                              "SECURITY FAILURE: a matching -verify_ip masked "
                              "a mismatched -verify_hostname")

        r = self._run_identity_check(["-verify_hostname", "example.com",
                                      "-verify_ip", "10.0.0.1"])
        self._assert_rejected(r, IP_MISMATCH,
                              "SECURITY FAILURE: a matching -verify_hostname "
                              "masked a mismatched -verify_ip")


if __name__ == "__main__":
    test_main()

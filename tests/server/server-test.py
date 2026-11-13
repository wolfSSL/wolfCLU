#!/usr/bin/env python3
"""TLS server/client communication test for wolfCLU."""

import os
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import WOLFSSL_BIN, CERTS_DIR, test_main, find_free_port


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

    def _run_server_version(self, version):
        """Start s_server with -version and wait for it to exit or listen.

        Returns (returncode, stderr). A server that starts listening is
        killed and returncode is None.
        """
        readyfile = "readyfile-version-" + version
        if os.path.exists(readyfile):
            os.remove(readyfile)
        self.addCleanup(
            lambda: os.path.exists(readyfile) and os.remove(readyfile))

        server = subprocess.Popen(
            [WOLFSSL_BIN, "s_server", "-port", str(find_free_port()),
             "-key", os.path.join(CERTS_DIR, "server-key.pem"),
             "-cert", os.path.join(CERTS_DIR, "server-cert.pem"),
             "-version", version, "-noVerify", "-readyFile", readyfile],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL, text=True,
        )
        try:
            deadline = time.time() + 30
            while True:
                try:
                    _, err = server.communicate(timeout=0.1)
                    return server.returncode, err
                except subprocess.TimeoutExpired:
                    if os.path.exists(readyfile):
                        server.kill()
                        _, err = server.communicate()
                        return None, err
                    if time.time() > deadline:
                        self.fail("s_server neither exited nor listened")
        finally:
            if server.poll() is None:
                server.kill()
                server.communicate()

    def test_unsupported_version(self):
        """s_server fails when the protocol version is not compiled in."""
        # 0: SSLv3, 1: TLS 1.0, 2: TLS 1.1
        for version in ("0", "1", "2"):
            with self.subTest(version=version):
                rc, err = self._run_server_version(version)
                if rc is None:
                    self.assertNotIn("unable to get method", err,
                                     "s_server kept running without a "
                                     "method: " + err)
                    self.skipTest("version {} compiled in".format(version))
                self.assertNotEqual(rc, 0, err)
                self.assertIn("unable to get method", err)
                self.assertNotIn("listening on port", err)


if __name__ == "__main__":
    test_main()

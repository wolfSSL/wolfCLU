#!/usr/bin/env python3
"""TLS server/client communication test for wolfCLU."""

import os
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import WOLFSSL_BIN, CERTS_DIR


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

    def test_server_client(self):
        """Start s_server, connect with s_client, verify handshake."""
        readyfile = "readyfile"
        if os.path.exists(readyfile):
            os.remove(readyfile)

        # Start server in background
        server = subprocess.Popen(
            [WOLFSSL_BIN, "s_server", "-port", "11111",
             "-key", os.path.join(CERTS_DIR, "server-key.pem"),
             "-cert", os.path.join(CERTS_DIR, "server-cert.pem"),
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
                [WOLFSSL_BIN, "s_client", "-connect", "127.0.0.1:11111",
                 "-CAfile", os.path.join(CERTS_DIR, "ca-cert.pem"),
                 "-verify_return_error", "-disable_stdin_check"],
                capture_output=True, stdin=subprocess.DEVNULL, timeout=30,
            )
            self.assertEqual(client.returncode, 0,
                             f"s_client failed: {client.stderr}")
        finally:
            server.terminate()
            server.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()

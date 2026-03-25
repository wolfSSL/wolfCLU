#!/usr/bin/env python3
"""Base64 encode/decode tests for wolfCLU."""

import filecmp
import os
import subprocess
import sys
import unittest

# Allow importing the shared helper when run standalone or via the test runner
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import WOLFSSL_BIN, CERTS_DIR, run_wolfssl


class Base64Test(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

        # Skip if filesystem support is disabled (Linux autotools build)
        config_log = os.path.join(".", "config.log")
        if os.path.isfile(config_log):
            with open(config_log, "r") as f:
                if "disable-filesystem" in f.read():
                    raise unittest.SkipTest("filesystem support disabled")

        # Skip if base64 coding support is not compiled in
        result = run_wolfssl("base64", "-in",
                             os.path.join(CERTS_DIR, "server-key.der"))
        combined = result.stdout + result.stderr
        if "No coding support" in combined:
            raise unittest.SkipTest("no base64 coding support")

    def test_encode(self):
        """Encode server-key.der and verify output appears in server-key.pem."""
        result = run_wolfssl("base64", "-in",
                             os.path.join(CERTS_DIR, "server-key.der"))
        self.assertEqual(result.returncode, 0, result.stderr)

        pem_path = os.path.join(CERTS_DIR, "server-key.pem")
        with open(pem_path, "r") as f:
            pem_contents = f.read()

        self.assertIn(result.stdout.strip(), pem_contents,
                      "server-key.der base64 conversion failed")

    def test_decode_and_reencode(self):
        """Decode signed.p7s to DER, re-encode, and verify against original."""
        tmp_der = "testp7.der"
        self.addCleanup(lambda: os.remove(tmp_der)
                        if os.path.exists(tmp_der) else None)

        result = run_wolfssl("base64", "-d", "-in",
                             os.path.join(CERTS_DIR, "signed.p7s"),
                             "-out", tmp_der)
        self.assertEqual(result.returncode, 0, result.stderr)

        result = run_wolfssl("base64", "-in", tmp_der)
        self.assertEqual(result.returncode, 0, result.stderr)

        p7s_path = os.path.join(CERTS_DIR, "signed.p7s")
        with open(p7s_path, "r") as f:
            p7s_contents = f.read()

        self.assertIn(result.stdout.strip(), p7s_contents,
                      "signed.p7s der base64 conversion failed")

    def test_roundtrip(self):
        """Encode then decode server-key.der and verify files match."""
        encoded_file = "test-b64-encoded.b64"
        decoded_file = "test-b64-decoded.der"
        self.addCleanup(lambda: os.remove(encoded_file)
                        if os.path.exists(encoded_file) else None)
        self.addCleanup(lambda: os.remove(decoded_file)
                        if os.path.exists(decoded_file) else None)

        original = os.path.join(CERTS_DIR, "server-key.der")

        result = run_wolfssl("base64", "-in", original, "-out", encoded_file)
        self.assertEqual(result.returncode, 0, result.stderr)

        result = run_wolfssl("base64", "-d", "-in", encoded_file,
                             "-out", decoded_file)
        self.assertEqual(result.returncode, 0, result.stderr)

        self.assertTrue(filecmp.cmp(original, decoded_file, shallow=False),
                        "base64 encode/decode round-trip failed")

    def test_stdin_input(self):
        """Feed data via stdin and verify wolfssl processes it."""
        p7b_path = os.path.join(CERTS_DIR, "signed.p7b")
        with open(p7b_path, "rb") as f:
            stdin_data = f.read()

        result = subprocess.run(
            [WOLFSSL_BIN, "base64"],
            input=stdin_data,
            capture_output=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0,
                         "Couldn't parse input from stdin")


if __name__ == "__main__":
    unittest.main()

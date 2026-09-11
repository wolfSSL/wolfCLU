#!/usr/bin/env python3
"""Base64 encode/decode tests for wolfCLU."""

import base64
import filecmp
import os
import random
import subprocess
import sys
import unittest

# Allow importing the shared helper when run standalone or via the test runner
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import WOLFSSL_BIN, CERTS_DIR, run_wolfssl, test_main


def pem_lines(data):
    """Base64 encode data as 64 character lines, the way wolfssl writes it."""
    encoded = base64.b64encode(data)
    return b"".join(encoded[i:i + 64] + b"\n"
                    for i in range(0, len(encoded), 64))


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

    def test_stdin_input_long(self):
        """Encode 100,000 bytes from stdin, spanning several buffer grows."""
        data = random.Random(0).randbytes(100000)

        result = subprocess.run(
            [WOLFSSL_BIN, "base64"],
            input=data,
            capture_output=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.replace(b"\n", b""),
                         base64.b64encode(data),
                         "stdin encode does not match python base64")

    def test_stdin_decode_long(self):
        """Decode more than the old 8000 byte stdin limit."""
        data = random.Random(1).randbytes(100000)

        result = subprocess.run(
            [WOLFSSL_BIN, "base64", "-d"],
            input=pem_lines(data),
            capture_output=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, data,
                         "stdin decode does not match the original data")

    @unittest.skipUnless(os.path.exists("/dev/stdin"), "needs /dev/stdin")
    def test_pipe_input_file(self):
        """-in on a pipe, which can't be sized with seek, reads like stdin."""
        data = random.Random(2).randbytes(5000)

        result = subprocess.run(
            [WOLFSSL_BIN, "base64", "-in", "/dev/stdin"],
            input=data,
            capture_output=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.replace(b"\n", b""),
                         base64.b64encode(data),
                         "pipe input encode does not match python base64")

    def test_empty_stdin(self):
        """Empty stdin produces empty output, matching 'openssl base64'."""
        result = subprocess.run(
            [WOLFSSL_BIN, "base64"],
            input=b"",
            capture_output=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"", "empty input should give no output")

    def test_empty_stdin_decode(self):
        """Empty stdin with -d produces empty output, like 'openssl base64'."""
        result = subprocess.run(
            [WOLFSSL_BIN, "base64", "-d"],
            input=b"",
            capture_output=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"", "empty input should give no output")

    def test_empty_file(self):
        """An empty input file produces an empty output file."""
        empty_file = "test-b64-empty.txt"
        out_file = "test-b64-empty.b64"
        self.addCleanup(lambda: os.remove(empty_file)
                        if os.path.exists(empty_file) else None)
        self.addCleanup(lambda: os.remove(out_file)
                        if os.path.exists(out_file) else None)

        with open(empty_file, "wb"):
            pass

        result = run_wolfssl("base64", "-in", empty_file, "-out", out_file)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(os.path.getsize(out_file), 0,
                         "empty input should give an empty output file")

    def test_missing_input_file(self):
        """A missing -in file gives a non-zero exit."""
        result = run_wolfssl("base64", "-in", "test-b64-does-not-exist.bin")
        self.assertNotEqual(result.returncode, 0,
                            "missing input file should fail")

    def test_output_dir_missing(self):
        """An -out path in a missing directory gives a non-zero exit."""
        result = run_wolfssl("base64", "-in",
                             os.path.join(CERTS_DIR, "server-key.der"),
                             "-out", os.path.join("test-b64-no-such-dir",
                                                  "out.b64"))
        self.assertNotEqual(result.returncode, 0,
                            "output in a missing directory should fail")

    def test_failed_decode_keeps_output(self):
        """A failed -d does not create or truncate the -out file."""
        out_file = "test-b64-keep.txt"
        self.addCleanup(lambda: os.remove(out_file)
                        if os.path.exists(out_file) else None)

        with open(out_file, "wb") as f:
            f.write(b"keep")

        result = run_wolfssl("base64", "-d", "-out", out_file,
                             stdin_data="@@@@")
        self.assertNotEqual(result.returncode, 0, "bad base64 should fail")
        with open(out_file, "rb") as f:
            self.assertEqual(f.read(), b"keep",
                             "failed decode should leave -out unchanged")

    def test_in_place(self):
        """-in and -out naming the same file encodes it in place."""
        work_file = "test-b64-inplace.bin"
        self.addCleanup(lambda: os.remove(work_file)
                        if os.path.exists(work_file) else None)

        with open(os.path.join(CERTS_DIR, "server-key.der"), "rb") as f:
            original = f.read()
        with open(work_file, "wb") as f:
            f.write(original)

        result = run_wolfssl("base64", "-in", work_file, "-out", work_file)
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(work_file, "rb") as f:
            self.assertEqual(f.read().replace(b"\n", b""),
                             base64.b64encode(original),
                             "in place encode does not match python base64")

    @unittest.skipUnless(os.path.exists("/dev/full"), "needs /dev/full")
    def test_stdout_write_error(self):
        """A failed write to stdout gives a non-zero exit."""
        with open("/dev/full", "wb") as full:
            result = subprocess.run(
                [WOLFSSL_BIN, "base64", "-in",
                 os.path.join(CERTS_DIR, "server-key.der")],
                stdout=full,
                stderr=subprocess.PIPE,
                timeout=60,
            )
        self.assertNotEqual(result.returncode, 0,
                            "write to a full device should fail")

    @unittest.skipUnless(os.path.exists("/dev/full"), "needs /dev/full")
    def test_output_file_write_error(self):
        """A failed write to the -out file gives a non-zero exit."""
        result = run_wolfssl("base64", "-in",
                             os.path.join(CERTS_DIR, "server-key.der"),
                             "-out", "/dev/full")
        self.assertNotEqual(result.returncode, 0,
                            "write to a full device should fail")

    def test_help(self):
        """ Test help flag """
        result = subprocess.run(
            [WOLFSSL_BIN, "base64", "-h"],
            capture_output=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertGreater(len(result.stderr), 0, "output was not completed")



if __name__ == "__main__":
    test_main()

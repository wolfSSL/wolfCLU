#!/usr/bin/env python3
"""Hash tests for wolfCLU."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import CERTS_DIR, run_wolfssl, test_main

HASH_DIR = os.path.join(".", "tests", "hash")
CERT_FILE = os.path.join(CERTS_DIR, "ca-cert.pem")


def _read_expected(name):
    path = os.path.join(HASH_DIR, name)
    with open(path, "r") as f:
        return f.read().strip()


class HashCommandTest(unittest.TestCase):
    """Tests using the -hash subcommand."""

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

        config_log = os.path.join(".", "config.log")
        if os.path.isfile(config_log):
            with open(config_log, "r") as f:
                if "disable-filesystem" in f.read():
                    raise unittest.SkipTest("filesystem support disabled")

    def test_sha_base64enc(self):
        r = run_wolfssl("-hash", "sha", "-in", CERT_FILE, "-base64enc")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), _read_expected("sha-expect.hex"))

    def test_sha256(self):
        r = run_wolfssl("-hash", "sha256", "-in", CERT_FILE)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), _read_expected("sha256-expect.hex"))

    def test_sha384(self):
        r = run_wolfssl("-hash", "sha384", "-in", CERT_FILE)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), _read_expected("sha384-expect.hex"))

    def test_sha512(self):
        r = run_wolfssl("-hash", "sha512", "-in", CERT_FILE)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), _read_expected("sha512-expect.hex"))


class HashShortcutTest(unittest.TestCase):
    """Tests using the shortcut subcommands (md5, sha256, etc.)."""

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

        config_log = os.path.join(".", "config.log")
        if os.path.isfile(config_log):
            with open(config_log, "r") as f:
                if "disable-filesystem" in f.read():
                    raise unittest.SkipTest("filesystem support disabled")

    def test_md5(self):
        r = run_wolfssl("md5", CERT_FILE)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), _read_expected("md5-expect.hex"))

    def test_sha256(self):
        r = run_wolfssl("sha256", CERT_FILE)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), _read_expected("sha256-expect.hex"))

    def test_sha384(self):
        r = run_wolfssl("sha384", CERT_FILE)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), _read_expected("sha384-expect.hex"))

    def test_sha512(self):
        r = run_wolfssl("sha512", CERT_FILE)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), _read_expected("sha512-expect.hex"))


if __name__ == "__main__":
    test_main()

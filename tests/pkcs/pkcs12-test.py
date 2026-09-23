#!/usr/bin/env python3
"""PKCS12 tests for wolfCLU."""

import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import WOLFSSL_BIN, CERTS_DIR, is_fips, run_wolfssl, test_main

P12_FILE = os.path.join(CERTS_DIR, "test-servercert.p12")


class Pkcs12Test(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

        config_log = os.path.join(".", "config.log")
        if os.path.isfile(config_log):
            with open(config_log, "r") as f:
                if "disable-filesystem" in f.read():
                    raise unittest.SkipTest("filesystem support disabled")

        if is_fips():
            raise unittest.SkipTest("FIPS build")

        r = run_wolfssl("pkcs12", "-nodes", "-passin", 'pass:wolfSSL test',
                        "-passout", "pass:", "-in", P12_FILE)
        combined = r.stdout + r.stderr
        if "Recompile wolfSSL with PKCS12 support" in combined:
            raise unittest.SkipTest("PKCS12 support not compiled in")

    def test_nocerts(self):
        r = subprocess.run(
            [WOLFSSL_BIN, "pkcs12", "-nodes", "-nocerts",
             "-passin", "stdin", "-passout", "pass:", "-in", P12_FILE],
            input=b"wolfSSL test\n", capture_output=True, text=False,
            timeout=60,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn(b"CERTIFICATE", r.stdout)

    def test_nokeys(self):
        r = subprocess.run(
            [WOLFSSL_BIN, "pkcs12", "-nokeys",
             "-passin", "stdin", "-passout", "pass:", "-in", P12_FILE],
            input=b"wolfSSL test\n", capture_output=True, text=False,
            timeout=60,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn(b"KEY", r.stdout)

    def test_pass_on_cmdline(self):
        r = run_wolfssl("pkcs12", "-nodes", "-passin", 'pass:wolfSSL test',
                        "-passout", "pass:", "-in", P12_FILE)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_help(self):
        for flag in ("-help", "-h"):
            r = run_wolfssl("pkcs12", flag)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("wolfssl pkcs12", r.stdout + r.stderr)

    def test_bad_argument_fails(self):
        r = run_wolfssl("pkcs12", "-not-a-real-option", "-in", P12_FILE)
        self.assertNotEqual(r.returncode, 0)

    def test_out_to_file(self):
        out = "pkcs12-out.pem"
        self.addCleanup(lambda: os.remove(out) if os.path.exists(out) else None)
        r = run_wolfssl("pkcs12", "-nodes", "-passin", 'pass:wolfSSL test',
                        "-passout", "pass:", "-in", P12_FILE, "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(out), "pkcs12 -out did not create file")
        with open(out, "r") as f:
            self.assertIn("BEGIN ", f.read())

    def test_out_bad_path_fails(self):
        r = run_wolfssl("pkcs12", "-nodes", "-passin", 'pass:wolfSSL test',
                        "-passout", "pass:", "-in", P12_FILE,
                        "-out", os.path.join("no-such-dir", "out.pem"))
        self.assertNotEqual(r.returncode, 0)

    def test_out_missing_file_name(self):
        """A trailing -out must fail, not print the key to stdout."""
        r = run_wolfssl("pkcs12", "-nodes", "-passin", 'pass:wolfSSL test',
                        "-passout", "pass:", "-in", P12_FILE, "-out")
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("PRIVATE KEY", r.stdout)

    def _out_mode(self, out, *args, stdin_data=None):
        """Run pkcs12 -out under umask 022. Return the new file's mode and
        contents."""
        old_umask = os.umask(0o022)
        self.addCleanup(os.umask, old_umask)
        self.addCleanup(lambda: os.remove(out) if os.path.exists(out) else None)
        # Start from a new file so the create mode applies.
        if os.path.exists(out):
            os.remove(out)
        r = run_wolfssl("pkcs12", "-passin", 'pass:wolfSSL test',
                        "-passout", "pass:", "-in", P12_FILE, "-out", out,
                        *args, stdin_data=stdin_data)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(out, "r") as f:
            content = f.read()
        return os.stat(out).st_mode & 0o777, content

    @unittest.skipIf(os.name == "nt", "POSIX file permissions only")
    def test_out_nodes_owner_only(self):
        mode, content = self._out_mode("pkcs12-perm-nodes.pem", "-nodes")
        self.assertIn("PRIVATE KEY", content)
        self.assertEqual(mode, 0o600,
                         "-nodes output mode is {:o}, expected 600".format(
                             mode))

    @unittest.skipIf(os.name == "nt", "POSIX file permissions only")
    def test_out_encrypted_key_owner_only(self):
        mode, content = self._out_mode("pkcs12-perm-enc.pem",
                                       stdin_data="wolfSSL test\n")
        self.assertIn("ENCRYPTED PRIVATE KEY", content)
        self.assertEqual(mode, 0o600,
                         "encrypted key output mode is {:o}, "
                         "expected 600".format(mode))

    @unittest.skipIf(os.name == "nt", "POSIX file permissions only")
    def test_out_nokeys_default_mode(self):
        mode, content = self._out_mode("pkcs12-perm-nokeys.pem", "-nokeys")
        self.assertNotIn("KEY", content)
        self.assertIn("CERTIFICATE", content)
        self.assertEqual(mode, 0o644,
                         "-nokeys output mode is {:o}, expected 644".format(
                             mode))

    def test_nocerts_with_passout(self):
        r = subprocess.run(
            [WOLFSSL_BIN, "pkcs12", "-passin", "stdin", "-passout", "pass:",
             "-in", P12_FILE, "-nocerts"],
            input=b"wolfSSL test\n", capture_output=True, text=False,
            timeout=60,
        )
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    test_main()

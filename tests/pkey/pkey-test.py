#!/usr/bin/env python3
"""pkey tests for wolfCLU."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import CERTS_DIR, run_wolfssl, test_main

ECC_PUBKEY_PEM = """\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuzOsTCdQSsZKpQTDPN6fNttyLc6U
6iv6yyAJOSwW6GEC6a9N0wKTmjFbl5Ihf/DPGNqREQI0huggWDMLgDSJ2A==
-----END PUBLIC KEY-----"""

ECC_PRIVKEY_PEM = """\
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEW2aQJznGyFoThbcujox6zEA41TNQT6bCjcNI3hqAmMoAoGCCqGSM49
AwEHoUQDQgAEuzOsTCdQSsZKpQTDPN6fNttyLc6U6iv6yyAJOSwW6GEC6a9N0wKT
mjFbl5Ihf/DPGNqREQI0huggWDMLgDSJ2A==
-----END EC PRIVATE KEY-----"""


class PkeyTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

        config_log = os.path.join(".", "config.log")
        if os.path.isfile(config_log):
            with open(config_log, "r") as f:
                if "disable-filesystem" in f.read():
                    raise unittest.SkipTest("filesystem support disabled")

    def _cleanup(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: os.remove(p)
                            if os.path.exists(p) else None)

    def test_pubin_ecc(self):
        r = run_wolfssl("pkey", "-pubin", "-in",
                        os.path.join(CERTS_DIR, "ecc-keyPub.pem"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), ECC_PUBKEY_PEM)

    def test_fail_pubin_private_key(self):
        r = run_wolfssl("pkey", "-pubin", "-in",
                        os.path.join(CERTS_DIR, "ecc-key.pem"))
        self.assertNotEqual(r.returncode, 0)

    def test_pem_der_pem_private(self):
        self._cleanup("ecc.der", "ecc.pem")

        r = run_wolfssl("pkey", "-in",
                        os.path.join(CERTS_DIR, "ecc-key.pem"),
                        "-outform", "der", "-out", "ecc.der")
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("pkey", "-in", "ecc.der", "-inform", "der",
                        "-outform", "pem", "-out", "ecc.pem")
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("pkey", "-in", "ecc.pem")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), ECC_PRIVKEY_PEM)

    def test_pem_der_pem_public(self):
        self._cleanup("ecc.der", "ecc.pem")

        r = run_wolfssl("pkey", "-pubin", "-in",
                        os.path.join(CERTS_DIR, "ecc-keyPub.pem"),
                        "-outform", "der", "-out", "ecc.der")
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("pkey", "-pubin", "-in", "ecc.der", "-inform", "der",
                        "-outform", "pem", "-out", "ecc.pem")
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("pkey", "-pubin", "-in", "ecc.pem")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), ECC_PUBKEY_PEM)


    def test_help(self):
        for flag in ("-help", "-h"):
            r = run_wolfssl("pkey", flag)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("wolfssl pkey", r.stdout + r.stderr)

    def test_pubout_from_private(self):
        r = run_wolfssl("pkey", "-in",
                        os.path.join(CERTS_DIR, "ecc-key.pem"), "-pubout")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), ECC_PUBKEY_PEM)

    def test_out_to_file(self):
        out = "pkey-out.pem"
        self._cleanup(out)
        r = run_wolfssl("pkey", "-in",
                        os.path.join(CERTS_DIR, "ecc-key.pem"),
                        "-pubout", "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(out), "pkey -out did not create file")
        with open(out, "r") as f:
            self.assertIn("BEGIN PUBLIC KEY", f.read())

    def _out_mode(self, out, key, *args):
        """Write a new -out file under umask 022 and return its mode."""
        self._cleanup(out)
        if os.path.exists(out):
            os.remove(out)
        old_umask = os.umask(0o022)
        try:
            r = run_wolfssl("pkey", "-in", os.path.join(CERTS_DIR, key),
                            "-out", out, *args)
        finally:
            os.umask(old_umask)
        self.assertEqual(r.returncode, 0, r.stderr)
        return os.stat(out).st_mode & 0o777

    @unittest.skipIf(os.name == "nt", "POSIX file permissions only")
    def test_private_out_mode(self):
        """Private key output must be owner-only (F-9859)."""
        for fmt in ("PEM", "DER"):
            with self.subTest(outform=fmt):
                mode = self._out_mode("test-pkey-perm-priv." + fmt.lower(),
                                      "ecc-key.pem", "-outform", fmt)
                self.assertEqual(mode, 0o600,
                                 "private key mode is {:o}, expected 600"
                                 .format(mode))

    @unittest.skipIf(os.name == "nt", "POSIX file permissions only")
    def test_public_out_mode(self):
        """Public only output keeps the umask default mode."""
        cases = [
            ("test-pkey-perm-pubout.pem", "ecc-key.pem", "-pubout"),
            ("test-pkey-perm-pubin.pem", "ecc-keyPub.pem", "-pubin"),
        ]
        for out, key, *args in cases:
            with self.subTest(args=args):
                mode = self._out_mode(out, key, *args)
                self.assertEqual(mode, 0o644,
                                 "public output mode is {:o}, expected 644"
                                 .format(mode))


    def test_out_missing_file_name(self):
        """A trailing -out must fail, not print the key to stdout."""
        r = run_wolfssl("pkey", "-in",
                        os.path.join(CERTS_DIR, "ecc-key.pem"), "-out")
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("PRIVATE KEY", r.stdout)


if __name__ == "__main__":
    test_main()

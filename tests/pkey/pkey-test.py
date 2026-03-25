#!/usr/bin/env python3
"""pkey tests for wolfCLU."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import CERTS_DIR, run_wolfssl

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


if __name__ == "__main__":
    unittest.main()

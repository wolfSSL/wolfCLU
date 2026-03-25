#!/usr/bin/env python3
"""Tests for wolfssl verify (converted from x509-verify-test.sh)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import CERTS_DIR, run_wolfssl


def _has_crl():
    """Check whether CRL support is compiled in."""
    r = run_wolfssl("verify", "-CAfile",
                    os.path.join(CERTS_DIR, "ca-cert.pem"),
                    "-crl_check",
                    os.path.join(CERTS_DIR, "server-cert.pem"))
    combined = r.stdout + r.stderr
    return "recompile wolfSSL with CRL" not in combined


class TestX509Verify(unittest.TestCase):
    """Certificate verification tests."""

    def test_verify_without_ca_fails(self):
        """verify server-cert.pem without CA should fail with issuer error."""
        r = run_wolfssl("verify",
                        os.path.join(CERTS_DIR, "server-cert.pem"))
        self.assertNotEqual(r.returncode, 0)
        combined = r.stdout + r.stderr
        self.assertIn("unable to get local issuer certificate", combined)

    def test_verify_ca_cert_self_signed_error(self):
        """verify ca-cert.pem alone should fail with self-signed error."""
        r = run_wolfssl("verify",
                        os.path.join(CERTS_DIR, "ca-cert.pem"))
        self.assertNotEqual(r.returncode, 0)
        combined = r.stdout + r.stderr
        self.assertIn("self-signed certificate in certificate chain", combined)

    def test_verify_with_correct_cafile(self):
        """verify with correct CAfile succeeds."""
        r = run_wolfssl("verify", "-CAfile",
                        os.path.join(CERTS_DIR, "ca-cert.pem"),
                        os.path.join(CERTS_DIR, "server-cert.pem"))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_verify_with_wrong_cafile_ecc(self):
        """verify ECC cert with RSA CA should fail."""
        r = run_wolfssl("verify", "-CAfile",
                        os.path.join(CERTS_DIR, "ca-cert.pem"),
                        os.path.join(CERTS_DIR, "server-ecc.pem"))
        self.assertNotEqual(r.returncode, 0)

    def test_verify_ecc_cert(self):
        """verify ECC cert with correct ECC CA succeeds."""
        r = run_wolfssl("verify", "-CAfile",
                        os.path.join(CERTS_DIR, "ca-ecc-cert.pem"),
                        os.path.join(CERTS_DIR, "server-ecc.pem"))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_verify_rsa_again(self):
        """verify RSA cert with RSA CA succeeds (repeat)."""
        r = run_wolfssl("verify", "-CAfile",
                        os.path.join(CERTS_DIR, "ca-cert.pem"),
                        os.path.join(CERTS_DIR, "server-cert.pem"))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_verify_self_as_ca_fails(self):
        """verify server-cert.pem as its own CA should fail."""
        r = run_wolfssl("verify", "-CAfile",
                        os.path.join(CERTS_DIR, "server-cert.pem"),
                        os.path.join(CERTS_DIR, "server-cert.pem"))
        self.assertNotEqual(r.returncode, 0)

    def test_verify_partial_chain(self):
        """verify with -partial_chain allows self as CA."""
        r = run_wolfssl("verify", "-partial_chain", "-CAfile",
                        os.path.join(CERTS_DIR, "server-cert.pem"),
                        os.path.join(CERTS_DIR, "server-cert.pem"))
        self.assertEqual(r.returncode, 0, r.stderr)


class TestX509VerifyCRL(unittest.TestCase):
    """CRL-related verification tests."""

    @classmethod
    def setUpClass(cls):
        cls.have_crl = _has_crl()

    def setUp(self):
        if not self.have_crl:
            self.skipTest("CRL not compiled in")

    def test_crl_check_no_crl_loaded_fails(self):
        """crl_check with no CRL loaded should fail."""
        r = run_wolfssl("verify", "-CAfile",
                        os.path.join(CERTS_DIR, "ca-cert.pem"),
                        "-crl_check",
                        os.path.join(CERTS_DIR, "server-cert.pem"))
        self.assertNotEqual(r.returncode, 0)

    def test_crl_check_with_chain(self):
        """crl_check with CRL chain succeeds."""
        r = run_wolfssl("verify", "-CAfile",
                        os.path.join(CERTS_DIR, "crl-chain.pem"),
                        "-crl_check",
                        os.path.join(CERTS_DIR, "server-cert.pem"))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_crl_check_revoked_fails(self):
        """crl_check on revoked cert should fail."""
        r = run_wolfssl("verify", "-CAfile",
                        os.path.join(CERTS_DIR, "crl-chain.pem"),
                        "-crl_check",
                        os.path.join(CERTS_DIR, "server-revoked-cert.pem"))
        self.assertNotEqual(r.returncode, 0)


class TestX509VerifyChain(unittest.TestCase):
    """Certificate chain verification tests."""

    def test_intermediate_without_root_fails(self):
        """Verifying int2 with int1 as CA (no root) should fail."""
        r = run_wolfssl("verify", "-CAfile",
                        os.path.join(CERTS_DIR, "ca-int-cert.pem"),
                        os.path.join(CERTS_DIR, "ca-int2-cert.pem"))
        self.assertNotEqual(r.returncode, 0)

    def test_intermediate_partial_chain(self):
        """Verifying int2 with int1 as CA and -partial_chain succeeds."""
        r = run_wolfssl("verify", "-partial_chain", "-CAfile",
                        os.path.join(CERTS_DIR, "ca-int-cert.pem"),
                        os.path.join(CERTS_DIR, "ca-int2-cert.pem"))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_client_int_partial_chain(self):
        """Verifying client-int-cert with int2 as CA and -partial_chain."""
        r = run_wolfssl("verify", "-partial_chain", "-CAfile",
                        os.path.join(CERTS_DIR, "ca-int2-cert.pem"),
                        os.path.join(CERTS_DIR, "client-int-cert.pem"))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_untrusted_chain(self):
        """Verifying with -untrusted intermediate succeeds."""
        r = run_wolfssl("verify", "-CAfile",
                        os.path.join(CERTS_DIR, "ca-cert.pem"),
                        "-untrusted",
                        os.path.join(CERTS_DIR, "ca-int-cert.pem"),
                        os.path.join(CERTS_DIR, "ca-int2-cert.pem"))
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()

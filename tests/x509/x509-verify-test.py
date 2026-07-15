#!/usr/bin/env python3
"""Tests for wolfssl verify (converted from x509-verify-test.sh)."""

import functools
import os
import sys
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import CERTS_DIR, run_wolfssl, test_main


@functools.lru_cache(maxsize=None)
def _has_crl():
    """Check whether CRL support is compiled in."""
    r = run_wolfssl("verify", "-CAfile",
                    os.path.join(CERTS_DIR, "ca-cert.pem"),
                    "-crl_check",
                    os.path.join(CERTS_DIR, "server-cert.pem"))
    combined = r.stdout + r.stderr
    return "recompile wolfSSL with CRL" not in combined


@functools.lru_cache(maxsize=None)
def _can_print_mldsa_cert():
    """True if `x509 -text` can render an ML-DSA certificate."""
    if not _has_dilithium():
        return False
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        key = os.path.join(d, "probe")
        cert = os.path.join(d, "probe.pem")
        r = run_wolfssl("-genkey", "ml-dsa", "-level", "2", "-out", key,
                        "-output", "keypair", "-outform", "PEM")
        if r.returncode != 0:
            return False
        r = run_wolfssl("req", "-x509", "-key", key + ".priv",
                        "-subj", "/CN=probe", "-days", "1", "-out", cert)
        if r.returncode != 0:
            return False
        r = run_wolfssl("x509", "-in", cert, "-text", "-noout")
        return r.returncode == 0


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
        """A non-root leaf used as its own -CAfile should fail."""
        with open(os.path.join(CERTS_DIR, "server-cert.pem"),
                  encoding="utf-8") as f:
            pem = f.read()
        leaf_end = pem.index("-----END CERTIFICATE-----") + \
            len("-----END CERTIFICATE-----")
        with tempfile.TemporaryDirectory() as d:
            leaf_only = os.path.join(d, "leaf-only.pem")
            with open(leaf_only, "w", encoding="utf-8") as f:
                f.write(pem[:leaf_end] + "\n")
            r = run_wolfssl("verify", "-CAfile", leaf_only, leaf_only)
            self.assertNotEqual(r.returncode, 0)

    def test_help_trailing_h(self):
        """verify -h (as the final argument) prints usage and exits 0."""
        r = run_wolfssl("verify", "-h")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("wolfssl verify", r.stdout + r.stderr)

    def test_help_flag(self):
        """verify -help <cert> prints usage and exits 0."""
        r = run_wolfssl("verify", "-help",
                        os.path.join(CERTS_DIR, "server-cert.pem"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("wolfssl verify", r.stdout + r.stderr)

    def test_verify_der_cert(self):
        """A DER-encoded cert is loaded via the DER fallback path."""
        der_cert = os.path.join(CERTS_DIR, "ca-cert.der")
        if not os.path.isfile(der_cert):
            self.skipTest("ca-cert.der not present")
        r = run_wolfssl("verify", "-partial_chain", "-CAfile",
                        os.path.join(CERTS_DIR, "ca-cert.pem"), der_cert)
        self.assertEqual(r.returncode, 0, r.stderr)

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

    def test_cafile_bundle_root_order_independent(self):
        """-CAfile with [intermediate, root] (root not first) still succeeds."""
        with tempfile.TemporaryDirectory() as d:
            bundle = os.path.join(d, "int-then-root.pem")
            with open(bundle, "w", encoding="utf-8") as out:
                for name in ("ca-int-cert.pem", "ca-cert.pem"):
                    with open(os.path.join(CERTS_DIR, name),
                              encoding="utf-8") as f:
                        out.write(f.read())
            r = run_wolfssl("verify", "-CAfile", bundle,
                            os.path.join(CERTS_DIR, "ca-int2-cert.pem"))
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_cafile_bundle_skips_non_ca_cert_to_find_root(self):
        """-CAfile bundle with a non-CA cert before the root still finds it."""
        r = run_wolfssl("verify", "-CAfile",
                        os.path.join(CERTS_DIR, "server-cert.pem"),
                        os.path.join(CERTS_DIR, "server-cert.pem"))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_cafile_bundle_no_root_fails_with_message(self):
        """-CAfile with no self-signed root fails with a dedicated error."""
        r = run_wolfssl("verify", "-CAfile",
                        os.path.join(CERTS_DIR, "ca-int-cert.pem"),
                        os.path.join(CERTS_DIR, "ca-int2-cert.pem"))
        self.assertNotEqual(r.returncode, 0)
        combined = r.stdout + r.stderr
        self.assertIn("does not contain a self-signed root CA", combined)

    # NOTE: cert_is_self_signed_root()'s hard-error path needs fault
    # injection to trigger, so it's not covered by black-box tests here.



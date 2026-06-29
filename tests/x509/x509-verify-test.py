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
def _has_dilithium():
    """Return True if the current build supports Dilithium/ML-DSA."""
    r = run_wolfssl("-genkey", "-h")
    return "dilithium" in (r.stdout + r.stderr)


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
    """True if `x509 -text` can render an ML-DSA certificate.

    Some wolfSSL builds cannot print an ML-DSA SubjectPublicKey, so an ML-DSA
    cert fails to print even though it is generated and written correctly.
    Probe so print-dependent assertions run only where the build supports
    them."""
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
        """verify server-cert.pem as its own CA should fail."""
        r = run_wolfssl("verify", "-CAfile",
                        os.path.join(CERTS_DIR, "server-cert.pem"),
                        os.path.join(CERTS_DIR, "server-cert.pem"))
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


@unittest.skipUnless(_has_dilithium(), "ML-DSA (Dilithium) not available")
class TestX509VerifyMLDSA(unittest.TestCase):
    """Verification of pure ML-DSA self-signed certificates."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def _make_cert(self, level, cn):
        """Generate an ML-DSA self-signed cert at the given level.

        Uses explicit -genkey followed by req -x509 -key so that keygen
        failures are reported separately from cert-creation failures and
        the verify test is not coupled to the req -newkey code path.
        """
        key = os.path.join(self.dir, "k{}_{}".format(level, cn))
        cert = os.path.join(self.dir, "c_{}.pem".format(cn))
        r = run_wolfssl("-genkey", "ml-dsa", "-level", str(level),
                        "-out", key, "-output", "keypair", "-outform", "PEM")
        self.assertEqual(r.returncode, 0,
                         "ml-dsa keygen failed: " + r.stderr)
        priv = key + ".priv"
        r = run_wolfssl("req", "-x509", "-key", priv,
                        "-subj", "/CN={}".format(cn),
                        "-days", "1", "-out", cert)
        self.assertEqual(r.returncode, 0,
                         "ml-dsa cert gen failed: " + r.stderr)
        return cert

    def test_verify_self_signed_ok(self):
        """A valid ML-DSA self-signed cert verifies against itself."""
        cert = self._make_cert(2, "mldsa-ok")
        r = run_wolfssl("verify", "-CAfile", cert, cert)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_verify_level5_self_signed(self):
        """Level-5 (ML-DSA-87) self-signed cert verifies against itself.

        Complements test_verify_self_signed_ok (level 2) with the largest
        parameter set, which uses a different key/sig size path through
        ConfirmSignature in wolfcrypt/src/asn.c.
        """
        cert = self._make_cert(5, "mldsa-level5")
        r = run_wolfssl("verify", "-CAfile", cert, cert)
        self.assertEqual(
            r.returncode, 0,
            "ML-DSA level-5 cert failed to verify: " + r.stderr)

    def test_self_signed_der_roundtrip(self):
        """req -x509 -outform der produces a parseable DER self-signed cert.

        Exercises the DER output branch in wolfCLU_MLDSAWriteCertBio
        (wolfSSL_BIO_write path) which is distinct from the PEM path.
        """
        key = os.path.join(self.dir, "k_der")
        cert_der = os.path.join(self.dir, "c_der.der")
        r = run_wolfssl("-genkey", "ml-dsa", "-level", "2",
                        "-out", key, "-output", "keypair", "-outform", "PEM")
        self.assertEqual(r.returncode, 0,
                         "ml-dsa keygen failed: " + r.stderr)
        priv = key + ".priv"
        r = run_wolfssl("req", "-x509", "-key", priv,
                        "-subj", "/CN=mldsa-der-test",
                        "-days", "1", "-outform", "der", "-out", cert_der)
        self.assertEqual(r.returncode, 0,
                         "ml-dsa DER cert gen failed: " + r.stderr)
        self.assertTrue(os.path.isfile(cert_der),
                        "DER cert file not created")
        self.assertGreater(os.path.getsize(cert_der), 0,
                           "DER cert file is empty")
        # Parsing back via `x509 -text` needs ML-DSA cert printing, which not
        # every wolfSSL build supports; the DER write path above is the point
        # of this test, so only assert the round-trip where print is available.
        if _can_print_mldsa_cert():
            r = run_wolfssl("x509", "-in", cert_der, "-inform", "der",
                            "-text", "-noout")
            self.assertEqual(r.returncode, 0,
                             "DER cert not parseable: " + r.stderr)

    def test_verify_der_ca_file(self):
        """wolfssl verify accepts a DER-encoded CA file via the DER fallback path.

        Exercises the `loaded == 0` branch in wolfCLU_x509Verify where the PEM
        loop reads nothing and load_cert_from_file is called instead.
        """
        key = os.path.join(self.dir, "k_derca")
        cert_pem = os.path.join(self.dir, "c_derca.pem")
        ca_der = os.path.join(self.dir, "ca_derca.der")
        r = run_wolfssl("-genkey", "ml-dsa", "-level", "2",
                        "-out", key, "-output", "keypair", "-outform", "PEM")
        self.assertEqual(r.returncode, 0, "ml-dsa keygen failed: " + r.stderr)
        priv = key + ".priv"
        r = run_wolfssl("req", "-x509", "-key", priv,
                        "-subj", "/CN=mldsa-derca-test",
                        "-days", "1", "-out", cert_pem)
        self.assertEqual(r.returncode, 0,
                         "ml-dsa PEM cert gen failed: " + r.stderr)
        r = run_wolfssl("x509", "-in", cert_pem, "-outform", "der",
                        "-out", ca_der)
        self.assertEqual(r.returncode, 0,
                         "PEM->DER conversion failed: " + r.stderr)
        self.assertTrue(os.path.isfile(ca_der), "DER CA file not created")
        r = run_wolfssl("verify", "-CAfile", ca_der, cert_pem)
        self.assertEqual(r.returncode, 0,
                         "verify with DER CA failed: " + r.stderr)

    def test_verify_without_ca_fails(self):
        """An ML-DSA cert without -CAfile fails because no trust anchor is set."""
        cert = self._make_cert(3, "mldsa-noca")
        r = run_wolfssl("verify", cert)
        self.assertNotEqual(r.returncode, 0,
                            "verify should fail with no CA supplied")
        combined = (r.stdout + r.stderr).lower()
        self.assertTrue(
            "unable to get local issuer certificate" in combined
            or "verification failed" in combined,
            "expected a trust-anchor missing diagnostic, got: "
            + r.stdout + r.stderr)

    def test_verify_wrong_ca_fails(self):
        """An ML-DSA cert does not verify against an unrelated CA."""
        cert = self._make_cert(2, "mldsa-wrongca")
        r = run_wolfssl("verify", "-CAfile",
                        os.path.join(CERTS_DIR, "ca-cert.pem"), cert)
        self.assertNotEqual(r.returncode, 0,
                            "verify should fail against an unrelated CA")

    def test_verify_wrong_mldsa_ca_fails(self):
        """An ML-DSA cert signed by CA-1 must not verify against CA-2.
        This exercises CheckCertSignaturePubKey with a structurally valid
        ML-DSA cert and the wrong (but same-level) ML-DSA public key."""
        ca2_key = os.path.join(self.dir, "ca2-key")
        ca2_cert = os.path.join(self.dir, "ca2-cert.pem")
        r = run_wolfssl("req", "-x509", "-newkey", "ml-dsa:2",
                        "-keyout", ca2_key, "-subj", "/CN=ca2",
                        "-days", "1", "-out", ca2_cert)
        self.assertEqual(r.returncode, 0, "ca2 cert gen failed: " + r.stderr)

        cert = self._make_cert(2, "mldsa-wrongmldsa")
        r = run_wolfssl("verify", "-CAfile", ca2_cert, cert)
        self.assertNotEqual(r.returncode, 0,
                            "verify must fail: cert signed by CA-1, not CA-2")

    def test_verify_bad_cafile_fails(self):
        """A -CAfile that cannot be loaded must fail explicitly, not fall back
        to self-verification and report a spurious OK."""
        cert = self._make_cert(2, "mldsa-badca")
        bogus = os.path.join(self.dir, "does_not_exist.pem")
        r = run_wolfssl("verify", "-CAfile", bogus, cert)
        self.assertNotEqual(r.returncode, 0,
                            "verify must fail when -CAfile cannot be loaded")

    def test_verify_garbage_cafile_fails(self):
        """A readable -CAfile that is not a certificate must fail (PEM/DER parse error)."""
        cert = self._make_cert(2, "mldsa-garbage-ca")
        bogus = os.path.join(self.dir, "garbage.pem")
        with open(bogus, "w", encoding="utf-8") as f:
            f.write("not a certificate\n")
        r = run_wolfssl("verify", "-CAfile", bogus, cert)
        self.assertNotEqual(r.returncode, 0,
                            "verify must fail when -CAfile is not a cert")

    def test_verify_tampered_signature_fails(self):
        """Flipping bytes INSIDE the ML-DSA signature (the trailing BIT STRING
        content) must make verification fail. Mutating signature content does
        not change any ASN.1 lengths, so the cert still parses and the failure
        is unambiguously in signature verification, not DER decoding."""
        import base64
        cert = self._make_cert(2, "mldsa-tamper")
        with open(cert, "r", encoding="utf-8") as f:
            pem = f.read()
        b64 = "".join(ln for ln in pem.splitlines() if "-----" not in ln)
        der = bytearray(base64.b64decode(b64))
        # The ML-DSA signature is the final element of the cert; the last bytes
        # are signature content (thousands of bytes for ML-DSA). Flip several
        # bytes near the very end, comfortably inside the signature.
        for off in (-4, -12, -40):
            der[off] ^= 0xFF
        new_b64 = base64.encodebytes(bytes(der)).decode("ascii")
        tampered = os.path.join(self.dir, "tampered.pem")
        with open(tampered, "w", encoding="utf-8", newline="\n") as f:
            f.write("-----BEGIN CERTIFICATE-----\n" + new_b64 +
                    "-----END CERTIFICATE-----\n")

        r = run_wolfssl("verify", "-CAfile", tampered, tampered)
        self.assertNotEqual(r.returncode, 0,
                            "verify should fail on a signature-tampered cert")

    def test_verify_ca_tampered_signature_rejected(self):
        """An ML-DSA CA cert with a corrupted self-signature is rejected.

        Covers all build configs: wc_CheckCertSigPubKey when OPENSSL_EXTRA or
        WOLFSSL_SMALL_CERT_VERIFY is set; explicit fatal error otherwise.
        """
        import base64
        cert = self._make_cert(2, "mldsa-ca-tamper")
        with open(cert, "r", encoding="utf-8") as fh:
            pem = fh.read()
        b64 = "".join(ln for ln in pem.splitlines() if "-----" not in ln)
        der = bytearray(base64.b64decode(b64))
        for off in (-4, -12, -40):
            der[off] ^= 0xFF
        new_b64 = base64.encodebytes(bytes(der)).decode("ascii")
        tampered = os.path.join(self.dir, "tampered-ca.pem")
        with open(tampered, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("-----BEGIN CERTIFICATE-----\n" + new_b64 +
                     "-----END CERTIFICATE-----\n")
        r = run_wolfssl("verify", "-CAfile", tampered, tampered)
        self.assertNotEqual(r.returncode, 0,
                            "verify should reject a signature-tampered CA cert")

    def test_verify_der_companion_pub(self):
        """wolfCLU_LoadMLDSACompanionPub accepts a DER-format companion .pub.

        When -genkey uses -outform DER the companion .pub file is raw DER.
        wolfCLU_LoadMLDSACompanionPub falls back to raw-DER decode when
        wolfCLU_KeyPemToDer returns <=0 (file is already DER). This test
        exercises that fallback path (LOW-12)."""
        key = os.path.join(self.dir, "k_der_companion")
        cert = os.path.join(self.dir, "c_der_companion.pem")
        r = run_wolfssl("-genkey", "ml-dsa", "-level", "2",
                        "-out", key, "-output", "keypair", "-outform", "DER")
        if r.returncode != 0:
            self.skipTest("DER keygen unsupported: " + r.stderr)
        priv = key + ".priv"
        r = run_wolfssl("req", "-x509", "-key", priv,
                        "-subj", "/CN=mldsa-der-companion",
                        "-days", "1", "-out", cert)
        self.assertEqual(r.returncode, 0,
                         "cert gen with DER companion pub failed: " + r.stderr)
        r = run_wolfssl("verify", "-CAfile", cert, cert)
        self.assertEqual(r.returncode, 0,
                         "verify with DER companion pub failed: " + r.stderr)


if __name__ == "__main__":
    test_main()

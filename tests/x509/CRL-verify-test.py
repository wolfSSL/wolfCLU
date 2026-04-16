#!/usr/bin/env python3
"""Tests for wolfssl crl (converted from CRL-verify-test.sh)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import CERTS_DIR, run_wolfssl, test_main


def _has_crl():
    """Check whether CRL support is compiled in."""
    r = run_wolfssl("crl", "-CAfile",
                    os.path.join(CERTS_DIR, "ca-cert.pem"),
                    "-in", os.path.join(CERTS_DIR, "crl.pem"))
    combined = r.stdout + r.stderr
    return "recompile wolfSSL with CRL support" not in combined


def _has_crl_text():
    """Check whether CRL -text is available (not just 'print not available')."""
    r = run_wolfssl("crl", "-in", os.path.join(CERTS_DIR, "crl.pem"),
                    "-text")
    combined = r.stdout + r.stderr
    # If it says "not available", the feature is missing
    return "CRL print not available in version of wolfSSL" not in combined


def _cleanup(*files):
    for f in files:
        if os.path.exists(f):
            os.remove(f)


class TestCRLVerify(unittest.TestCase):
    """CRL verification tests."""

    @classmethod
    def setUpClass(cls):
        cls.have_crl = _has_crl()
        if not cls.have_crl:
            raise unittest.SkipTest("CRL not compiled into wolfSSL")

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_crl_print(self):
        """CRL output should contain BEGIN marker."""
        r = run_wolfssl("crl", "-CAfile",
                        os.path.join(CERTS_DIR, "ca-cert.pem"),
                        "-in", os.path.join(CERTS_DIR, "crl.pem"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("BEGIN", r.stdout)

    def test_crl_noout(self):
        """CRL -noout should not print the CRL PEM."""
        r = run_wolfssl("crl", "-noout", "-CAfile",
                        os.path.join(CERTS_DIR, "ca-cert.pem"),
                        "-in", os.path.join(CERTS_DIR, "crl.pem"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("BEGIN X509 CRL", r.stdout)

    def test_crl_der_parse_cert_fails(self):
        """Parsing a certificate as CRL (DER) should fail."""
        r = run_wolfssl("crl", "-inform", "DER", "-outform", "PEM",
                        "-in", os.path.join(CERTS_DIR, "ca-cert.der"))
        self.assertNotEqual(r.returncode, 0)

    def test_crl_verify_with_wrong_ca(self):
        """CRL verification with a non-CA cert should fail."""
        client_cert = "test_crl_client.pem"
        self._clean(client_cert)
        r = run_wolfssl("req", "-new", "-days", "3650",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj",
                        "/O=wolfSSL/C=US/ST=WA/L=Seattle/CN=wolfSSL/OU=org-unit",
                        "-out", client_cert, "-x509")
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("crl", "-noout", "-CAfile", client_cert,
                        "-in", os.path.join(CERTS_DIR, "crl.pem"))
        self.assertNotEqual(r.returncode, 0)

    def test_crl_missing_cafile_fails(self):
        """CRL with nonexistent CAfile should fail."""
        r = run_wolfssl("crl", "-noout", "-CAfile",
                        os.path.join(CERTS_DIR, "ca-cer.pem"),
                        "-in", os.path.join(CERTS_DIR, "crl.pem"))
        self.assertNotEqual(r.returncode, 0)

    def test_crl_missing_input_fails(self):
        """CRL with nonexistent input file should fail."""
        r = run_wolfssl("crl", "-noout", "-CAfile",
                        os.path.join(CERTS_DIR, "ca-cert.pem"),
                        "-in", os.path.join(CERTS_DIR, "cl.pem"))
        self.assertNotEqual(r.returncode, 0)

    def test_crl_verify_wrong_issuer_fails(self):
        """CRL verification with wrong issuer cert should fail."""
        r = run_wolfssl("crl", "-noout", "-CAfile",
                        os.path.join(CERTS_DIR, "client-int-cert.pem"),
                        "-in", os.path.join(CERTS_DIR, "crl.pem"))
        self.assertNotEqual(r.returncode, 0)

    def test_crl_der_to_pem(self):
        """CRL DER -> PEM conversion and verification."""
        out_pem = "test_crl_d2p.pem"
        self._clean(out_pem)

        r = run_wolfssl("crl", "-inform", "DER", "-outform", "PEM",
                        "-in", os.path.join(CERTS_DIR, "crl.der"),
                        "-out", out_pem)
        self.assertEqual(r.returncode, 0, r.stderr)

        r2 = run_wolfssl("crl", "-noout", "-CAfile",
                         os.path.join(CERTS_DIR, "ca-cert.pem"),
                         "-in", out_pem)
        self.assertEqual(r2.returncode, 0, r2.stderr)

    def test_crl_der_cert_to_pem_fails(self):
        """Converting a cert DER as CRL should fail."""
        out = "test_crl_bad.pem"
        self._clean(out)
        r = run_wolfssl("crl", "-inform", "DER", "-outform", "PEM",
                        "-in", os.path.join(CERTS_DIR, "ca-cert.der"),
                        "-out", out)
        self.assertNotEqual(r.returncode, 0)

    def test_crl_fail_no_output_file(self):
        """Failed CRL conversion should not create output file."""
        out = "test_crl_nofile.pem"
        _cleanup(out)  # ensure clean before test
        self._clean(out)
        r = run_wolfssl("crl", "-inform", "DER", "-outform", "PEM",
                        "-in", os.path.join(CERTS_DIR, "ca-cert.der"),
                        "-out", out)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.isfile(out),
                         "output file should not be created on failure")

    def test_crl_invalid_outform_error_message(self):
        """Invalid -outform value must produce an outform-related error."""
        r = run_wolfssl("crl", "-in", os.path.join(CERTS_DIR, "crl.pem"),
                        "-outform", "INVALID")
        combined = (r.stdout + r.stderr).lower()
        self.assertIn("outform", combined,
                      "Expected 'outform' in error output, got: {}".format(
                          combined))


class TestCRLText(unittest.TestCase):
    """CRL -text output tests."""

    @classmethod
    def setUpClass(cls):
        if not _has_crl():
            raise unittest.SkipTest("CRL not compiled into wolfSSL")
        if not _has_crl_text():
            raise unittest.SkipTest("CRL -text not available in this wolfSSL")

    def test_crl_text_noout(self):
        """CRL -text -noout should show CRL info."""
        r = run_wolfssl("crl", "-noout",
                        "-in", os.path.join(CERTS_DIR, "crl.pem"),
                        "-text")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Certificate Revocation List (CRL):", r.stdout)


if __name__ == "__main__":
    test_main()

#!/usr/bin/env python3
"""Tests for wolfssl x509 processing (converted from x509-process-test.sh)."""

import os
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import WOLFSSL_BIN, CERTS_DIR, run_wolfssl

TESTS_X509_DIR = os.path.join(".", "tests", "x509")
HAS_OPENSSL = shutil.which("openssl") is not None


def _check_cert_signature(cert_path, digest, inform="PEM"):
    """Use OpenSSL to verify the signature on a self-signed certificate.

    Returns True on success, raises AssertionError on failure.
    Requires openssl, xxd, and the cert to be self-signed.
    """
    if not HAS_OPENSSL:
        raise unittest.SkipTest("openssl not available")

    stripped = cert_path + ".stripped.pem"
    sig_bin = cert_path + ".sig.bin"
    body_bin = cert_path + ".body.bin"
    pub_pem = cert_path + ".pub.pem"
    try:
        subprocess.run(
            ["openssl", "x509", "-inform", inform, "-in", cert_path,
             "-out", stripped, "-outform", "PEM"],
            check=True, capture_output=True, timeout=60)

        # Extract signature hex
        r = subprocess.run(
            ["openssl", "x509", "-in", stripped, "-text", "-noout",
             "-certopt", "ca_default", "-certopt", "no_validity",
             "-certopt", "no_serial", "-certopt", "no_subject",
             "-certopt", "no_extensions", "-certopt", "no_signame"],
            check=True, capture_output=True, text=True, timeout=60)
        lines = []
        for line in r.stdout.splitlines():
            if "Signature Algorithm" in line:
                continue
            if "Signature Value" in line:
                continue
            stripped_line = line.replace(" ", "").replace(":", "")
            if stripped_line:
                lines.append(stripped_line)
        sig_hex = "".join(lines)

        with open(sig_bin, "wb") as f:
            f.write(bytes.fromhex(sig_hex))

        subprocess.run(
            ["openssl", "asn1parse", "-in", stripped, "-strparse", "4",
             "-out", body_bin, "-noout"],
            check=True, capture_output=True, timeout=60)

        with open(pub_pem, "w") as pub_f:
            subprocess.run(
                ["openssl", "x509", "-in", stripped, "-noout", "-pubkey"],
                check=True, stdout=pub_f, stderr=subprocess.DEVNULL,
                timeout=60)

        r = subprocess.run(
            ["openssl", "dgst", "-" + digest, "-verify", pub_pem,
             "-signature", sig_bin, body_bin],
            capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, "Signature verification failed for {}".format(cert_path)
    finally:
        for f in [stripped, sig_bin, body_bin, pub_pem]:
            try:
                os.remove(f)
            except OSError:
                pass


def _cleanup(*files):
    for f in files:
        if os.path.exists(f):
            os.remove(f)


class TestX509ProcessValid(unittest.TestCase):
    """run1: valid PEM/DER format conversions and combined file handling."""

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_1a_pem_to_pem(self):
        """PEM -> PEM conversion produces valid output file."""
        out = "test_1a.pem"
        self._clean(out)
        r = run_wolfssl("x509", "-inform", "pem", "-outform", "pem",
                        "-in", os.path.join(CERTS_DIR, "ca-cert.pem"),
                        "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(out), "output file not created")

    @unittest.skipUnless(HAS_OPENSSL, "openssl not available")
    def test_1a_pem_to_pem_signature(self):
        out = "test_1a_sig.pem"
        self._clean(out)
        r = run_wolfssl("x509", "-inform", "pem", "-outform", "pem",
                        "-in", os.path.join(CERTS_DIR, "ca-cert.pem"),
                        "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        _check_cert_signature(out, "sha256")

    def test_1b_pem_text_noout_matches(self):
        """PEM text/noout output is identical for original and round-tripped cert."""
        out1 = "test_1b_out.pem"
        out2 = "test_1b_ca.pem"
        tmp = "test_1b_tmp.pem"
        self._clean(out1, out2, tmp)

        r = run_wolfssl("x509", "-inform", "pem", "-outform", "pem",
                        "-in", os.path.join(CERTS_DIR, "ca-cert.pem"),
                        "-out", tmp)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run_wolfssl("x509", "-in", tmp, "-text", "-noout", "-out", out1)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run_wolfssl("x509", "-in", os.path.join(CERTS_DIR, "ca-cert.pem"),
                        "-text", "-noout", "-out", out2)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(out1) as f:
            data1 = f.read()
        with open(out2) as f:
            data2 = f.read()
        self.assertEqual(data1, data2, "PEM text/noout mismatch")

    def test_1c_pem_to_der(self):
        """PEM -> DER conversion succeeds."""
        out = "test_1c.der"
        self._clean(out)
        r = run_wolfssl("x509", "-inform", "pem", "-outform", "der",
                        "-in", os.path.join(CERTS_DIR, "ca-cert.pem"),
                        "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)

    @unittest.skipUnless(HAS_OPENSSL, "openssl not available")
    def test_1c_pem_to_der_signature(self):
        out = "test_1c_sig.der"
        self._clean(out)
        r = run_wolfssl("x509", "-inform", "pem", "-outform", "der",
                        "-in", os.path.join(CERTS_DIR, "ca-cert.pem"),
                        "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        _check_cert_signature(out, "sha256", inform="DER")

    def test_1d_der_to_pem_stdout(self):
        """DER -> PEM to stdout succeeds."""
        r = run_wolfssl("x509", "-inform", "der", "-outform", "pem",
                        "-in", os.path.join(CERTS_DIR, "ca-cert.der"))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_1e_der_to_der(self):
        """DER -> DER conversion succeeds."""
        out = "test_1e.der"
        self._clean(out)
        r = run_wolfssl("x509", "-inform", "der", "-outform", "der",
                        "-in", os.path.join(CERTS_DIR, "ca-cert.der"),
                        "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)

    @unittest.skipUnless(HAS_OPENSSL, "openssl not available")
    def test_1e_der_to_der_signature(self):
        out = "test_1e_sig.der"
        self._clean(out)
        r = run_wolfssl("x509", "-inform", "der", "-outform", "der",
                        "-in", os.path.join(CERTS_DIR, "ca-cert.der"),
                        "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        _check_cert_signature(out, "sha256", inform="DER")

    def test_1f_der_text_noout(self):
        """DER text/noout succeeds."""
        r = run_wolfssl("x509", "-inform", "der", "-text", "-noout",
                        "-in", os.path.join(CERTS_DIR, "ca-cert.der"))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_1g_der_pubkey_noout(self):
        """DER pubkey/noout succeeds."""
        r = run_wolfssl("x509", "-inform", "der", "-pubkey", "-noout",
                        "-in", os.path.join(CERTS_DIR, "ca-cert.der"))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_1h_der_to_pem_file(self):
        """DER -> PEM to file succeeds."""
        out = "test_1h.pem"
        self._clean(out)
        r = run_wolfssl("x509", "-inform", "der", "-outform", "pem",
                        "-in", os.path.join(CERTS_DIR, "ca-cert.der"),
                        "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)

    @unittest.skipUnless(HAS_OPENSSL, "openssl not available")
    def test_1h_der_to_pem_signature(self):
        out = "test_1h_sig.pem"
        self._clean(out)
        r = run_wolfssl("x509", "-inform", "der", "-outform", "pem",
                        "-in", os.path.join(CERTS_DIR, "ca-cert.der"),
                        "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        _check_cert_signature(out, "sha256")

    def test_1i_combined_pem(self):
        """Combined key+cert PEM file is handled correctly."""
        combined = "test_1i_combined.pem"
        process_out = "test_1i_process.pem"
        ca_out = "test_1i_ca.pem"
        self._clean(combined, process_out, ca_out)

        key_path = os.path.join(CERTS_DIR, "ca-key.pem")
        cert_path = os.path.join(CERTS_DIR, "ca-cert.pem")
        with open(key_path) as kf, open(cert_path) as cf:
            with open(combined, "w") as out:
                out.write(kf.read())
                out.write(cf.read())

        r = run_wolfssl("x509", "-in", combined, "-out", process_out)
        self.assertEqual(r.returncode, 0, r.stderr)

        r1 = run_wolfssl("x509", "-in", process_out, "-text")
        self.assertEqual(r1.returncode, 0, r1.stderr)

        r2 = run_wolfssl("x509", "-in", cert_path, "-text")
        self.assertEqual(r2.returncode, 0, r2.stderr)

        self.assertEqual(r1.stdout, r2.stdout,
                         "combined PEM output differs from original")


class TestX509ProcessInvalidInput(unittest.TestCase):
    """run2: invalid argument combinations should fail."""

    def _fail(self, *args):
        r = run_wolfssl("x509", *args)
        self.assertNotEqual(r.returncode, 0,
                            "expected failure for: {}".format(args))

    def test_2a_double_inform(self):
        self._fail("-inform", "pem", "-inform", "der")

    def test_2b_double_outform(self):
        self._fail("-outform", "pem", "-outform", "der")

    def test_2c_inform_inform(self):
        self._fail("-inform", "-inform")

    def test_2d_outform_outform(self):
        self._fail("-outform", "-outform")

    def test_2e_triple_inform(self):
        self._fail("-inform", "pem", "-inform", "der", "-inform")

    def test_2f_triple_outform(self):
        self._fail("-outform", "pem", "-outform", "der", "-outform")

    def test_2g_inform_outform_inform(self):
        self._fail("-inform", "pem", "-outform", "der", "-inform")

    def test_2h_outform_inform_outform(self):
        self._fail("-outform", "pem", "-inform", "der", "-outform")

    def test_2i_inform_alone(self):
        self._fail("-inform")

    def test_2j_outform_alone(self):
        self._fail("-outform")

    def test_2k_double_outform_noout(self):
        self._fail("-outform", "pem", "-outform", "der", "-noout")

    def test_2l_outform_outform_noout(self):
        self._fail("-outform", "-outform", "-noout")

    def test_2m_triple_outform_noout(self):
        self._fail("-outform", "pem", "-outform", "der", "-outform", "-noout")

    def test_2n_inform_outform_inform_noout(self):
        self._fail("-inform", "pem", "-outform", "der", "-inform", "-noout")

    def test_2o_outform_inform_outform_noout(self):
        self._fail("-outform", "pem", "-inform", "der", "-outform", "-noout")

    def test_2p_outform_noout(self):
        self._fail("-outform", "-noout")


class TestX509ProcessValidFiles(unittest.TestCase):
    """run3: valid input file operations and field extraction."""

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_3a_der_to_pem_matches(self):
        """DER -> PEM matches original PEM."""
        test_pem = "test_3a.pem"
        tmp_pem = "test_3a_tmp.pem"
        self._clean(test_pem, tmp_pem)

        r = run_wolfssl("x509", "-inform", "pem",
                        "-in", os.path.join(CERTS_DIR, "ca-cert.pem"),
                        "-outform", "pem", "-out", test_pem)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run_wolfssl("x509", "-inform", "der",
                        "-in", os.path.join(CERTS_DIR, "ca-cert.der"),
                        "-outform", "pem", "-out", tmp_pem)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(test_pem) as f1, open(tmp_pem) as f2:
            self.assertEqual(f1.read(), f2.read())

    def test_3b_pem_to_der_matches(self):
        """Two PEM -> DER conversions produce identical output."""
        der1 = "test_3b_1.der"
        der2 = "test_3b_2.der"
        self._clean(der1, der2)

        r = run_wolfssl("x509", "-inform", "pem",
                        "-in", os.path.join(CERTS_DIR, "ca-cert.pem"),
                        "-outform", "der", "-out", der1)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run_wolfssl("x509", "-inform", "pem", "-outform", "der",
                        "-in", os.path.join(CERTS_DIR, "ca-cert.pem"),
                        "-out", der2)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(der1, "rb") as f1, open(der2, "rb") as f2:
            self.assertEqual(f1.read(), f2.read())

    def test_3c_subject(self):
        expected_file = os.path.join(TESTS_X509_DIR, "expect-subject.txt")
        with open(expected_file) as f:
            expected = f.read().strip()
        r = run_wolfssl("x509", "-in",
                        os.path.join(CERTS_DIR, "server-cert.pem"),
                        "-subject", "-noout")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), expected)

    def test_3d_issuer(self):
        expected_file = os.path.join(TESTS_X509_DIR, "expect-issuer.txt")
        with open(expected_file) as f:
            expected = f.read().strip()
        r = run_wolfssl("x509", "-in",
                        os.path.join(CERTS_DIR, "server-cert.pem"),
                        "-issuer", "-noout")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), expected)

    def test_3e_ca_serial(self):
        expected_file = os.path.join(TESTS_X509_DIR, "expect-ca-serial.txt")
        with open(expected_file) as f:
            expected = f.read().strip()
        r = run_wolfssl("x509", "-in",
                        os.path.join(CERTS_DIR, "ca-cert.pem"),
                        "-serial", "-noout")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), expected)

    def test_3f_server_serial(self):
        expected_file = os.path.join(TESTS_X509_DIR,
                                     "expect-server-serial.txt")
        with open(expected_file) as f:
            expected = f.read().strip()
        r = run_wolfssl("x509", "-in",
                        os.path.join(CERTS_DIR, "server-cert.pem"),
                        "-serial", "-noout")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), expected)

    def test_3g_dates(self):
        expected_file = os.path.join(TESTS_X509_DIR, "expect-dates.txt")
        with open(expected_file) as f:
            expected = f.read().strip()
        r = run_wolfssl("x509", "-in",
                        os.path.join(CERTS_DIR, "server-cert.pem"),
                        "-dates", "-noout")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), expected)

    def test_3h_email(self):
        expected_file = os.path.join(TESTS_X509_DIR, "expect-email.txt")
        with open(expected_file) as f:
            expected = f.read().strip()
        r = run_wolfssl("x509", "-in",
                        os.path.join(CERTS_DIR, "server-cert.pem"),
                        "-email", "-noout")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), expected)

    def test_3i_fingerprint(self):
        expected_file = os.path.join(TESTS_X509_DIR,
                                     "expect-fingerprint.txt")
        with open(expected_file) as f:
            expected = f.read().strip()
        r = run_wolfssl("x509", "-in",
                        os.path.join(CERTS_DIR, "server-cert.pem"),
                        "-fingerprint", "-noout")
        self.assertEqual(r.returncode, 0, r.stderr)
        # Strip the prefix "SHA1 of cert. DER : " if present
        output = r.stdout.strip()
        prefix = "SHA1 of cert. DER : "
        if output.startswith(prefix):
            output = output[len(prefix):]
        self.assertEqual(output, expected)

    def test_3j_purpose(self):
        expected_file = os.path.join(TESTS_X509_DIR, "expect-purpose.txt")
        with open(expected_file) as f:
            expected = f.read().strip()
        r = run_wolfssl("x509", "-in",
                        os.path.join(CERTS_DIR, "server-cert.pem"),
                        "-purpose", "-noout")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), expected)

    def test_3k_hash(self):
        expected_file = os.path.join(TESTS_X509_DIR, "expect-hash.txt")
        with open(expected_file) as f:
            expected = f.read().strip()
        old_expected = "f6cf410e"
        r = run_wolfssl("x509", "-in",
                        os.path.join(CERTS_DIR, "server-cert.pem"),
                        "-hash", "-noout")
        self.assertEqual(r.returncode, 0, r.stderr)
        output = r.stdout.strip()
        self.assertTrue(output == expected or output == old_expected,
                        "hash {} does not match expected {} or {}".format(
                            output, expected, old_expected))

    def test_3l_email_from_generated_cert(self):
        """Email from a generated self-signed cert (no email) should succeed."""
        tmp_cert = "test_3l.cert"
        self._clean(tmp_cert)
        r = run_wolfssl("req", "-new", "-days", "3650",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj",
                        "/O=wolfSSL/C=US/ST=WA/L=Seattle/CN=wolfSSL/OU=org-unit",
                        "-out", tmp_cert, "-x509")
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run_wolfssl("x509", "-in", tmp_cert, "-email", "-noout")
        self.assertEqual(r.returncode, 0, r.stderr)


class TestX509ProcessInvalidFiles(unittest.TestCase):
    """run4: invalid input files should fail."""

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_4a_double_in(self):
        r = run_wolfssl("x509", "-inform", "der",
                        "-in", os.path.join(CERTS_DIR, "ca-cert.der"),
                        "-in", os.path.join(CERTS_DIR, "ca-cert.der"),
                        "-outform", "pem", "-out", "tmp_4a.pem")
        self._clean("tmp_4a.pem")
        self.assertNotEqual(r.returncode, 0)

    def test_4b_double_out(self):
        r = run_wolfssl("x509", "-inform", "der",
                        "-in", os.path.join(CERTS_DIR, "ca-cert.der"),
                        "-outform", "pem", "-out", "tmp_4b.pem",
                        "-out", "tmp_4b.pem")
        self._clean("tmp_4b.pem")
        self.assertNotEqual(r.returncode, 0)

    def test_4c_double_out_double_in(self):
        r = run_wolfssl("x509", "-inform", "pem", "-outform", "der",
                        "-in", os.path.join(CERTS_DIR, "ca-cert.pem"),
                        "-out", "tmp_4c.der", "-out", "tmp_4c.der",
                        "-in", os.path.join(CERTS_DIR, "ca-cert.pem"))
        self._clean("tmp_4c.der")
        self.assertNotEqual(r.returncode, 0)

    def test_4d_pem_inform_with_der_file(self):
        """PEM inform with DER file should fail and not create output."""
        out = "test_4d.der"
        self._clean(out)
        _cleanup(out)  # ensure it doesn't exist before test
        r = run_wolfssl("x509", "-inform", "pem",
                        "-in", os.path.join(CERTS_DIR, "ca-cert.der"),
                        "-outform", "der", "-out", out)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.isfile(out),
                         "output file should not be created on error")

    def test_4e_nonexistent_file_der(self):
        r = run_wolfssl("x509", "-inform", "der", "-in", "ca-cert.pem",
                        "-outform", "der", "-out", "out.txt")
        self._clean("out.txt")
        self.assertNotEqual(r.returncode, 0)

    def test_4f_nonexistent_file_pem(self):
        r = run_wolfssl("x509", "-inform", "pem", "-in", "ca-cert.pem",
                        "-outform", "pem", "-out", "out.txt")
        self._clean("out.txt")
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()

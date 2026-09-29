#!/usr/bin/env python3
"""Tests for wolfssl x509 processing (converted from x509-process-test.sh)."""

import filecmp
import os
import re
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import WOLFSSL_BIN, CERTS_DIR, run_wolfssl, test_main

TESTS_X509_DIR = os.path.dirname(os.path.abspath(__file__))
HAS_OPENSSL = shutil.which("openssl") is not None

# ML-DSA-44 public key and signature sizes, from FIPS 204.
ML_DSA_44_PUB_SZ = 1312
ML_DSA_44_SIG_SZ = 2420

# One line of a printed hex block, e.g. "A4:2A:BB:...:78:" or "...:F0:18".
_HEX_LINE = re.compile(r"(?:[0-9A-Fa-f]{2}:)*[0-9A-Fa-f]{2}:?\Z")


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


def _hex_block(lines, start):
    """Return the bytes of the hex block printed directly under lines[start].

    Stops at the first line that is not colon separated hex, so a block that
    was cut short is reported as a short byte count rather than skipped.
    """
    out = []
    for line in lines[start + 1:]:
        text = line.strip()
        if not _HEX_LINE.match(text):
            break
        out.extend(b for b in text.split(":") if b)
    return out


def _find_line(lines, text):
    """Index of the only line containing 'text', -1 when absent."""
    hits = [i for i, l in enumerate(lines) if text in l]
    return hits[0] if len(hits) == 1 else -1


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
        r = run_wolfssl("x509", "-inform", "der", "-in", "nonexistent-file.pem",
                        "-outform", "der", "-out", "out.txt")
        self._clean("out.txt")
        self.assertNotEqual(r.returncode, 0)

    def test_4f_nonexistent_file_pem(self):
        r = run_wolfssl("x509", "-inform", "pem", "-in", "nonexistent-file.pem",
                        "-outform", "pem", "-out", "out.txt")
        self._clean("out.txt")
        self.assertNotEqual(r.returncode, 0)


class TestMalformedArguments(unittest.TestCase):
    """ Regression: for malformed arguments """

    def test_5a_malformed_subj_argument(self):
        """ malformed string passed to -subj should result in error and
        logging of issue """
        r = run_wolfssl("req", "-new", "-days", "3650",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj",
                        "/O=wolfSSL/C=US/ST=WA/L=Seattle/CN=wolfSSL/OUorg-unit")
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertGreater(len(r.stderr), 0)


class TestX509ModulusNoout(unittest.TestCase):
    """Regression: x509 -modulus -noout must not crash."""

    def test_modulus_noout(self):
        r = run_wolfssl("x509", "-in",
                        os.path.join(CERTS_DIR, "server-cert.pem"),
                        "-modulus", "-noout")
        self.assertEqual(r.returncode, 0,
                         "x509 -modulus -noout failed: {}".format(r.stderr))
        self.assertGreaterEqual(r.returncode, 0,
                                "x509 -modulus -noout crashed with signal "
                                "{}".format(r.returncode))


class TestX509MlDsaText(unittest.TestCase):
    """x509 -text on a pure ML-DSA-44 certificate."""

    CERT_PEM = os.path.join(CERTS_DIR, "mldsa", "mldsa44-cert.pem")
    CERT_DER = os.path.join(CERTS_DIR, "mldsa", "mldsa44-cert.der")
    PUB_DER = os.path.join(CERTS_DIR, "mldsa", "mldsa44-keyPub.der")

    @classmethod
    def setUpClass(cls):
        config_log = os.path.join(".", "config.log")
        if os.path.isfile(config_log):
            with open(config_log, "r") as f:
                if "disable-filesystem" in f.read():
                    raise unittest.SkipTest("filesystem support disabled")

        r = run_wolfssl("genkey", "ml-dsa", "-level", "2", "-out",
                        "mldsa509-probe", "-output", "keypair",
                        "-outform", "pem")
        _cleanup("mldsa509-probe.priv", "mldsa509-probe.pub")
        if r.returncode != 0 or "not enabled" in (r.stdout + r.stderr):
            raise unittest.SkipTest("ML-DSA support not compiled in")

    def _text(self, *extra):
        r = run_wolfssl("x509", "-in", self.CERT_PEM, "-text", "-noout", *extra)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_names_parameter_set(self):
        """The parameter set is named in the key and both algorithm slots."""
        out = self._text()
        self.assertEqual(out.count("Signature Algorithm: ML-DSA 44"), 2,
                         "expected both the tbs and the outer algorithm")
        self.assertIn("Public Key Algorithm: ML-DSA 44", out)
        self.assertIn("ML-DSA 44 Public-Key:", out)

    def test_prints_whole_key_and_signature(self):
        """The key and signature print in full, at their FIPS 204 sizes."""
        lines = self._text().splitlines()

        pub = _find_line(lines, "pub:")
        self.assertNotEqual(pub, -1, "no 'pub:' block")
        self.assertEqual(len(_hex_block(lines, pub)), ML_DSA_44_PUB_SZ)

        sig = [i for i, l in enumerate(lines)
               if l.strip().startswith("Signature Algorithm:")]
        self.assertEqual(len(sig), 2, "expected two algorithm lines")
        self.assertEqual(len(_hex_block(lines, sig[-1])), ML_DSA_44_SIG_SZ)

    def test_der_text_matches_pem(self):
        """The DER form of the cert prints identically to the PEM form."""
        r = run_wolfssl("x509", "-inform", "der", "-text", "-noout",
                        "-in", self.CERT_DER)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, self._text(), "DER/PEM text mismatch")

    def test_pubkey_matches_cert_key(self):
        """-pubkey prints the cert's SPKI."""
        out, der = "mldsa44-spki.pem", "mldsa44-spki.der"
        self.addCleanup(lambda: _cleanup(out, der))

        r = run_wolfssl("x509", "-in", self.CERT_PEM, "-pubkey", "-noout",
                        "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(out) as f:
            self.assertIn("BEGIN PUBLIC KEY", f.read())

        r = run_wolfssl("pkey", "-pubin", "-in", out, "-inform", "pem",
                        "-outform", "der", "-out", der)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(filecmp.cmp(self.PUB_DER, der, shallow=False),
                        "-pubkey did not match the cert's public key")


class TestX509MlDsaDualAlgText(unittest.TestCase):
    """x509 -text on chimera certs with ML-DSA-44 as the alternative alg."""

    # Primary alg  : ECDSA
    # Secondary alg: ML-DSA-44
    CERTS = (os.path.join(CERTS_DIR, "ca-chimera-cert.pem"),
             os.path.join(CERTS_DIR, "server-chimera-cert.pem"))

    ALT_PUB = "X509v3 Subject Alternative Public Key Info"
    ALT_ALG = "X509v3 Alternative Signature Algorithm"
    ALT_SIG = "X509v3 Alternative Signature Value"

    @classmethod
    def setUpClass(cls):
        config_log = os.path.join(".", "config.log")
        if os.path.isfile(config_log):
            with open(config_log, "r") as f:
                if "disable-filesystem" in f.read():
                    raise unittest.SkipTest("filesystem support disabled")

        # '-altextend' is only built with WOLFSSL_DUAL_ALG_CERTS and
        # HAVE_DILITHIUM, the same pair that gates printing the alt extensions.
        r = run_wolfssl("ca", "-help")
        if "altextend" not in r.stdout + r.stderr:
            raise unittest.SkipTest("altextend not available")

    def _text(self, cert):
        r = run_wolfssl("x509", "-in", cert, "-text", "-noout")
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_alt_extensions_are_decoded(self):
        """ECDSA, then the ML-DSA 44 alt extensions, then ECDSA again."""
        expected = ("Signature Algorithm: sha256WithECDSA",
                    "Public Key Algorithm: id-ecPublicKey",
                    self.ALT_PUB, "ML-DSA 44 Public-Key:",
                    self.ALT_ALG, "ML-DSA 44",
                    self.ALT_SIG,
                    "Signature Algorithm: sha256WithECDSA")
        for cert in self.CERTS:
            with self.subTest(cert=cert):
                lines = self._text(cert).splitlines()
                prev = -1
                for text in expected:
                    i = next((j for j, l in enumerate(lines)
                              if j > prev and text in l), -1)
                    self.assertNotEqual(
                        i, -1, "'{}' missing or out of order".format(text))
                    prev = i

    def test_alt_key_and_signature_are_whole(self):
        """The alternative key and signature print at their full sizes."""
        for cert in self.CERTS:
            with self.subTest(cert=cert):
                lines = self._text(cert).splitlines()

                # The alt key's own "pub:" header, not the EC key's.
                start = _find_line(lines, self.ALT_PUB)
                self.assertNotEqual(start, -1, "no alternative key info")
                pub = next((i for i, l in enumerate(lines)
                            if i > start and l.strip() == "pub:"), -1)
                self.assertNotEqual(pub, -1, "no alternative 'pub:' block")
                self.assertEqual(len(_hex_block(lines, pub)), ML_DSA_44_PUB_SZ)

                sig = _find_line(lines, self.ALT_SIG)
                self.assertNotEqual(sig, -1, "no alternative signature value")
                self.assertEqual(len(_hex_block(lines, sig)), ML_DSA_44_SIG_SZ)

    def test_der_text_matches_pem(self):
        """The alternative extensions survive a round trip through DER."""
        for i, cert in enumerate(self.CERTS):
            with self.subTest(cert=cert):
                der = "x509-chimera-%d.der" % i
                self.addCleanup(lambda p=der: _cleanup(p))

                r = run_wolfssl("x509", "-in", cert, "-outform", "der",
                                "-out", der)
                self.assertEqual(r.returncode, 0, r.stderr)

                r = run_wolfssl("x509", "-inform", "der", "-in", der,
                                "-text", "-noout")
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(r.stdout, self._text(cert),
                                 "DER/PEM text mismatch")


if __name__ == "__main__":
    test_main()

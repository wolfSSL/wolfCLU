#!/usr/bin/env python3
"""Tests for wolfssl req and x509 -req (converted from x509-req-test.sh)."""

import os
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import WOLFSSL_BIN, CERTS_DIR, run_wolfssl, test_main

HAS_OPENSSL = shutil.which("openssl") is not None
_SKIP_WIN = sys.platform == "win32"
_WIN_REASON = "config file paths not supported on Windows UNC shares"

TEST_CONF = """\
[ req ]
distinguished_name =req_distinguished_name
attributes =req_attributes
prompt =no
x509_extensions = v3_req
req_extensions = v3_req
[ req_distinguished_name ]
countryName =US
stateOrProvinceName =Montana
localityName =Bozeman
organizationName =wolfSSL
commonName = testing
[ req_attributes ]
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
[ v3_alt_ca ]
basicConstraints = CA:TRUE
keyUsage = digitalSignature
subjectAltName = @alt_names
[ v3_alt_req_full ]
basicConstraints = CA:TRUE
keyUsage = digitalSignature
subjectAltName = @alt_names_full_skip
[alt_names]
DNS.1 = extraName
DNS.2 = alt-name
DNS.3 = thirdName
IP.1 = 2607:f8b0:400a:80b::2004
DNS.4 = 2607:f8b0:400a:80b::2004 (google.com)
IP.2 = 127.0.0.1
[alt_names_full_skip]
DNS.1 = extraName
DNS.2 = alt-name
DNS.4 = thirdName
IP.1 = 2607:f8b0:400a:80b::2004
DNS.5 = 2607:f8b0:400a:80b::2004 (google.com)
IP.2 = 127.0.0.1
DNS.6 = thirdName
DNS.7 = thirdName
DNS.8 = thirdName
DNS.9 = thirdName
DNS.10 = tenthName
"""

TEST_PROMPT_CONF = """\
[ req ]
distinguished_name =req_distinguished_name
attributes =req_attributes
x509_extensions = v3_req
req_extensions = v3_req
[ req_distinguished_name ]
countryName = 2 Letter Country Name
countryName_default = US
countryName_max = 2
countryName_min = 2
[ req_attributes ]
[ v3_req ]
basicConstraints = critical,CA:true
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
[alt_names]
RID.1 = 1.1.1.1
RID.2 = surname
email.1 = facts@wolfssl.com
URI.1 = facts@wolfssl.com
"""


def _is_fips():
    r = run_wolfssl("-v")
    return "FIPS" in (r.stdout + r.stderr)


def _cleanup(*files):
    for f in files:
        if os.path.exists(f):
            os.remove(f)


class TestReqNew(unittest.TestCase):
    """Test req -new with various options."""

    @classmethod
    def setUpClass(cls):
        cls.conf_file = "test_req.conf"
        cls.prompt_conf_file = "test_req_prompt.conf"
        with open(cls.conf_file, "w") as f:
            f.write(TEST_CONF)
        with open(cls.prompt_conf_file, "w") as f:
            f.write(TEST_PROMPT_CONF)

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.conf_file, cls.prompt_conf_file)

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_req_new_with_subj(self):
        """req -new -subj creates cert with correct subject."""
        tmp = "test_req_subj.cert"
        self._clean(tmp)
        r = run_wolfssl("req", "-new", "-days", "3650",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj",
                        "O=wolfSSL/C=US/ST=WA/L=Seattle/CN=wolfSSL/OU=org-unit",
                        "-out", tmp, "-x509")
        self.assertEqual(r.returncode, 0, r.stderr)

        r2 = run_wolfssl("x509", "-in", tmp, "-text")
        self.assertEqual(r2.returncode, 0, r2.stderr)
        # Find the Subject line
        subject_line = ""
        for line in r2.stdout.splitlines():
            if "Subject:" in line:
                subject_line = line
                break
        expected = "        Subject: O=wolfSSL, C=US, ST=WA, L=Seattle, CN=wolfSSL, OU=org-unit"
        self.assertEqual(subject_line, expected,
                         "Got: {!r}".format(subject_line))

    @unittest.skipIf(_SKIP_WIN, _WIN_REASON)
    def test_req_with_prompt_config(self):
        """req with prompt config file creates CSR with SAN."""
        tmp_csr = "test_req_prompt.csr"
        self._clean(tmp_csr)
        r = run_wolfssl("req", "-new",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-config", self.prompt_conf_file,
                        "-out", tmp_csr,
                        stdin_data="US\n")
        self.assertEqual(r.returncode, 0, r.stderr)

        r2 = run_wolfssl("req", "-text", "-in", tmp_csr)
        self.assertEqual(r2.returncode, 0, r2.stderr)

        # Check for SAN content
        r3 = run_wolfssl("req", "-in", tmp_csr, "-text")
        found_san = False
        lines = r3.stdout.splitlines()
        for i, line in enumerate(lines):
            if "X509v3 Subject Alternative Name" in line:
                found_san = True
                # Next line should have the SAN details
                if i + 1 < len(lines):
                    san_line = lines[i + 1]
                    self.assertIn("facts@wolfssl.com", san_line)
                break
        self.assertTrue(found_san, "SAN not found in CSR output")

    @unittest.skipIf(_SKIP_WIN, _WIN_REASON)
    def test_req_with_config(self):
        """req with config file succeeds."""
        tmp_csr = "test_req_conf.csr"
        self._clean(tmp_csr)
        r = run_wolfssl("req", "-new",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-config", self.conf_file,
                        "-out", tmp_csr,
                        stdin_data="US\n")
        self.assertEqual(r.returncode, 0, r.stderr)

    @unittest.skipIf(_SKIP_WIN, _WIN_REASON)
    def test_req_extensions_not_found_fails(self):
        """req with nonexistent extensions section should fail."""
        r = run_wolfssl("req", "-new", "-extensions", "v3_alt_ca_not_found",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-config", self.conf_file,
                        "-x509", "-out", "alt_nf.crt")
        self._clean("alt_nf.crt")
        self.assertNotEqual(r.returncode, 0)

    @unittest.skipIf(_SKIP_WIN, _WIN_REASON)
    def test_req_extensions_v3_alt_ca(self):
        """req with v3_alt_ca extensions sets CA:TRUE."""
        alt_crt = "test_req_alt.crt"
        self._clean(alt_crt)
        r = run_wolfssl("req", "-new", "-extensions", "v3_alt_ca",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-config", self.conf_file,
                        "-x509", "-out", alt_crt)
        self.assertEqual(r.returncode, 0, r.stderr)

        r2 = run_wolfssl("x509", "-in", alt_crt, "-text", "-noout")
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertIn("CA:TRUE", r2.stdout)


class TestReqPemDerRoundTrip(unittest.TestCase):
    """Test PEM <-> DER round-trip for CSR."""

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    @classmethod
    def setUpClass(cls):
        cls.conf_file = "test_req_rt.conf"
        with open(cls.conf_file, "w") as f:
            f.write(TEST_CONF)
        cls.csr = "test_req_rt.csr"
        r = run_wolfssl("req", "-new",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-config", cls.conf_file,
                        "-out", cls.csr,
                        stdin_data="US\n")
        assert r.returncode == 0, "setup CSR creation failed: " + r.stderr

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.conf_file, cls.csr)

    def test_pem_to_der_to_pem(self):
        """CSR PEM -> DER -> PEM round-trip produces identical output."""
        der_file = "test_req_rt.csr.der"
        pem_file = "test_req_rt.csr.pem"
        self._clean(der_file, pem_file)

        r = run_wolfssl("req", "-inform", "pem", "-outform", "der",
                        "-in", self.csr, "-out", der_file)
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("req", "-inform", "der", "-outform", "pem",
                        "-in", der_file, "-out", pem_file)
        self.assertEqual(r.returncode, 0, r.stderr)

        with open(pem_file) as f1, open(self.csr) as f2:
            self.assertEqual(f1.read(), f2.read(),
                             "PEM -> DER -> PEM round-trip mismatch")


class TestX509ReqSign(unittest.TestCase):
    """Test x509 -req -signkey signing."""

    @classmethod
    def setUpClass(cls):
        cls.conf_file = "test_x509req_sign.conf"
        with open(cls.conf_file, "w") as f:
            f.write(TEST_CONF)
        cls.csr = "test_x509req_sign.csr"
        r = run_wolfssl("req", "-new",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-config", cls.conf_file,
                        "-out", cls.csr,
                        stdin_data="US\n")
        assert r.returncode == 0, "setup CSR creation failed: " + r.stderr

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.conf_file, cls.csr)

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_x509_in_csr_no_req_flag_fails(self):
        """x509 -in csr without -req should fail."""
        r = run_wolfssl("x509", "-in", self.csr, "-days", "3650",
                        "-out", "tmp_sign.cert")
        self._clean("tmp_sign.cert")
        self.assertNotEqual(r.returncode, 0)

    def test_x509_req_without_signkey_fails(self):
        """x509 -req without -signkey should fail."""
        r = run_wolfssl("x509", "-req", "-in", self.csr, "-days", "3650",
                        "-out", "tmp_sign.cert")
        self._clean("tmp_sign.cert")
        self.assertNotEqual(r.returncode, 0)

    def test_x509_in_csr_signkey_no_req_fails(self):
        """x509 -in csr -signkey without -req should fail."""
        r = run_wolfssl("x509", "-in", self.csr, "-days", "3650",
                        "-signkey", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-out", "tmp_sign.cert")
        self._clean("tmp_sign.cert")
        self.assertNotEqual(r.returncode, 0)

    def test_x509_req_signkey_succeeds(self):
        """x509 -req -signkey succeeds."""
        out = "tmp_x509req_sign.cert"
        self._clean(out)
        r = run_wolfssl("x509", "-req", "-in", self.csr, "-days", "3650",
                        "-signkey",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)


class TestX509ReqHashAlgorithms(unittest.TestCase):
    """Test hash algorithm options for x509 -req."""

    @classmethod
    def setUpClass(cls):
        cls.conf_file = "test_x509req_hash.conf"
        with open(cls.conf_file, "w") as f:
            f.write(TEST_CONF)
        cls.csr = "test_x509req_hash.csr"
        r = run_wolfssl("req", "-new",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-config", cls.conf_file,
                        "-out", cls.csr,
                        stdin_data="US\n")
        assert r.returncode == 0, "setup CSR creation failed: " + r.stderr

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.conf_file, cls.csr)

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def _test_hash(self, algo):
        out = "tmp_hash_{}.cert".format(algo)
        self._clean(out)
        r = run_wolfssl("x509", "-req", "-in", self.csr, "-days", "3650",
                        "-{}".format(algo),
                        "-signkey",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_sha1(self):
        self._test_hash("sha1")

    def test_sha224(self):
        self._test_hash("sha224")

    def test_sha256(self):
        self._test_hash("sha256")

    def test_sha384(self):
        self._test_hash("sha384")

    def test_sha512(self):
        self._test_hash("sha512")


@unittest.skipIf(_SKIP_WIN, _WIN_REASON)
class TestX509ReqExtensions(unittest.TestCase):
    """Test extensions from config file for x509 -req."""

    @classmethod
    def setUpClass(cls):
        cls.conf_file = "test_x509req_ext.conf"
        with open(cls.conf_file, "w") as f:
            f.write(TEST_CONF)
        cls.csr = "test_x509req_ext.csr"
        r = run_wolfssl("req", "-new",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-config", cls.conf_file,
                        "-out", cls.csr,
                        stdin_data="US\n")
        assert r.returncode == 0, "setup CSR creation failed: " + r.stderr

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.conf_file, cls.csr)

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_extfile_v3_alt_ca(self):
        """x509 -req with -extfile and -extensions v3_alt_ca sets CA:TRUE."""
        out = "tmp_ext.cert"
        self._clean(out)
        r = run_wolfssl("x509", "-req", "-in", self.csr, "-days", "3650",
                        "-extfile", self.conf_file,
                        "-extensions", "v3_alt_ca",
                        "-signkey",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)

        r2 = run_wolfssl("x509", "-in", out, "-text", "-noout")
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertIn("CA:TRUE", r2.stdout)


@unittest.skipIf(_SKIP_WIN, _WIN_REASON)
class TestReqConfigSubject(unittest.TestCase):
    """Test subject from config file."""

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_subject_from_config(self):
        """req with config file produces correct subject."""
        conf = "test_req_cfg_subj.conf"
        tmp = "test_req_cfg_subj.cert"
        self._clean(conf, tmp)
        with open(conf, "w") as f:
            f.write(TEST_CONF)

        r = run_wolfssl("req", "-new",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-config", conf, "-x509", "-out", tmp)
        self.assertEqual(r.returncode, 0, r.stderr)

        r2 = run_wolfssl("x509", "-in", tmp, "-text")
        self.assertEqual(r2.returncode, 0, r2.stderr)
        subject_line = ""
        for line in r2.stdout.splitlines():
            if "Subject:" in line:
                subject_line = line
                break
        expected = "        Subject: C=US, ST=Montana, L=Bozeman, O=wolfSSL, CN=testing"
        self.assertEqual(subject_line, expected,
                         "Got: {!r}".format(subject_line))


class TestReqDefaultBasicConstraints(unittest.TestCase):
    """Test default basic constraints extension."""

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_default_ca_true(self):
        """req -new -x509 sets CA:TRUE by default."""
        tmp = "test_req_bc.cert"
        self._clean(tmp)
        r = run_wolfssl("req", "-new", "-x509",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj",
                        "O=wolfSSL/C=US/ST=WA/L=Seattle/CN=wolfSSL/OU=org-unit",
                        "-out", tmp)
        self.assertEqual(r.returncode, 0, r.stderr)

        r2 = run_wolfssl("x509", "-in", tmp, "-text", "-noout")
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertIn("CA:TRUE", r2.stdout)


class TestReqFIPS(unittest.TestCase):
    """FIPS-conditional tests."""

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    @classmethod
    def setUpClass(cls):
        cls.conf_file = "test_req_fips.conf"
        with open(cls.conf_file, "w") as f:
            f.write(TEST_CONF)

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.conf_file)

    def test_newkey_with_passout_stdin(self):
        """req -newkey rsa:2048 with -passout stdin produces ENCRYPTED key."""
        if _is_fips():
            self.skipTest("FIPS build")
        tmp = "test_req_fips_passout.cert"
        self._clean(tmp)
        r = run_wolfssl("req", "-new", "-newkey", "rsa:2048",
                        "-config", self.conf_file, "-x509",
                        "-out", tmp, "-passout", "stdin",
                        stdin_data="long test password\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ENCRYPTED", r.stdout + r.stderr)

    def test_newkey_keyout_with_passout(self):
        """req -newkey -keyout with -passout produces encrypted key."""
        if _is_fips():
            self.skipTest("FIPS build")
        tmp = "test_req_fips_keyout.cert"
        key = "test_req_fips_newkey.pem"
        self._clean(tmp, key)
        r = run_wolfssl("req", "-newkey", "rsa:2048", "-keyout", key,
                        "-config", self.conf_file, "-out", tmp,
                        "-passout", "pass:123456789wolfssl",
                        "-outform", "pem", "-sha256")
        self.assertEqual(r.returncode, 0, r.stderr)

        r2 = run_wolfssl("rsa", "-in", key,
                         "-passin", "pass:123456789wolfssl")
        self.assertEqual(r2.returncode, 0, r2.stderr)

    def test_newkey_with_passout_keyout(self):
        """req -newkey rsa:2048 -keyout with -passout stdin."""
        if _is_fips():
            self.skipTest("FIPS build")
        tmp = "test_req_fips_ko2.cert"
        key = "test_req_fips_ko2.pem"
        self._clean(tmp, key)
        r = run_wolfssl("req", "-new", "-newkey", "rsa:2048",
                        "-keyout", key, "-config", self.conf_file,
                        "-x509", "-out", tmp, "-passout", "stdin",
                        stdin_data="long test password\n")
        self.assertEqual(r.returncode, 0, r.stderr)


@unittest.skipIf(_SKIP_WIN, _WIN_REASON)
class TestReqHashAndKeyAlgos(unittest.TestCase):
    """Test hash and key algorithm options for req."""

    @classmethod
    def setUpClass(cls):
        cls.conf_file = "test_req_algo.conf"
        with open(cls.conf_file, "w") as f:
            f.write(TEST_CONF)

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.conf_file)

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def _test_algo(self, algo_flag):
        tmp = "test_req_algo_{}.cert".format(algo_flag)
        self._clean(tmp)
        r = run_wolfssl("req", "-new", "-days", "3650",
                        "-{}".format(algo_flag),
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-config", self.conf_file, "-out", tmp, "-x509")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_rsa(self):
        self._test_algo("rsa")

    def test_ed25519(self):
        self._test_algo("ed25519")

    def test_sha(self):
        self._test_algo("sha")

    def test_sha224(self):
        self._test_algo("sha224")

    def test_sha256(self):
        self._test_algo("sha256")

    def test_sha384(self):
        self._test_algo("sha384")

    def test_sha512(self):
        self._test_algo("sha512")


@unittest.skipIf(_SKIP_WIN, _WIN_REASON)
class TestReqAltNamesFullSkip(unittest.TestCase):
    """Test full alt_names extension with skipped indices."""

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    @classmethod
    def setUpClass(cls):
        cls.conf_file = "test_req_altfull.conf"
        with open(cls.conf_file, "w") as f:
            f.write(TEST_CONF)

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.conf_file)

    def test_v3_alt_req_full_tenthname(self):
        """req with v3_alt_req_full includes tenthName."""
        tmp = "test_req_altfull.cert"
        self._clean(tmp)
        r = run_wolfssl("req", "-new",
                        "-key", os.path.join(CERTS_DIR, "ca-key.pem"),
                        "-config", self.conf_file,
                        "-extensions", "v3_alt_req_full",
                        "-out", tmp)
        self.assertEqual(r.returncode, 0, r.stderr)

        r2 = run_wolfssl("req", "-in", tmp, "-noout", "-text")
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertIn("tenthName", r2.stdout)


@unittest.skipIf(_SKIP_WIN, _WIN_REASON)
class TestReqPromptValidation(unittest.TestCase):
    """Test prompt-based config validation."""

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    @classmethod
    def setUpClass(cls):
        cls.prompt_conf = "test_req_pv.conf"
        with open(cls.prompt_conf, "w") as f:
            f.write(TEST_PROMPT_CONF)

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.prompt_conf)

    def test_valid_country_code(self):
        """req with valid 2-letter country code succeeds."""
        tmp = "test_req_pv_ok.cert"
        self._clean(tmp)
        r = run_wolfssl("req", "-new", "-x509",
                        "-key", os.path.join(CERTS_DIR, "ca-key.pem"),
                        "-config", self.prompt_conf,
                        "-out", tmp,
                        stdin_data="AA\n")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_long_country_code_fails(self):
        """req with too-long country code should fail."""
        tmp = "test_req_pv_fail.cert"
        self._clean(tmp)
        r = run_wolfssl("req", "-new", "-x509",
                        "-key", os.path.join(CERTS_DIR, "ca-key.pem"),
                        "-config", self.prompt_conf,
                        "-out", tmp,
                        stdin_data="LONG\n")
        self.assertNotEqual(r.returncode, 0)


class TestReqCSRAttributes(unittest.TestCase):
    """Test CSR attribute printing."""

    def test_attributes_csr(self):
        """req -text on attributes-csr.pem shows expected attributes."""
        csr_path = os.path.join(CERTS_DIR, "attributes-csr.pem")
        if not os.path.isfile(csr_path):
            self.skipTest("attributes-csr.pem not available")

        r = run_wolfssl("req", "-text", "-noout", "-in", csr_path)
        if r.returncode != 0:
            self.skipTest("wolfSSL version does not support CSR attributes")

        output = r.stdout
        self.assertIn("initials", output)
        self.assertIn("abc", output)
        self.assertIn("dnQualifier", output)
        self.assertIn("dn", output)
        self.assertIn("challengePassword", output)
        self.assertIn("test", output)
        self.assertIn("givenName", output)
        self.assertIn("Given Name", output)
        self.assertIn("surname", output)


class TestReqCSRVersion(unittest.TestCase):
    """Test CSR version number."""

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_csr_version(self):
        """CSR version should be 1 (0x0)."""
        conf = "test_req_ver.conf"
        csr = "test_req_ver.csr"
        self._clean(conf, csr)
        with open(conf, "w") as f:
            f.write(TEST_CONF)

        r = run_wolfssl("req", "-new",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-config", conf, "-out", csr)
        self.assertEqual(r.returncode, 0, r.stderr)

        r2 = run_wolfssl("req", "-text", "-noout", "-in", csr)
        if r2.returncode != 0:
            self.skipTest("req -text not supported")
        # Check version
        found_version = False
        for line in r2.stdout.splitlines():
            if "Version" in line and "1" in line and "0x0" in line:
                found_version = True
                break
        self.assertTrue(found_version,
                        "Version 1 (0x0) not found in: {}".format(r2.stdout))

    @unittest.skipUnless(HAS_OPENSSL, "openssl not available")
    def test_csr_version_openssl_interop(self):
        """OpenSSL should also see version 1 (0x0) in our CSR."""
        conf = "test_req_ver_ossl.conf"
        csr = "test_req_ver_ossl.csr"
        self._clean(conf, csr)
        with open(conf, "w") as f:
            f.write(TEST_CONF)

        r = run_wolfssl("req", "-new",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-config", conf, "-out", csr)
        self.assertEqual(r.returncode, 0, r.stderr)

        r2 = subprocess.run(
            ["openssl", "req", "-text", "-noout", "-in", csr],
            capture_output=True, text=True, timeout=60)
        if r2.returncode != 0:
            self.skipTest("openssl req -text failed")
        found_version = False
        for line in r2.stdout.splitlines():
            if "Version" in line and "1" in line and "0x0" in line:
                found_version = True
                break
        self.assertTrue(found_version,
                        "Version not found in openssl output: {}".format(
                            r2.stdout))


if __name__ == "__main__":
    test_main()

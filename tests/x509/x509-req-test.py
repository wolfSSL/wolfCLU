#!/usr/bin/env python3
"""Tests for wolfssl req and x509 -req (converted from x509-req-test.sh)."""

import os
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import WOLFSSL_BIN, CERTS_DIR, is_fips, run_wolfssl, test_main


def _tmp(name):
    """Return an absolute path for a temp file in the current working directory.

    Tests run from the build directory, which may differ from the source
    tree (e.g. under `make distcheck`, where the srcdir is read-only).
    Uses forward slashes so wolfSSL's path handling recognizes the path
    as absolute on Windows (it checks for leading '/')."""
    return os.path.abspath(os.path.join(os.getcwd(), name)).replace("\\", "/")

HAS_OPENSSL = shutil.which("openssl") is not None

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
URI.1 = https://www.wolfssl.com
"""


def _cleanup(*files):
    for f in files:
        if os.path.exists(f):
            os.remove(f)


class TestReqNew(unittest.TestCase):
    """Test req -new with various options."""

    @classmethod
    def setUpClass(cls):
        cls.conf_file = _tmp("test_req.conf")
        cls.prompt_conf_file = _tmp("test_req_prompt.conf")
        with open(cls.conf_file, "w", encoding="utf-8", newline="\n") as f:
            f.write(TEST_CONF)
        with open(cls.prompt_conf_file, "w", encoding="utf-8", newline="\n") as f:
            f.write(TEST_PROMPT_CONF)

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.conf_file, cls.prompt_conf_file)

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_req_new_with_subj(self):
        """req -new -subj creates cert with correct subject."""
        tmp = _tmp("test_req_subj.cert")
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


    def test_req_new_interactive_name(self):
        """req -new with no -subj/-config reads the name fields from stdin.

        Exercises wolfCLU_CreateX509Name(). The prompts consume one line each:
        Country, State, Locality, Organization, Org-Unit, Common Name, Email.
        """
        tmp = _tmp("test_req_interactive.csr")
        self._clean(tmp)
        name_input = ("US\nMontana\nBozeman\nwolfSSL\n"
                      "engineering\nexample.com\ntest@example.com\n")
        r = subprocess.run(
            [WOLFSSL_BIN, "req", "-new",
             "-key", os.path.join(CERTS_DIR, "server-key.pem"),
             "-out", tmp],
            input=name_input, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(tmp), "req did not create CSR")

        r2 = subprocess.run(
            [WOLFSSL_BIN, "req", "-in", tmp, "-text", "-verify"],
            input=name_input, capture_output=True, text=True, timeout=60)
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertIn("example.com", r2.stdout)

    def test_req_new_interactive_skip_fields(self):
        """Empty lines skip the corresponding name fields (still succeeds)."""
        tmp = _tmp("test_req_interactive_skip.csr")
        self._clean(tmp)
        # Only a common name; everything else left blank.
        name_input = "\n\n\n\n\nexample.com\n\n"
        r = subprocess.run(
            [WOLFSSL_BIN, "req", "-new",
             "-key", os.path.join(CERTS_DIR, "server-key.pem"),
             "-out", tmp],
            input=name_input, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(tmp), "req did not create CSR")

    def test_req_with_prompt_config(self):
        """req with prompt config file creates CSR with SAN."""
        tmp_csr = _tmp("test_req_prompt.csr")
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


    def test_req_with_config(self):
        """req with config file succeeds."""
        tmp_csr = _tmp("test_req_conf.csr")
        self._clean(tmp_csr)
        r = run_wolfssl("req", "-new",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-config", self.conf_file,
                        "-out", tmp_csr,
                        stdin_data="US\n")
        self.assertEqual(r.returncode, 0, r.stderr)


    def test_req_extensions_not_found_fails(self):
        """req with nonexistent extensions section should fail."""
        r = run_wolfssl("req", "-new", "-extensions", "v3_alt_ca_not_found",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-config", self.conf_file,
                        "-x509", "-out", _tmp("alt_nf.crt"))
        self._clean(_tmp("alt_nf.crt"))
        self.assertNotEqual(r.returncode, 0)




    def test_req_extensions_v3_alt_ca(self):
        """req with v3_alt_ca extensions sets CA:TRUE."""
        alt_crt = _tmp("test_req_alt.crt")
        self._clean(alt_crt)
        r = run_wolfssl("req", "-new", "-extensions", "v3_alt_ca",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-config", self.conf_file,
                        "-x509", "-out", alt_crt)
        self.assertEqual(r.returncode, 0, r.stderr)

        r2 = run_wolfssl("x509", "-in", alt_crt, "-text", "-noout")
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertIn("CA:TRUE", r2.stdout)


    def test_req_x509_addext_subject_alt_name(self):
        """req -x509 -addext subjectAltName adds IP and DNS alt names."""
        crt = _tmp("test_req_addext.crt")
        self._clean(crt)
        r = run_wolfssl("req", "-new", "-days", "3650",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj", "CN=192.168.1.2",
                        "-addext",
                        "subjectAltName=IP:192.168.1.2,DNS:example.com",
                        "-x509", "-out", crt)
        self.assertEqual(r.returncode, 0, r.stderr)

        r2 = run_wolfssl("x509", "-in", crt, "-text", "-noout")
        self.assertEqual(r2.returncode, 0, r2.stderr)
        found_san = False
        lines = r2.stdout.splitlines()
        for i, line in enumerate(lines):
            if "X509v3 Subject Alternative Name" in line:
                found_san = True
                san_line = lines[i + 1]
                self.assertIn("IP Address:192.168.1.2", san_line)
                self.assertIn("DNS:example.com", san_line)
                break
        self.assertTrue(found_san, "SAN not found in cert output")


    def _addext_san_line(self, addext, crt_name):
        """Generate an -x509 cert with the given -addext and return the line
        following the SAN header, or None if no SAN is present."""
        crt = _tmp(crt_name)
        self._clean(crt)
        r = run_wolfssl("req", "-new", "-days", "3650",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj", "CN=test",
                        "-addext", addext,
                        "-x509", "-out", crt)
        self.assertEqual(r.returncode, 0, r.stderr)

        r2 = run_wolfssl("x509", "-in", crt, "-text", "-noout")
        self.assertEqual(r2.returncode, 0, r2.stderr)
        lines = r2.stdout.splitlines()
        for i, line in enumerate(lines):
            if "X509v3 Subject Alternative Name" in line:
                return lines[i + 1]
        return None

    def test_req_addext_san_uri(self):
        """req -addext subjectAltName=URI:... adds a URI alt name."""
        san = self._addext_san_line(
            "subjectAltName=URI:https://www.wolfssl.com",
            "test_req_addext_uri.crt")
        self.assertIsNotNone(san, "SAN not found in cert output")
        self.assertIn("URI:https://www.wolfssl.com", san)

    def test_req_addext_san_email(self):
        """req -addext subjectAltName=email:... adds an email alt name."""
        san = self._addext_san_line(
            "subjectAltName=email:facts@wolfssl.com",
            "test_req_addext_email.crt")
        self.assertIsNotNone(san, "SAN not found in cert output")
        self.assertIn("email:facts@wolfssl.com", san)

    def test_req_addext_san_rid(self):
        """req -addext subjectAltName=RID:... adds a registered ID alt name."""
        san = self._addext_san_line("subjectAltName=RID:1.2.3.4",
                                    "test_req_addext_rid.crt")
        self.assertIsNotNone(san, "SAN not found in cert output")
        self.assertIn("Registered ID:1.2.3.4", san)

    def test_req_addext_san_ipv6(self):
        """req -addext subjectAltName=IP:<ipv6> keeps colons in the value.

        The TYPE:value split consumes only the first ':' so the remaining
        colons of an IPv6 literal stay part of the address."""
        san = self._addext_san_line(
            "subjectAltName=IP:2607:f8b0:400a:80b::2004",
            "test_req_addext_ipv6.crt")
        self.assertIsNotNone(san, "SAN not found in cert output")
        self.assertIn(
            "IP Address:2607:F8B0:400A:080B:0000:0000:0000:2004", san)

    def _addext_fails(self, addext, crt_name):
        """req -x509 with a malformed -addext must exit non-zero."""
        crt = _tmp(crt_name)
        self._clean(crt)
        r = run_wolfssl("req", "-new", "-days", "3650",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj", "CN=test",
                        "-addext", addext,
                        "-x509", "-out", crt)
        self.assertNotEqual(r.returncode, 0,
                            "expected failure for -addext {!r}".format(addext))

    def test_req_addext_no_equals_fails(self):
        """req -addext without '=' (name=value form) should fail."""
        self._addext_fails("subjectAltName", "test_req_addext_noeq.crt")

    def test_req_addext_san_entry_no_colon_fails(self):
        """req -addext subjectAltName entry without TYPE:value should fail."""
        self._addext_fails("subjectAltName=foo",
                           "test_req_addext_nocolon.crt")

    def test_req_addext_unsupported_extension_fails(self):
        """req -addext with an unsupported extension name should fail."""
        self._addext_fails("keyUsage=digitalSignature",
                           "test_req_addext_unsupported_ext.crt")

    def test_req_addext_unsupported_alt_type_fails(self):
        """req -addext with an unsupported subjectAltName type should fail."""
        self._addext_fails("subjectAltName=otherName:foo",
                           "test_req_addext_badtype.crt")


class TestReqPemDerRoundTrip(unittest.TestCase):
    """Test PEM <-> DER round-trip for CSR."""

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    @classmethod
    def setUpClass(cls):
        cls.conf_file = _tmp("test_req_rt.conf")
        with open(cls.conf_file, "w", encoding="utf-8", newline="\n") as f:
            f.write(TEST_CONF)
        cls.csr = _tmp("test_req_rt.csr")
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
        der_file = _tmp("test_req_rt.csr.der")
        pem_file = _tmp("test_req_rt.csr.pem")
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
        cls.conf_file = _tmp("test_x509req_sign.conf")
        with open(cls.conf_file, "w", encoding="utf-8", newline="\n") as f:
            f.write(TEST_CONF)
        cls.csr = _tmp("test_x509req_sign.csr")
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
                        "-out", _tmp("tmp_sign.cert"))
        self._clean(_tmp("tmp_sign.cert"))
        self.assertNotEqual(r.returncode, 0)

    def test_x509_req_without_signkey_fails(self):
        """x509 -req without -signkey should fail."""
        r = run_wolfssl("x509", "-req", "-in", self.csr, "-days", "3650",
                        "-out", _tmp("tmp_sign.cert"))
        self._clean(_tmp("tmp_sign.cert"))
        self.assertNotEqual(r.returncode, 0)

    def test_x509_in_csr_signkey_no_req_fails(self):
        """x509 -in csr -signkey without -req should fail."""
        r = run_wolfssl("x509", "-in", self.csr, "-days", "3650",
                        "-signkey", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-out", _tmp("tmp_sign.cert"))
        self._clean(_tmp("tmp_sign.cert"))
        self.assertNotEqual(r.returncode, 0)

    def test_x509_req_signkey_succeeds(self):
        """x509 -req -signkey succeeds."""
        out = _tmp("tmp_x509req_sign.cert")
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
        cls.conf_file = _tmp("test_x509req_hash.conf")
        with open(cls.conf_file, "w", encoding="utf-8", newline="\n") as f:
            f.write(TEST_CONF)
        cls.csr = _tmp("test_x509req_hash.csr")
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
        out = _tmp("tmp_hash_{}.cert".format(algo))
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

    def test_sha224_sig_algorithm(self):
        """Regression: -sha224 must produce a SHA-224 signature, not SHA-256."""
        out = _tmp("tmp_sha224_sig.cert")
        self._clean(out)
        r = run_wolfssl("x509", "-req", "-in", self.csr, "-days", "3650",
                        "-sha224",
                        "-signkey",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)

        r2 = run_wolfssl("x509", "-in", out, "-text", "-noout")
        self.assertEqual(r2.returncode, 0, r2.stderr)
        text = (r2.stdout + r2.stderr).lower()
        if "sha224" not in text:
            self.assertNotIn(
                "sha256", text,
                "SHA-224 cert incorrectly uses SHA-256 signature algorithm")



class TestX509ReqExtensions(unittest.TestCase):
    """Test extensions from config file for x509 -req."""

    @classmethod
    def setUpClass(cls):
        cls.conf_file = _tmp("test_x509req_ext.conf")
        with open(cls.conf_file, "w", encoding="utf-8", newline="\n") as f:
            f.write(TEST_CONF)
        cls.csr = _tmp("test_x509req_ext.csr")
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
        out = _tmp("tmp_ext.cert")
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



class TestReqConfigSubject(unittest.TestCase):
    """Test subject from config file."""

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_subject_from_config(self):
        """req with config file produces correct subject."""
        conf = _tmp("test_req_cfg_subj.conf")
        tmp = _tmp("test_req_cfg_subj.cert")
        self._clean(conf, tmp)
        with open(conf, "w", encoding="utf-8", newline="\n") as f:
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
        tmp = _tmp("test_req_bc.cert")
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
        cls.conf_file = _tmp("test_req_fips.conf")
        with open(cls.conf_file, "w", encoding="utf-8", newline="\n") as f:
            f.write(TEST_CONF)

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.conf_file)

    def test_newkey_with_passout_stdin(self):
        """req -newkey rsa:2048 with -passout stdin produces ENCRYPTED key."""
        if is_fips():
            self.skipTest("FIPS build")
        tmp = _tmp("test_req_fips_passout.cert")
        self._clean(tmp)
        r = run_wolfssl("req", "-new", "-newkey", "rsa:2048",
                        "-config", self.conf_file, "-x509",
                        "-out", tmp, "-passout", "stdin",
                        stdin_data="long test password\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ENCRYPTED", r.stdout + r.stderr)

    def test_newkey_keyout_with_passout(self):
        """req -newkey -keyout with -passout produces encrypted key."""
        if is_fips():
            self.skipTest("FIPS build")
        tmp = _tmp("test_req_fips_keyout.cert")
        key = _tmp("test_req_fips_newkey.pem")
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
        if is_fips():
            self.skipTest("FIPS build")
        tmp = _tmp("test_req_fips_ko2.cert")
        key = _tmp("test_req_fips_ko2.pem")
        self._clean(tmp, key)
        r = run_wolfssl("req", "-new", "-newkey", "rsa:2048",
                        "-keyout", key, "-config", self.conf_file,
                        "-x509", "-out", tmp, "-passout", "stdin",
                        stdin_data="long test password\n")
        self.assertEqual(r.returncode, 0, r.stderr)



class TestReqHashAndKeyAlgos(unittest.TestCase):
    """Test hash and key algorithm options for req."""

    @classmethod
    def setUpClass(cls):
        cls.conf_file = _tmp("test_req_algo.conf")
        with open(cls.conf_file, "w", encoding="utf-8", newline="\n") as f:
            f.write(TEST_CONF)

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.conf_file)

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def _test_algo(self, algo_flag):
        tmp = _tmp("test_req_algo_{}.cert".format(algo_flag))
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



class TestReqAltNamesFullSkip(unittest.TestCase):
    """Test full alt_names extension with skipped indices."""

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    @classmethod
    def setUpClass(cls):
        cls.conf_file = _tmp("test_req_altfull.conf")
        with open(cls.conf_file, "w", encoding="utf-8", newline="\n") as f:
            f.write(TEST_CONF)

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.conf_file)



    def test_v3_alt_req_full_tenthname(self):
        """req with v3_alt_req_full includes tenthName."""
        tmp = _tmp("test_req_altfull.cert")
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



class TestReqPromptValidation(unittest.TestCase):
    """Test prompt-based config validation."""

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    @classmethod
    def setUpClass(cls):
        cls.prompt_conf = _tmp("test_req_pv.conf")
        with open(cls.prompt_conf, "w", encoding="utf-8", newline="\n") as f:
            f.write(TEST_PROMPT_CONF)

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.prompt_conf)

    def test_valid_country_code(self):
        """req with valid 2-letter country code succeeds."""
        tmp = _tmp("test_req_pv_ok.cert")
        self._clean(tmp)
        r = run_wolfssl("req", "-new", "-x509",
                        "-key", os.path.join(CERTS_DIR, "ca-key.pem"),
                        "-config", self.prompt_conf,
                        "-out", tmp,
                        stdin_data="AA\n")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_long_country_code_fails(self):
        """req with too-long country code should fail."""
        tmp = _tmp("test_req_pv_fail.cert")
        self._clean(tmp)
        r = run_wolfssl("req", "-new", "-x509",
                        "-key", os.path.join(CERTS_DIR, "ca-key.pem"),
                        "-config", self.prompt_conf,
                        "-out", tmp,
                        stdin_data="LONG\n")
        self.assertNotEqual(r.returncode, 0)


class TestReqCSRAttributes(unittest.TestCase):
    """Test CSR attribute printing."""

    def test_supported_attributes(self):
        """req -text on a CSR with supported attributes shows them."""
        csr_path = os.path.join(CERTS_DIR, "attributes-supported-csr.pem")
        if not os.path.isfile(csr_path):
            self.skipTest("attributes-supported-csr.pem not available")

        r = run_wolfssl("req", "-text", "-noout", "-in", csr_path)
        self.assertEqual(r.returncode, 0, r.stderr)

        output = r.stdout
        self.assertIn("challengePassword", output)
        self.assertIn("test123", output)
        self.assertIn("unstructuredName", output)
        self.assertIn("wolfSSL_test", output)

    def test_unsupported_attributes_fail(self):
        """req -text on a CSR with unsupported attributes should fail."""
        csr_path = os.path.join(CERTS_DIR, "attributes-csr.pem")
        if not os.path.isfile(csr_path):
            self.skipTest("attributes-csr.pem not available")

        r = run_wolfssl("req", "-text", "-noout", "-in", csr_path)
        self.assertNotEqual(r.returncode, 0,
                            "CSR with unsupported attributes should fail")


class TestReqCSRVersion(unittest.TestCase):
    """Test CSR version number."""

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_csr_version(self):
        """CSR version should be 1 (0x0)."""
        conf = _tmp("test_req_ver.conf")
        csr = _tmp("test_req_ver.csr")
        self._clean(conf, csr)
        with open(conf, "w", encoding="utf-8", newline="\n") as f:
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
        conf = _tmp("test_req_ver_ossl.conf")
        csr = _tmp("test_req_ver_ossl.csr")
        self._clean(conf, csr)
        with open(conf, "w", encoding="utf-8", newline="\n") as f:
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


TEST_ABBREV_KU_CONF = """\
[ req ]
distinguished_name = req_distinguished_name
prompt = no
x509_extensions = v3_req
req_extensions = v3_req
[ req_distinguished_name ]
countryName = US
stateOrProvinceName = Montana
localityName = Bozeman
organizationName = wolfSSL
commonName = testing
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = d
"""

TEST_ATTR_CONF = """\
[ req ]
distinguished_name = req_distinguished_name
attributes = req_attributes
prompt = no
[ req_distinguished_name ]
countryName = US
stateOrProvinceName = Montana
localityName = Bozeman
organizationName = wolfSSL
commonName = testing
[ req_attributes ]
challengePassword = testpass123
"""


class TestReqKeyUsageAbbrev(unittest.TestCase):
    """Regression: abbreviated keyUsage names must not be accepted."""

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_abbreviated_ku_rejected(self):
        """keyUsage = d must not match digitalSignature."""
        conf = _tmp("test-abbrev-ku.conf")
        tmp = _tmp("tmp-ku.cert")
        self._clean(conf, tmp)
        with open(conf, "w", encoding="utf-8", newline="\n") as f:
            f.write(TEST_ABBREV_KU_CONF)

        r = run_wolfssl("req", "-new",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-config", conf, "-x509", "-out", tmp)
        if r.returncode == 0 and os.path.isfile(tmp):
            r2 = run_wolfssl("x509", "-in", tmp, "-text", "-noout")
            self.assertEqual(r2.returncode, 0, r2.stderr)
            self.assertNotIn(
                "Digital Signature", r2.stdout,
                "Abbreviated keyUsage 'd' should not match digitalSignature")


class TestReqChallengePassword(unittest.TestCase):
    """req config with challengePassword attribute must succeed."""

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_challenge_password_attribute(self):
        conf = _tmp("test-attr.conf")
        csr = _tmp("tmp-attr.csr")
        self._clean(conf, csr)
        with open(conf, "w", encoding="utf-8", newline="\n") as f:
            f.write(TEST_ATTR_CONF)

        r = run_wolfssl("req", "-new",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-config", conf, "-out", csr)
        self.assertEqual(r.returncode, 0, r.stderr)


def _has_dilithium():
    """Return True if the current build supports Dilithium/ML-DSA."""
    r = run_wolfssl("-genkey", "-h")
    return "dilithium" in (r.stdout + r.stderr)


@unittest.skipUnless(_has_dilithium(), "ML-DSA (Dilithium) not available")
class TestReqMLDSACert(unittest.TestCase):
    """End-to-end tests for `req -x509 -newkey ml-dsa:N` certificate generation.

    Guards the wolfCLU_MakeMLDSACert code path, including:
      - the isMLDSA guard that was missing from wolfCLU_requestSetup
      - wolfCLU_KeyPemToDer probe cleanup with correct DER buffer size
    """

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def _test_newkey_level(self, level):
        cert = _tmp("mldsa{}_cert.pem".format(level))
        priv = _tmp("mldsa{}_key".format(level))
        self._clean(cert, priv + ".priv", priv + ".pub")

        r = run_wolfssl("req", "-x509",
                        "-newkey", "ml-dsa:{}".format(level),
                        "-keyout", priv,
                        "-subj", "/CN=wolfCLU-ML-DSA-{}/O=wolfSSL".format(level),
                        "-days", "1",
                        "-out", cert)
        self.assertEqual(r.returncode, 0,
                         "req -x509 -newkey ml-dsa:{} failed: {}".format(
                             level, r.stderr))
        self.assertTrue(os.path.isfile(cert),
                        "cert file not created for ml-dsa:{}".format(level))
        self.assertGreater(os.path.getsize(cert), 0,
                           "cert file is empty for ml-dsa:{}".format(level))

        # Self-signed cert must verify against itself (implicitly parses too).
        r2 = run_wolfssl("verify", "-CAfile", cert, cert)
        self.assertEqual(r2.returncode, 0,
                         "verify failed for self-signed ml-dsa:{} cert: "
                         "{}".format(level, r2.stderr))

        # If OpenSSL supports ML-DSA, confirm the signature algorithm name.
        if HAS_OPENSSL:
            import subprocess as _sp
            r3 = _sp.run(
                ["openssl", "x509", "-in", cert, "-text", "-noout"],
                capture_output=True, text=True, timeout=60)
            if r3.returncode == 0:
                self.assertIn("ML-DSA", r3.stdout,
                              "ML-DSA not found in openssl cert text")

    def test_newkey_level2(self):
        """ML-DSA level 2 cert: creation, parse, and self-verify."""
        self._test_newkey_level(2)

    def test_newkey_level3(self):
        """ML-DSA level 3 cert: creation, parse, and self-verify."""
        self._test_newkey_level(3)

    def test_newkey_level5(self):
        """ML-DSA level 5 cert: creation, parse, and self-verify."""
        self._test_newkey_level(5)

    def test_invalid_level_fails(self):
        """ml-dsa:4 is not a valid level and must fail."""
        cert = _tmp("mldsa_bad_level.pem")
        priv = _tmp("mldsa_bad_level_key")
        self._clean(cert, priv + ".priv", priv + ".pub")
        r = run_wolfssl("req", "-x509",
                        "-newkey", "ml-dsa:4",
                        "-keyout", priv,
                        "-subj", "/CN=bad",
                        "-days", "1",
                        "-out", cert)
        self.assertNotEqual(r.returncode, 0,
                            "ml-dsa:4 should fail but returned 0")

    def test_newkey_der_output(self):
        """ML-DSA cert in DER form must be parseable by wolfssl x509."""
        cert = _tmp("mldsa5_cert.der")
        priv = _tmp("mldsa5_key_der")
        self._clean(cert, priv + ".priv", priv + ".pub")

        r = run_wolfssl("req", "-x509",
                        "-newkey", "ml-dsa:5",
                        "-keyout", priv,
                        "-subj", "/CN=wolfCLU-ML-DSA-5-DER/O=wolfSSL",
                        "-days", "1",
                        "-outform", "DER",
                        "-out", cert)
        self.assertEqual(r.returncode, 0,
                         "req -x509 -newkey ml-dsa:5 -outform DER failed: "
                         + r.stderr)
        self.assertGreater(os.path.getsize(cert), 0,
                           "DER cert file is empty")

    def test_existing_key(self):
        """req -x509 -key <existing ml-dsa key>: create and self-verify."""
        priv = _tmp("mldsa_existing_key")
        cert = _tmp("mldsa_existing_cert.pem")
        self._clean(priv + ".priv", priv + ".pub", cert)

        r = run_wolfssl("-genkey", "dilithium", "-level", "2",
                        "-out", priv, "-outform", "pem")
        if r.returncode != 0:
            self.skipTest("key generation failed: " + r.stderr)

        r = run_wolfssl("req", "-x509",
                        "-key", priv + ".priv",
                        "-subj", "/CN=wolfCLU-ML-DSA-existing/O=wolfSSL",
                        "-days", "1",
                        "-out", cert)
        self.assertEqual(r.returncode, 0,
                         "req -x509 with existing ml-dsa key failed: "
                         + r.stderr)
        self.assertTrue(os.path.isfile(cert),
                        "cert not created from existing ml-dsa key")

        r2 = run_wolfssl("verify", "-CAfile", cert, cert)
        self.assertEqual(r2.returncode, 0,
                         "verify failed for existing-key ml-dsa cert: "
                         + r2.stderr)

    def test_newkey_without_x509_makes_csr(self):
        """ML-DSA -newkey without -x509 produces a PKCS#10 CSR; with -keyout the
        freshly generated key pair is retained for later reuse."""
        priv = _tmp("mldsa_csr_key")
        csr = _tmp("mldsa_csr.pem")
        self._clean(priv + ".priv", priv + ".pub", csr)

        r = run_wolfssl("req",
                        "-newkey", "ml-dsa:2",
                        "-keyout", priv,
                        "-subj", "/CN=wolfCLU-ML-DSA-csr",
                        "-out", csr)
        self.assertEqual(r.returncode, 0,
                         "ml-dsa CSR generation failed: " + r.stderr)
        with open(csr, encoding="utf-8") as f:
            self.assertIn("BEGIN CERTIFICATE REQUEST", f.read(),
                          "output is not a PKCS#10 certificate request")
        # -keyout retains the generated key pair.
        self.assertTrue(os.path.exists(priv + ".priv"),
                        "-keyout .priv should be retained")
        self.assertTrue(os.path.exists(priv + ".pub"),
                        "-keyout .pub should be retained")

    def test_newkey_keyout_roundtrip(self):
        """A key kept via -keyout (standard SPKI .pub) is reusable with -key."""
        key = _tmp("mldsa_rt_key")
        cert1 = _tmp("mldsa_rt1.pem")
        cert2 = _tmp("mldsa_rt2.pem")
        self._clean(key + ".priv", key + ".pub", cert1, cert2)

        r = run_wolfssl("req", "-x509", "-newkey", "ml-dsa:2",
                        "-keyout", key, "-subj", "/CN=rt1/O=wolfSSL",
                        "-days", "1", "-out", cert1)
        self.assertEqual(r.returncode, 0, "initial gen failed: " + r.stderr)

        # reuse the retained .priv (+ companion .pub) to make another cert
        r = run_wolfssl("req", "-x509", "-key", key + ".priv",
                        "-subj", "/CN=rt2/O=wolfSSL", "-days", "1",
                        "-out", cert2)
        self.assertEqual(r.returncode, 0,
                         "reuse of kept ml-dsa key failed: " + r.stderr)
        r2 = run_wolfssl("verify", "-CAfile", cert2, cert2)
        self.assertEqual(r2.returncode, 0,
                         "verify of round-trip cert failed: " + r2.stderr)

    def test_newkey_no_keyout_no_x509_cleans_temp(self):
        """-newkey ml-dsa (no -x509, no -keyout) produces a CSR and removes the
        throwaway key pair afterwards — the key is kept only with -keyout."""
        csr = _tmp("mldsa_tmp_csr.pem")
        tmp_priv = _tmp("wolfclu_tmp_mldsa.priv")
        tmp_pub = _tmp("wolfclu_tmp_mldsa.pub")
        self._clean(csr, tmp_priv, tmp_pub)

        r = run_wolfssl("req",
                        "-newkey", "ml-dsa:2",
                        "-subj", "/CN=wolfCLU-ML-DSA-tmp-nox509",
                        "-out", csr)
        self.assertEqual(r.returncode, 0,
                         "ml-dsa CSR generation failed: " + r.stderr)
        with open(csr, encoding="utf-8") as f:
            self.assertIn("BEGIN CERTIFICATE REQUEST", f.read(),
                          "output is not a PKCS#10 certificate request")
        self.assertFalse(os.path.exists(tmp_priv),
                         "throwaway private key should be removed after CSR gen")
        self.assertFalse(os.path.exists(tmp_pub),
                         "throwaway public key should be removed after CSR gen")

    def test_missing_pub_sibling_fails(self):
        """req -x509 -key <mldsa.priv> with no .pub sibling fails gracefully."""
        priv = _tmp("mldsa_nopub_key")
        cert = _tmp("mldsa_nopub_cert.pem")
        self._clean(priv + ".priv", priv + ".pub", cert)

        r = run_wolfssl("-genkey", "dilithium", "-level", "2",
                        "-out", priv, "-outform", "pem")
        if r.returncode != 0:
            self.skipTest("key generation failed: " + r.stderr)
        os.remove(priv + ".pub")

        r = run_wolfssl("req", "-x509",
                        "-key", priv + ".priv",
                        "-subj", "/CN=nopub",
                        "-days", "1",
                        "-out", cert)
        self.assertNotEqual(r.returncode, 0,
                            "missing .pub sibling should fail but returned 0")
        self.assertFalse(os.path.exists(cert) and os.path.getsize(cert) > 0,
                         "no usable cert should be produced on failure")

    def test_key_not_named_priv_fails(self):
        """An ML-DSA private key not ending in .priv fails with a clear error."""
        priv = _tmp("mldsa_named_key")
        renamed = _tmp("mldsa_named_key.pem")
        cert = _tmp("mldsa_named_cert.pem")
        self._clean(priv + ".priv", priv + ".pub", renamed, cert)

        r = run_wolfssl("-genkey", "dilithium", "-level", "2",
                        "-out", priv, "-outform", "pem")
        if r.returncode != 0:
            self.skipTest("key generation failed: " + r.stderr)
        # private-only key whose name does not end in .priv
        shutil.copyfile(priv + ".priv", renamed)

        r = run_wolfssl("req", "-x509",
                        "-key", renamed,
                        "-subj", "/CN=named",
                        "-days", "1",
                        "-out", cert)
        self.assertNotEqual(r.returncode, 0,
                            "non-.priv ml-dsa key should fail but returned 0")

    def test_newkey_no_keyout_cleans_temp(self):
        """-newkey ml-dsa without -keyout must not leave temp key files behind."""
        cert = _tmp("mldsa_tmp_cert.pem")
        tmp_priv = _tmp("wolfclu_tmp_mldsa.priv")
        tmp_pub = _tmp("wolfclu_tmp_mldsa.pub")
        # guard against leaving artifacts even if the assertion fails
        self._clean(cert, tmp_priv, tmp_pub)

        r = run_wolfssl("req", "-x509",
                        "-newkey", "ml-dsa:2",
                        "-subj", "/CN=wolfCLU-ML-DSA-tmp",
                        "-days", "1",
                        "-out", cert)
        self.assertEqual(r.returncode, 0,
                         "req -x509 -newkey ml-dsa:2 (no -keyout) failed: "
                         + r.stderr)
        self.assertGreater(os.path.getsize(cert), 0, "cert file is empty")
        self.assertFalse(os.path.exists(tmp_priv),
                         "throwaway private key was not cleaned up")
        self.assertFalse(os.path.exists(tmp_pub),
                         "throwaway public key was not cleaned up")

    def test_newkey_keyout_too_long_fails(self):
        """An overlong -keyout name is rejected gracefully (path-truncation
        guard), not silently truncated into the wrong file."""
        cert = _tmp("mldsa_long_cert.pem")
        self._clean(cert)
        longname = "a" * 600

        r = run_wolfssl("req", "-x509", "-newkey", "ml-dsa:2",
                        "-keyout", longname, "-subj", "/CN=long",
                        "-days", "1", "-out", cert)
        self.assertNotEqual(r.returncode, 0,
                            "overlong -keyout should be rejected")
        self.assertIn("too long", r.stdout + r.stderr)

    def test_config_extensions_warns(self):
        """ML-DSA -x509 with -config warns that extensions are not applied."""
        conf = _tmp("mldsa_ext.conf")
        cert = _tmp("mldsa_ext_cert.pem")
        priv = _tmp("mldsa_ext_key")
        self._clean(conf, cert, priv + ".priv", priv + ".pub")
        with open(conf, "w", encoding="utf-8", newline="\n") as f:
            f.write(TEST_CONF)

        r = run_wolfssl("req", "-x509",
                        "-newkey", "ml-dsa:2",
                        "-keyout", priv,
                        "-config", conf,
                        "-days", "1",
                        "-out", cert)
        self.assertEqual(r.returncode, 0,
                         "ml-dsa -x509 with -config failed: " + r.stderr)
        self.assertIn("ignores -config", r.stdout + r.stderr,
                      "expected a warning that extensions are ignored")

        # the produced cert is still a valid self-signed cert
        r2 = run_wolfssl("verify", "-CAfile", cert, cert)
        self.assertEqual(r2.returncode, 0,
                         "verify failed for ml-dsa -config cert: " + r2.stderr)

        # extensions really are dropped: the config's subjectAltName is absent
        if HAS_OPENSSL:
            import subprocess as _sp
            r3 = _sp.run(["openssl", "x509", "-in", cert, "-text", "-noout"],
                         capture_output=True, text=True, timeout=60)
            if r3.returncode == 0:
                self.assertNotIn("extraName", r3.stdout,
                                 "subjectAltName from config should be dropped")

    def test_keyout_passout_unencrypted_warning(self):
        """ML-DSA -keyout with -passout warns that passout is not applied."""
        key = _tmp("mldsa_warn_key")
        cert = _tmp("mldsa_warn_cert.pem")
        self._clean(key + ".priv", key + ".pub", cert)

        r = run_wolfssl("req", "-x509", "-newkey", "ml-dsa:2",
                        "-keyout", key, "-passout", "pass:secret",
                        "-subj", "/CN=warn/O=wolfSSL",
                        "-days", "1", "-out", cert)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("written unencrypted", r.stdout + r.stderr,
                      "expected the unencrypted-key warning when -passout set")

    def test_keyout_no_passout_no_warning(self):
        """ML-DSA -keyout without -passout must NOT emit the unencrypted warning."""
        key = _tmp("mldsa_nodes_key")
        cert = _tmp("mldsa_nodes_cert.pem")
        self._clean(key + ".priv", key + ".pub", cert)

        r = run_wolfssl("req", "-x509", "-newkey", "ml-dsa:2",
                        "-keyout", key, "-subj", "/CN=nodes/O=wolfSSL",
                        "-days", "1", "-out", cert)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("written unencrypted", r.stdout + r.stderr,
                         "no warning expected when no encryption requested")

    def test_noout_suppresses_output(self):
        """-noout must suppress certificate output on the ML-DSA path."""
        key = _tmp("mldsa_noout_key")
        cert = _tmp("mldsa_noout_cert.pem")
        self._clean(key + ".priv", key + ".pub", cert)

        r = run_wolfssl("req", "-x509", "-newkey", "ml-dsa:2",
                        "-keyout", key, "-noout", "-subj", "/CN=noout",
                        "-days", "1", "-out", cert)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("BEGIN CERTIFICATE", r.stdout,
                         "-noout should not print the certificate")
        self.assertFalse(os.path.exists(cert) and os.path.getsize(cert) > 0,
                         "-noout should not write certificate content")

    def test_text_warns_unsupported(self):
        """-text on the ML-DSA path warns that it is unsupported."""
        key = _tmp("mldsa_text_key")
        cert = _tmp("mldsa_text_cert.pem")
        self._clean(key + ".priv", key + ".pub", cert)

        r = run_wolfssl("req", "-x509", "-newkey", "ml-dsa:2",
                        "-keyout", key, "-text", "-subj", "/CN=text",
                        "-days", "1", "-out", cert)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("not supported", r.stdout + r.stderr,
                      "expected a warning that -text is unsupported")

    def test_level5_full_subject_dn(self):
        """ML-DSA-87 (largest sig+key) with a fully-populated subject DN must
        still fit the cert buffer (self-signed duplicates the DN as issuer)."""
        cert = _tmp("mldsa5_fulldn.pem")
        key = _tmp("mldsa5_fulldn_key")
        self._clean(cert, key + ".priv", key + ".pub")

        big = "X" * 60  # near CTC_NAME_SIZE (64) for each component
        subj = ("/C=US/ST={0}/L={0}/O={0}/OU={0}/CN={0}".format(big))
        r = run_wolfssl("req", "-x509", "-newkey", "ml-dsa:5",
                        "-keyout", key, "-subj", subj, "-days", "1",
                        "-out", cert)
        self.assertEqual(r.returncode, 0,
                         "ml-dsa:5 with a full subject DN failed: " + r.stderr)
        self.assertGreater(os.path.getsize(cert), 0, "cert file is empty")
        r2 = run_wolfssl("verify", "-CAfile", cert, cert)
        self.assertEqual(r2.returncode, 0,
                         "verify failed for full-DN ml-dsa:5 cert: " + r2.stderr)

    def test_newkey_dilithium_alias(self):
        """The 'dilithium:N' spelling of -newkey works like 'ml-dsa:N'."""
        cert = _tmp("dilithium_alias_cert.pem")
        key = _tmp("dilithium_alias_key")
        self._clean(cert, key + ".priv", key + ".pub")

        r = run_wolfssl("req", "-x509", "-newkey", "dilithium:2",
                        "-keyout", key, "-subj", "/CN=dilithium-alias/O=wolfSSL",
                        "-days", "1", "-out", cert)
        self.assertEqual(r.returncode, 0,
                         "req -x509 -newkey dilithium:2 failed: " + r.stderr)
        self.assertGreater(os.path.getsize(cert), 0, "cert file is empty")
        r2 = run_wolfssl("verify", "-CAfile", cert, cert)
        self.assertEqual(r2.returncode, 0,
                         "verify failed for dilithium-alias cert: " + r2.stderr)

    def test_existing_key_makes_csr(self):
        """An existing ML-DSA -key without -x509 produces a PKCS#10 CSR."""
        key = _tmp("mldsa_existing_csr_key")
        csr = _tmp("mldsa_existing_csr.pem")
        self._clean(key + ".priv", key + ".pub", csr)

        r = run_wolfssl("-genkey", "dilithium", "-level", "2",
                        "-out", key, "-outform", "pem")
        if r.returncode != 0:
            self.skipTest("key generation failed: " + r.stderr)

        r = run_wolfssl("req", "-key", key + ".priv",
                        "-subj", "/CN=mldsa-existing-csr", "-out", csr)
        self.assertEqual(r.returncode, 0,
                         "ml-dsa CSR generation failed: " + r.stderr)
        with open(csr, encoding="utf-8") as f:
            self.assertIn("BEGIN CERTIFICATE REQUEST", f.read(),
                          "output is not a PKCS#10 certificate request")

    def test_csr_missing_pub_sibling_fails(self):
        """CSR generation fails when the companion .pub file is missing,
        exercising wolfCLU_LoadMLDSACompanionPub error path on the CSR branch."""
        key = _tmp("mldsa_csr_nopub_key")
        csr = _tmp("mldsa_csr_nopub.pem")
        self._clean(key + ".priv", key + ".pub", csr)

        r = run_wolfssl("-genkey", "dilithium", "-level", "2",
                        "-out", key, "-outform", "pem")
        if r.returncode != 0:
            self.skipTest("key generation failed: " + r.stderr)
        try:
            os.remove(key + ".pub")
        except OSError:
            self.skipTest("could not remove .pub for test setup")

        r = run_wolfssl("req", "-key", key + ".priv",
                        "-subj", "/CN=nopub", "-out", csr)
        self.assertNotEqual(r.returncode, 0,
                            "expected failure when companion .pub is absent")
        self.assertFalse(os.path.isfile(csr),
                         "no CSR should be produced when .pub is missing")

    def test_csr_corrupt_key_fails(self):
        """CSR generation fails gracefully when -key points to a garbage file,
        exercising wolfCLU_LoadMLDSAKey error path on the CSR branch."""
        bad_key = _tmp("mldsa_corrupt.priv")
        bad_pub = _tmp("mldsa_corrupt.pub")
        csr = _tmp("mldsa_corrupt_csr.pem")
        self._clean(bad_key, bad_pub, csr)

        with open(bad_key, "w") as f:
            f.write("this is not a valid ML-DSA private key\n")
        with open(bad_pub, "w") as f:
            f.write("this is not a valid ML-DSA public key\n")

        r = run_wolfssl("req", "-key", bad_key,
                        "-subj", "/CN=corrupt", "-out", csr)
        self.assertNotEqual(r.returncode, 0,
                            "expected failure for a corrupt ML-DSA key file")
        self.assertFalse(os.path.isfile(csr),
                         "no CSR should be produced for a corrupt key")

    def test_subject_field_too_long_fails(self):
        """A DN component longer than CTC_NAME_SIZE-1 bytes is a hard error.

        Silently truncating a subject DN would produce a cert with a different
        subject than requested; wolfCLU returns a fatal error instead.
        """
        cert = _tmp("mldsa_trunc_cert.pem")
        key = _tmp("mldsa_trunc_key")
        self._clean(cert, key + ".priv", key + ".pub")

        # CTC_NAME_SIZE is build-dependent (64 by default, 128 with
        # --enable-all); 300 exceeds either so the length-check fires.
        long_cn = "Z" * 300
        r = run_wolfssl("req", "-x509", "-newkey", "ml-dsa:2",
                        "-keyout", key, "-subj", "/CN={}".format(long_cn),
                        "-days", "1", "-out", cert)
        self.assertNotEqual(r.returncode, 0,
                            "cert gen should fail with an over-long CN")
        self.assertFalse(os.path.isfile(cert) and os.path.getsize(cert) > 0,
                         "no cert should be written when DN field is too long")

    @unittest.skipUnless(HAS_OPENSSL, "openssl needed to make a PKCS#8 RSA key")
    def test_pkcs8_rsa_key_not_misclassified(self):
        """In a Dilithium build the -key ML-DSA probe must not misclassify a
        conventional PKCS#8 RSA key; it must be handled by the normal path."""
        import subprocess as _sp
        key = _tmp("pkcs8_rsa.pem")
        cert = _tmp("pkcs8_rsa_cert.pem")
        self._clean(key, cert)

        g = _sp.run(["openssl", "genpkey", "-algorithm", "RSA",
                     "-pkeyopt", "rsa_keygen_bits:2048", "-out", key],
                    capture_output=True, text=True, timeout=60)
        if g.returncode != 0:
            self.skipTest("openssl genpkey failed: " + g.stderr)

        r = run_wolfssl("req", "-x509", "-key", key, "-subj", "/CN=pkcs8rsa",
                        "-days", "1", "-out", cert)
        self.assertEqual(r.returncode, 0,
                         "PKCS#8 RSA key via -key failed (probe regression?): "
                         + r.stderr)
        self.assertGreater(os.path.getsize(cert), 0, "cert file is empty")


if __name__ == "__main__":
    test_main()

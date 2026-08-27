#!/usr/bin/env python3
"""Tests for wolfssl req and x509 -req (converted from x509-req-test.sh)."""

import datetime
import os
import re
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import WOLFSSL_BIN, CERTS_DIR, is_fips, run_wolfssl, test_main


def _ext_value(text, header):
    """Return the value line following an X509v3 extension header.

    `x509 -text` prints each extension as a header line ending in ':' with the
    value indented on the line below. A leading 'keyid:' is stripped so an
    Authority Key Id can be compared directly against a Subject Key Id.
    Returns None when the extension is absent."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if header in line and i + 1 < len(lines):
            value = lines[i + 1].strip()
            return value[len("keyid:"):] if value.startswith("keyid:") \
                else value
    return None


def _parse_time(text, label):
    """Parse a notBefore/notAfter line out of `x509 -text` output."""
    m = re.search(re.escape(label) + r"\s*:\s*(.+)", text)
    assert m, "could not find '{}' in cert text".format(label)
    # e.g. "Jul 22 22:25:31 2026 GMT"; collapse the double-space padding
    # used for single-digit days and drop the trailing timezone.
    raw = " ".join(m.group(1).replace("GMT", "").split())
    return datetime.datetime.strptime(raw, "%b %d %H:%M:%S %Y")


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


def _flip_last_der_byte(src, dst):
    """Copy a DER file to dst with its final byte flipped.

    A CSR's DER encoding ends with the signature BIT STRING, so flipping
    the last byte corrupts the signature value while leaving every ASN.1
    length intact: the request still parses, but the signature no longer
    verifies."""
    with open(src, "rb") as f:
        data = bytearray(f.read())
    assert len(data) > 0, "empty DER file"
    data[-1] ^= 0xFF
    with open(dst, "wb") as f:
        f.write(data)


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


    def _get_san_line(self, stdout):
        """Return the value line that follows an 'X509v3 Subject Alternative
        Name' header in `x509 -text` output, or None if not found."""
        lines = stdout.splitlines()
        for i, line in enumerate(lines):
            if "X509v3 Subject Alternative Name" in line:
                self.assertLess(i + 1, len(lines), "Missing SAN value line")
                return lines[i + 1]
        return None

    def test_req_inline_subjectaltname_openssl_compat(self):
        """A config subjectAltName in the OpenSSL inline form (TYPE:value list,
        not the @section indirection) is accepted and applied to the cert.

        Pins the behavior in wolfCLU_setExtensions (clu_config.c): the inline
        form is parsed via the same path as -addext
        (wolfCLU_setInlineSubjectAltNames), so an OpenSSL-style config is
        neither silently dropped nor rejected. Whitespace after the comma
        must be tolerated. Skipped on builds without
        cert extensions, where the parsing path is absent."""
        conf = _tmp("test_req_inline_san.conf")
        out = _tmp("test_req_inline_san.crt")
        self._clean(conf, out)
        with open(conf, "w", encoding="utf-8", newline="\n") as f:
            f.write(
                "[ req ]\n"
                "distinguished_name = dn\n"
                "prompt = no\n"
                "x509_extensions = v3_ext\n"
                "[ dn ]\n"
                "commonName = inline-san-test\n"
                "[ v3_ext ]\n"
                "basicConstraints = CA:FALSE\n"
                "subjectAltName = DNS:example.com, IP:10.0.0.1\n")
        r = run_wolfssl("req", "-new", "-x509",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-config", conf, "-out", out)
        combined = r.stdout + r.stderr
        if "not compiled with cert extensions" in combined:
            self.skipTest("cert extensions not compiled in")
        if "WOLFSSL_ALT_NAMES" in combined:
            self.skipTest("alt names not compiled in")
        self.assertEqual(r.returncode, 0,
                         "inline (OpenSSL-form) subjectAltName should be "
                         "accepted: " + combined)
        self.assertTrue(os.path.isfile(out) and os.path.getsize(out) > 0,
                        "certificate should be written")
        # The SAN must actually be present in the issued cert.
        r2 = run_wolfssl("x509", "-in", out, "-text", "-noout")
        self.assertEqual(r2.returncode, 0, r2.stderr)
        san_line = self._get_san_line(r2.stdout)
        self.assertIsNotNone(san_line, "SAN not found in cert output")
        self.assertIn("DNS:example.com", san_line,
                      "DNS SAN not applied from inline config form")
        self.assertIn("IP Address:10.0.0.1", san_line,
                      "IP SAN not applied from inline config form")

    def test_req_inline_subjectaltname_trims_whitespace(self):
        """Inline subjectAltName entries are trimmed of surrounding whitespace
        like OpenSSL: whitespace BEFORE the comma (a trailing space on the
        value) and AFTER the colon must not end up in the stored name. Pins the
        trailing/leading trim in wolfCLU_setInlineSubjectAltNames
        (clu_config.c)."""
        conf = _tmp("test_req_inline_san_ws.conf")
        out = _tmp("test_req_inline_san_ws.crt")
        self._clean(conf, out)
        with open(conf, "w", encoding="utf-8", newline="\n") as f:
            f.write(
                "[ req ]\n"
                "distinguished_name = dn\n"
                "prompt = no\n"
                "x509_extensions = v3_ext\n"
                "[ dn ]\n"
                "commonName = inline-san-ws-test\n"
                "[ v3_ext ]\n"
                "basicConstraints = CA:FALSE\n"
                # space before the comma (trailing on DNS value) and after the
                # colon (leading on IP value)
                "subjectAltName = DNS:trim.example.com , IP: 10.0.0.1\n")
        r = run_wolfssl("req", "-new", "-x509",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-config", conf, "-out", out)
        combined = r.stdout + r.stderr
        if "not compiled with cert extensions" in combined:
            self.skipTest("cert extensions not compiled in")
        if "WOLFSSL_ALT_NAMES" in combined:
            self.skipTest("alt names not compiled in")
        self.assertEqual(r.returncode, 0,
                         "inline subjectAltName with whitespace should be "
                         "accepted: " + combined)
        r2 = run_wolfssl("x509", "-in", out, "-text", "-noout")
        self.assertEqual(r2.returncode, 0, r2.stderr)
        san_line = self._get_san_line(r2.stdout)
        self.assertIsNotNone(san_line, "SAN not found in cert output")
        # Extract the exact DNS value; a trailing space would make this
        # "trim.example.com " and fail the equality (assertIn would not).
        m = re.search(r"DNS:([^,]*)", san_line)
        self.assertIsNotNone(m, "DNS SAN missing: " + san_line)
        self.assertEqual(m.group(1), "trim.example.com",
                         "DNS SAN not trimmed of surrounding whitespace")
        self.assertIn("IP Address:10.0.0.1", san_line,
                      "IP SAN not applied/trimmed from inline config form")

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
        self._addext_fails("bogusExtension=1",
                           "test_req_addext_unsupported_ext.crt")

    def test_req_addext_name_prefix_not_matched(self):
        """An extension name is matched up to the '=', not as a prefix.

        "keyUsagePeriod" starts with the supported name "keyUsage", so a
        prefix-only comparison would wrongly accept it as a key usage."""
        self._addext_fails("keyUsagePeriod=foo",
                           "test_req_addext_prefix.crt")

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

    def test_addext_on_existing_request_is_signed_over(self):
        """-in plus -addext must re-sign, not copy the request through.

        The mutation is applied to the parsed struct, but PEM output writes
        the cached input DER and DER output re-attaches the original
        signature, so skipping the re-sign either drops the extension at exit
        0 or emits a request whose signature does not cover its own body."""
        for form in ("pem", "der"):
            with self.subTest(outform=form):
                new = _tmp("test_req_mod." + form)
                self._clean(new)
                r = run_wolfssl("req", "-in", self.csr,
                                "-key", os.path.join(CERTS_DIR,
                                                     "server-key.pem"),
                                "-addext",
                                "subjectAltName=DNS:added.example.com",
                                "-outform", form, "-out", new)
                self.assertEqual(r.returncode, 0, r.stderr)

                t = run_wolfssl("req", "-inform", form, "-in", new,
                                "-text", "-noout")
                self.assertEqual(t.returncode, 0, t.stderr)
                self.assertIn("added.example.com", t.stdout,
                              "-addext was dropped on the -in path")

                v = run_wolfssl("req", "-inform", form, "-in", new,
                                "-noout", "-verify")
                self.assertEqual(v.returncode, 0,
                                 "altered request was not re-signed: "
                                 + v.stderr)

    def test_newkey_on_existing_request_is_signed_over(self):
        """-in plus -newkey must re-sign over the replaced public key.

        -newkey swaps the request's public key but is not one of the arms
        that sets reSign, so the signing dispatch used to skip makeReq
        entirely: PEM output re-emitted the cached input DER (dropping the
        new key at exit 0) and DER output re-encoded a request whose
        signature did not cover its own public key."""
        for form in ("pem", "der"):
            with self.subTest(outform=form):
                new = _tmp("test_req_newkey." + form)
                new_key = _tmp("test_req_newkey.key")
                self._clean(new, new_key)
                r = run_wolfssl("req", "-in", self.csr,
                                "-newkey", "rsa:2048",
                                "-keyout", new_key,
                                "-nodes",
                                "-outform", form, "-out", new)
                self.assertEqual(r.returncode, 0, r.stderr)

                v = run_wolfssl("req", "-inform", form, "-in", new,
                                "-noout", "-verify")
                self.assertEqual(v.returncode, 0,
                                 "request with a replaced key was not "
                                 "re-signed: " + v.stderr)

                with open(new, "rb") as f1, open(self.csr, "rb") as f2:
                    self.assertNotEqual(
                        f1.read(), f2.read(),
                        "-newkey was dropped, input copied through verbatim")

    def test_in_place_conversion_does_not_truncate_input(self):
        """-out naming the same file as -in must not destroy the request.

        -out is opened "wb", which truncates the moment it is opened. If it
        is opened before -in has been read, an in-place conversion wipes the
        user's CSR and then fails on an empty input. The command must either
        succeed with a valid converted request or leave the original intact.
        """
        in_place = _tmp("test_req_rt_inplace.csr")
        self._clean(in_place)
        shutil.copyfile(self.csr, in_place)
        with open(in_place, "rb") as f:
            original = f.read()

        r = run_wolfssl("req", "-inform", "pem", "-outform", "der",
                        "-in", in_place, "-out", in_place)

        with open(in_place, "rb") as f:
            after = f.read()
        self.assertGreater(len(after), 0,
                           "in-place conversion truncated the input file")

        if r.returncode == 0:
            # Converted in place: the file must now be a readable DER request.
            check = run_wolfssl("req", "-inform", "der", "-in", in_place,
                                "-noout", "-verify")
            self.assertEqual(check.returncode, 0,
                             "in-place conversion left an unreadable request: "
                             + check.stderr)
        else:
            # Refused the aliasing: the original must be untouched.
            self.assertEqual(after, original,
                             "failed in-place conversion still modified the "
                             "input file")


class TestReqVerify(unittest.TestCase):
    """Test req -verify, including that a tampered CSR fails (F-5363)."""

    @classmethod
    def setUpClass(cls):
        cls.key = os.path.join(CERTS_DIR, "server-key.pem")
        cls.csr_pem = _tmp("test_req_verify.csr")
        cls.csr_der = _tmp("test_req_verify.csr.der")
        r = run_wolfssl("req", "-new", "-key", cls.key,
                        "-subj", "/O=wolfSSL/C=US/CN=verify-test",
                        "-out", cls.csr_pem)
        assert r.returncode == 0, "setup CSR creation failed: " + r.stderr
        r = run_wolfssl("req", "-inform", "pem", "-outform", "der",
                        "-in", cls.csr_pem, "-out", cls.csr_der)
        assert r.returncode == 0, "setup CSR DER convert failed: " + r.stderr

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.csr_pem, cls.csr_der)

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_verify_good_csr(self):
        """A valid CSR verifies OK and exits 0."""
        r = run_wolfssl("req", "-in", self.csr_pem, "-verify", "-noout")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("verify OK", r.stdout + r.stderr)

    def test_verify_newly_created_csr(self):
        """-verify on a request this same command creates must succeed.

        Every other -verify test reads an already signed request from -in, so
        none of them notice if the verify runs before the signing step. This
        one does: the request is built and signed in the same invocation."""
        tmp = _tmp("test_req_new_verify.csr")
        self._clean(tmp)
        r = run_wolfssl("req", "-new",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj", "CN=test",
                        "-out", tmp, "-verify", "-noout")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("verify OK", r.stdout + r.stderr)

    def test_verify_newly_created_self_signed_cert(self):
        """-x509 -verify checks the certificate the command just self signed.

        This is the only path that reaches the X509_verify arm of verifyX509;
        isCSR is cleared by the -x509 dispatch, so the verify has to run after
        it to get there at all."""
        tmp = _tmp("test_req_x509_verify.crt")
        self._clean(tmp)
        r = run_wolfssl("req", "-x509", "-days", "3650",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj", "CN=test",
                        "-out", tmp, "-verify", "-noout")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("verify OK", r.stdout + r.stderr)

    def test_verify_tampered_csr_der_fails(self):
        """A CSR with a corrupted signature must fail verification (F-5363)."""
        bad = _tmp("test_req_verify_bad.der")
        self._clean(bad)
        _flip_last_der_byte(self.csr_der, bad)

        r = run_wolfssl("req", "-inform", "der", "-in", bad,
                        "-verify", "-noout")
        self.assertNotEqual(r.returncode, 0,
                            "tampered CSR verify should fail")
        self.assertGreaterEqual(r.returncode, 0,
                                "tampered CSR verify crashed with signal "
                                "{}".format(r.returncode))

    def test_verify_tampered_csr_no_output(self):
        """A failed verify must not emit the CSR even without -noout (F-5363).

        Output handling is gated on the verify result, so a tampered CSR
        produces no PEM body on stdout."""
        bad = _tmp("test_req_verify_bad2.der")
        self._clean(bad)
        _flip_last_der_byte(self.csr_der, bad)

        r = run_wolfssl("req", "-inform", "der", "-in", bad, "-verify")
        self.assertNotEqual(r.returncode, 0,
                            "tampered CSR verify should fail")
        self.assertNotIn("BEGIN CERTIFICATE REQUEST", r.stdout)


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

    def test_x509_days_on_a_cert_without_req_fails(self):
        """-days alters the cert, which needs a re-sign, so -req is required.

        Uses a real certificate rather than a CSR so the failure comes from
        the -days/-req check and not from the "input is a request" check."""
        out = _tmp("tmp_x509_days_noreq.cert")
        self._clean(out)
        r = run_wolfssl("x509", "-in", os.path.join(CERTS_DIR, "ca-cert.pem"),
                        "-days", "100", "-out", out)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("-req", r.stdout + r.stderr)

    def test_x509_days_rejects_out_of_range(self):
        """-days must reject values that would wrap an int, not truncate them.

        XATOI wraps silently, so 4294967396 would be accepted as 100 and
        issue a 100-day certificate at exit 0."""
        for bad in ("0", "-1", "abc", "4294967396", "99999999999999999999"):
            with self.subTest(days=bad):
                out = _tmp("tmp_x509_days_bad.cert")
                self._clean(out)
                r = run_wolfssl("x509", "-req", "-in", self.csr,
                                "-days", bad, "-signkey",
                                os.path.join(CERTS_DIR, "server-key.pem"),
                                "-out", out)
                self.assertNotEqual(r.returncode, 0,
                                    "-days {} must be rejected".format(bad))

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

    def test_x509_req_signkey_days_sets_validity_window(self):
        """x509 -req -signkey -days N sets a notAfter exactly N days after
        notBefore.

        Exercises the -days handling in wolfCLU_certSetup: it stamps the
        signed cert with a fresh notBefore of now and a notAfter of now + N
        days, rather than leaving the CSR's (absent) validity in place."""
        out = _tmp("tmp_x509req_days.cert")
        self._clean(out)
        r = run_wolfssl("x509", "-req", "-in", self.csr, "-days", "100",
                        "-signkey",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)

        r2 = run_wolfssl("x509", "-in", out, "-text", "-noout")
        self.assertEqual(r2.returncode, 0, r2.stderr)
        text = r2.stdout + r2.stderr
        before = _parse_time(text, "Not Before")
        after = _parse_time(text, "Not After")
        self.assertEqual((after - before).days, 100,
                         "validity window should be 100 days")


class TestReqCASign(unittest.TestCase):
    """Test `req -CA -CAkey` CA-signing of a CSR (caSignCert path).

    This is distinct from `req -x509` self-signing: here the issuer name and
    signature come from a separate CA cert/key, while the subject and public
    key come from the incoming request. `-CA` implies certificate issuance,
    so it works with or without `-x509`.
    """

    # Subjects baked into the request CSRs, used to assert the issued cert
    # preserves the requester's subject.
    RSA_SUBJ = "/O=wolfSSL/C=US/ST=MT/L=Bozeman/CN=leaf.example.com/OU=test"
    ECC_SUBJ = "/O=eccleaf/C=US/CN=ecc.example.com"

    @classmethod
    def setUpClass(cls):
        cls.rsa_csr = _tmp("test_reqca_rsa.csr")
        r = run_wolfssl("req", "-new",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj", cls.RSA_SUBJ, "-out", cls.rsa_csr)
        assert r.returncode == 0, "setup RSA CSR failed: " + r.stderr

        cls.ecc_csr = _tmp("test_reqca_ecc.csr")
        r = run_wolfssl("req", "-new",
                        "-key", os.path.join(CERTS_DIR, "server-ecc-key.pem"),
                        "-subj", cls.ECC_SUBJ, "-out", cls.ecc_csr)
        assert r.returncode == 0, "setup ECC CSR failed: " + r.stderr

        # Requests that state their own Basic Constraints, for the tests that
        # pin what the CA path does with a requested CA flag.
        cls.ca_true_csr = _tmp("test_reqca_catrue.csr")
        r = run_wolfssl("req", "-new",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj", cls.RSA_SUBJ,
                        "-addext", "basicConstraints=CA:TRUE",
                        "-out", cls.ca_true_csr)
        assert r.returncode == 0, "setup CA:TRUE CSR failed: " + r.stderr

        cls.ca_false_csr = _tmp("test_reqca_cafalse.csr")
        r = run_wolfssl("req", "-new",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj", cls.RSA_SUBJ,
                        "-addext", "basicConstraints=CA:FALSE",
                        "-out", cls.ca_false_csr)
        assert r.returncode == 0, "setup CA:FALSE CSR failed: " + r.stderr

        # Requests carrying extensions the issuer never agreed to. Only one
        # -addext is supported per run, so each gets its own request.
        cls.san_csr = _tmp("test_reqca_san.csr")
        r = run_wolfssl("req", "-new",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj", cls.RSA_SUBJ,
                        "-addext", "subjectAltName=DNS:notmine.example.com",
                        "-out", cls.san_csr)
        assert r.returncode == 0, "setup SAN CSR failed: " + r.stderr

        cls.ku_csr = _tmp("test_reqca_ku.csr")
        r = run_wolfssl("req", "-new",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj", cls.RSA_SUBJ,
                        "-addext", "keyUsage=digitalSignature,keyEncipherment",
                        "-out", cls.ku_csr)
        assert r.returncode == 0, "setup keyUsage CSR failed: " + r.stderr

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.rsa_csr, cls.ecc_csr, cls.ca_true_csr, cls.ca_false_csr,
                 cls.san_csr, cls.ku_csr)

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def _ca_sign(self, out_name, *extra, csr=None, ca="ca-cert.pem",
                 cakey="ca-key.pem"):
        """Run `req -CA -CAkey -in <csr>` and return (result, out_path).

        Deliberately omits `-x509`: `-CA` alone must issue a certificate, so
        the whole suite exercises that canonical invocation."""
        out = _tmp(out_name)
        self._clean(out)
        r = run_wolfssl("req",
                        "-CA", os.path.join(CERTS_DIR, ca),
                        "-CAkey", os.path.join(CERTS_DIR, cakey),
                        "-in", csr if csr is not None else self.rsa_csr,
                        "-out", out, *extra)
        return r, out

    def _text(self, cert, *extra):
        r = run_wolfssl("x509", "-in", cert, "-text", "-noout", *extra)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout + r.stderr

    def test_ca_sign_rsa_verifies(self):
        """A CA-signed cert chains back to the signing CA."""
        r, out = self._ca_sign("reqca_rsa.pem")
        self.assertEqual(r.returncode, 0, r.stderr)

        v = run_wolfssl("verify", "-CAfile",
                        os.path.join(CERTS_DIR, "ca-cert.pem"), out)
        self.assertEqual(v.returncode, 0, v.stderr)

    def test_ca_sign_wrong_ca_does_not_verify(self):
        """A cert signed by ca-cert must not verify against an unrelated CA."""
        r, out = self._ca_sign("reqca_rsa_wrongca.pem")
        self.assertEqual(r.returncode, 0, r.stderr)

        v = run_wolfssl("verify", "-CAfile",
                        os.path.join(CERTS_DIR, "ca-ecc-cert.pem"), out)
        self.assertNotEqual(v.returncode, 0)

    def test_ca_sign_issuer_is_ca_subject(self):
        """Issuer of the issued cert equals the CA cert's subject."""
        r, out = self._ca_sign("reqca_issuer.pem")
        self.assertEqual(r.returncode, 0, r.stderr)

        issuer = run_wolfssl("x509", "-in", out, "-issuer", "-noout")
        ca_subj = run_wolfssl("x509", "-in",
                              os.path.join(CERTS_DIR, "ca-cert.pem"),
                              "-subject", "-noout")
        self.assertEqual(issuer.stdout.strip(), ca_subj.stdout.strip(),
                         "issued cert issuer should match CA subject")

    def test_ca_sign_preserves_request_subject(self):
        """Subject of the issued cert comes from the request, not the CA."""
        r, out = self._ca_sign("reqca_subject.pem")
        self.assertEqual(r.returncode, 0, r.stderr)

        subj = run_wolfssl("x509", "-in", out, "-subject", "-noout")
        self.assertIn("leaf.example.com", subj.stdout,
                      "issued cert should keep the requester's CN")

    def test_ca_sign_leaf_is_ca_false(self):
        """A CA-signed leaf gets Basic Constraints CA:FALSE."""
        r, out = self._ca_sign("reqca_bc.pem")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("CA:FALSE", self._text(out))

    def test_ca_sign_ca_true_request_is_downgraded_with_a_warning(self):
        """A request asking for CA:TRUE is still issued as a leaf, and said so.

        The requester does not get to choose its own Basic Constraints: an
        honored CA:TRUE would let anyone who can get a CSR signed mint itself
        a sub-CA just by asking. OpenSSL draws the same line -- it ignores
        request extensions unless -copy_extensions says otherwise -- but it
        prints "ignoring any extensions in the request" rather than changing
        the meaning of the request silently. The warning is the assertion that
        matters here; dropping it would make the override invisible."""
        req = run_wolfssl("req", "-in", self.ca_true_csr, "-text", "-noout")
        self.assertEqual(req.returncode, 0, req.stderr)
        self.assertIn("CA:TRUE", req.stdout + req.stderr,
                      "the request under test must actually ask for CA:TRUE")

        r, out = self._ca_sign("reqca_catrue.pem", csr=self.ca_true_csr)
        self.assertEqual(r.returncode, 0, r.stderr)

        text = self._text(out)
        self.assertIn("CA:FALSE", text)
        self.assertNotIn("CA:TRUE", text)
        self.assertIn("Warning", r.stderr,
                      "the CA:TRUE downgrade must be reported, not silent")
        self.assertIn("CA:TRUE", r.stderr)

    def test_ca_sign_ca_false_request_does_not_warn(self):
        """A request that already asks for CA:FALSE gets no warning.

        Guards the warning above from the other side: it must fire on a
        meaning-changing override, not on every request that happens to carry
        Basic Constraints."""
        r, out = self._ca_sign("reqca_cafalse.pem", csr=self.ca_false_csr)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("CA:FALSE", self._text(out))
        self.assertNotIn("Warning", r.stderr)

    def test_ca_sign_plain_request_does_not_warn(self):
        """Nor does a request carrying no Basic Constraints at all."""
        r, out = self._ca_sign("reqca_nobc.pem")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("Warning", r.stderr)

    def test_ca_sign_request_prints_extensions(self):
        """Reqest gains extensions from CA and they are printed"""
        ca = "ca-cert.pem"
        cakey = "ca-key.pem"
        r = run_wolfssl("req",
                        "-CA", os.path.join(CERTS_DIR, ca),
                        "-CAkey", os.path.join(CERTS_DIR, cakey),
                        "-in", self.rsa_csr,
                        "-text")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("CA:FALSE", r.stdout)

    def test_ca_sign_has_key_identifiers(self):
        """Leaf carries its own Subject Key Id and the CA's Authority Key Id."""
        r, out = self._ca_sign("reqca_keyid.pem")
        self.assertEqual(r.returncode, 0, r.stderr)
        text = self._text(out)
        self.assertIn("Subject Key Identifier", text)
        self.assertIn("Authority Key Identifier", text)

    def test_ca_sign_ecc_request_rsa_ca(self):
        """An RSA CA can certify a request carrying an ECC public key."""
        r, out = self._ca_sign("reqca_eccreq.pem", csr=self.ecc_csr)
        self.assertEqual(r.returncode, 0, r.stderr)

        v = run_wolfssl("verify", "-CAfile",
                        os.path.join(CERTS_DIR, "ca-cert.pem"), out)
        self.assertEqual(v.returncode, 0, v.stderr)

    def test_ca_sign_days_sets_validity_window(self):
        """-days N produces a notAfter exactly N days after notBefore."""
        r, out = self._ca_sign("reqca_days.pem", "-days", "100")
        self.assertEqual(r.returncode, 0, r.stderr)

        text = self._text(out)
        before = _parse_time(text, "Not Before")
        after = _parse_time(text, "Not After")
        self.assertEqual((after - before).days, 100,
                         "validity window should be 100 days")

    def test_ca_sign_set_serial(self):
        """-set_serial assigns the requested serial (regression: no leak)."""
        r, out = self._ca_sign("reqca_serial.pem", "-set_serial", "12345")
        self.assertEqual(r.returncode, 0, r.stderr)

        s = run_wolfssl("x509", "-in", out, "-serial", "-noout")
        self.assertEqual(s.returncode, 0, s.stderr)
        # 12345 == 0x3039
        self.assertEqual(s.stdout.strip(), "serial=3039")

    def test_ca_sign_default_serial_is_wide_and_unique(self):
        """The generated default serial must be wide, positive and non zero.

        It used to be drawn from sizeof(int)-1 bytes, i.e. 24 bits, which
        collides with about 50% probability after ~4100 certificates from the
        same CA, and then from sizeof(long), which is only 8 bytes on LP64 --
        half that on the Windows and 32-bit builds. A zero draw was worse: both
        signing helpers gated on "serial > 0", so it skipped set_serialNumber
        entirely and the cert carried wolfSSL's default instead."""
        seen = set()
        for i in range(4):
            r, out = self._ca_sign("reqca_defserial{}.pem".format(i))
            self.assertEqual(r.returncode, 0, r.stderr)

            s = run_wolfssl("x509", "-in", out, "-serial", "-noout")
            self.assertEqual(s.returncode, 0, s.stderr)
            hexval = s.stdout.strip().split("=", 1)[1]

            value = int(hexval, 16)
            self.assertGreater(value, 0, "serial must be positive and non zero")
            # WOLFCLU_SERIAL_SIZE is 8 bytes, and the draw forces bit 0x40 of
            # the top one, so the width is the same on every target rather
            # than following sizeof(long).
            self.assertEqual(len(hexval), 16,
                             "serial {!r} is not 8 bytes wide".format(hexval))
            # No high-bit check on the first printed octet: -serial prints the
            # magnitude, like OpenSSL does, not the DER content octets. A
            # positive INTEGER whose top magnitude byte has the high bit set is
            # encoded with a leading 0x00 pad that is not printed, so a leading
            # octet >= 0x80 here says nothing about the sign. assertGreater
            # above is the positivity check.
            seen.add(hexval)

        self.assertEqual(len(seen), 4, "serials repeated: {}".format(seen))

    def test_ca_sign_sha512_digest(self):
        """-sha512 is reflected in the certificate signature algorithm."""
        r, out = self._ca_sign("reqca_sha512.pem", "-sha512")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("sha512", self._text(out).lower())

    def test_ca_sign_outform_der_verifies(self):
        """The DER output must carry the signature that was made over it.

        Reading the subject back only proves the file parses; a DER encoding
        rebuilt from the struct rather than written out as signed would still
        parse but no longer verify."""
        r, out = self._ca_sign("reqca_verify.der", "-outform", "DER")
        self.assertEqual(r.returncode, 0, r.stderr)

        pem = _tmp("reqca_verify_fromder.pem")
        self._clean(pem)
        c = run_wolfssl("x509", "-inform", "DER", "-in", out,
                        "-outform", "PEM", "-out", pem)
        self.assertEqual(c.returncode, 0, c.stderr)

        v = run_wolfssl("verify", "-CAfile",
                        os.path.join(CERTS_DIR, "ca-cert.pem"), pem)
        self.assertEqual(v.returncode, 0, v.stderr)

    def test_ca_sign_der_ca_cert(self):
        """-CA accepts a DER encoded CA certificate."""
        r, out = self._ca_sign("reqca_derca.pem", ca="ca-cert.der")
        self.assertEqual(r.returncode, 0, r.stderr)

        v = run_wolfssl("verify", "-CAfile",
                        os.path.join(CERTS_DIR, "ca-cert.pem"), out)
        self.assertEqual(v.returncode, 0, v.stderr)

    def test_ca_without_cakey_fails(self):
        """-CA without -CAkey has no signing key and must fail."""
        out = _tmp("reqca_nokey.pem")
        self._clean(out)
        r = run_wolfssl("req",
                        "-CA", os.path.join(CERTS_DIR, "ca-cert.pem"),
                        "-in", self.rsa_csr, "-out", out)
        self.assertNotEqual(r.returncode, 0)

    def test_cakey_without_ca_fails(self):
        """-CAkey alone must not fall through to the CSR / -x509 path."""
        out = _tmp("reqca_keyonly.pem")
        self._clean(out)
        r = run_wolfssl("req",
                        "-CAkey", os.path.join(CERTS_DIR, "ca-key.pem"),
                        "-in", self.rsa_csr, "-out", out)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("-CAkey", r.stdout + r.stderr)

    def test_x509_with_ca_is_rejected(self):
        """-x509 and -CA ask for mutually exclusive artifacts.

        The signing dispatch tests -CA first, so left unchecked this issued a
        CA-signed leaf and silently ignored the self-signing the operator
        asked for, at exit 0."""
        out = _tmp("reqca_x509_conflict.pem")
        self._clean(out)
        r = run_wolfssl("req", "-in", self.rsa_csr, "-x509",
                        "-CA", os.path.join(CERTS_DIR, "ca-cert.pem"),
                        "-CAkey", os.path.join(CERTS_DIR, "ca-key.pem"),
                        "-out", out)
        self.assertNotEqual(r.returncode, 0,
                            "-x509 with -CA was silently accepted")
        self.assertIn("-x509", r.stdout + r.stderr)

    def test_ca_sign_rejects_request_altering_options(self):
        """-CA passes the request through, so mutating options are rejected."""
        for opt in (("-subj", "/CN=other"),
                    ("-addext", "basicConstraints=CA:FALSE"),
                    ("-key", os.path.join(CERTS_DIR, "server-key.pem")),
                    ("-newkey", "rsa:2048")):
            with self.subTest(opt=opt[0]):
                r, _ = self._ca_sign("reqca_mutate.pem", *opt)
                self.assertNotEqual(r.returncode, 0,
                                    "{} must be rejected with -CA".format(
                                        opt[0]))

    def test_ca_sign_newkey_does_not_truncate_keyout(self):
        """-newkey with -CA must be rejected before -keyout is truncated."""
        keyout = _tmp("reqca_keyout.pem")
        self._clean(keyout)
        with open(keyout, "w") as f:
            f.write("PRE-EXISTING\n")

        r, _ = self._ca_sign("reqca_newkey.pem", "-newkey", "rsa:2048",
                             "-keyout", keyout, "-nodes")
        self.assertNotEqual(r.returncode, 0)
        with open(keyout) as f:
            self.assertEqual(f.read(), "PRE-EXISTING\n",
                             "-keyout was truncated before the run was "
                             "rejected")

    def test_ca_sign_non_ca_cert_fails(self):
        """A CA:FALSE cert cannot be used to issue certificates."""
        r, out = self._ca_sign("reqca_notca.pem", ca="server-ecc.pem",
                               cakey="server-ecc-key.pem")
        self.assertNotEqual(r.returncode, 0)

    @unittest.skipUnless(HAS_OPENSSL, "needs openssl to mark an EKU critical")
    def test_ca_sign_non_ca_cert_with_critical_eku_fails(self):
        """A CA:FALSE cert with a *critical* EKU must still not issue.

        wolfSSL_X509_check_ca() answers 1 for a real CA but also 4 for a leaf
        that merely carries a critical extendedKeyUsage, so a `< 1` test lets
        this shape through. Built with openssl because wolfCLU does not emit a
        critical EKU itself."""
        conf = _tmp("reqca_criteku.cnf")
        ca_pem = _tmp("reqca_criteku_ca.pem")
        out = _tmp("reqca_criteku_out.pem")
        self._clean(conf, ca_pem, out)

        with open(conf, "w") as f:
            f.write("[ req ]\ndistinguished_name = dn\nprompt = no\n"
                    "[ dn ]\ncountryName = US\ncommonName = crit-eku-leaf\n"
                    "[ v3_leaf ]\nbasicConstraints = CA:FALSE\n"
                    "extendedKeyUsage = critical, serverAuth\n")

        key = os.path.join(CERTS_DIR, "server-key.pem")
        gen = subprocess.run(
            ["openssl", "req", "-new", "-x509", "-config", conf,
             "-extensions", "v3_leaf", "-key", key, "-days", "365",
             "-out", ca_pem],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True)
        self.assertEqual(gen.returncode, 0, gen.stdout)

        r = run_wolfssl("req", "-CA", ca_pem, "-CAkey", key,
                        "-in", self.rsa_csr, "-out", out)
        self.assertNotEqual(r.returncode, 0,
                            "a CA:FALSE cert with a critical EKU must not "
                            "be accepted as an issuer")
        self.assertFalse(os.path.exists(out),
                         "no certificate should have been written")

    def test_ca_sign_tampered_request_fails(self):
        """A request with a corrupted signature must not be certified."""
        der_csr = _tmp("test_reqca_tamper.csr")
        bad_csr = _tmp("test_reqca_tamper_bad.csr")
        out = _tmp("reqca_tamper.pem")
        self._clean(der_csr, bad_csr, out)

        r = run_wolfssl("req", "-new",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj", self.RSA_SUBJ,
                        "-outform", "DER", "-out", der_csr)
        self.assertEqual(r.returncode, 0, r.stderr)
        _flip_last_der_byte(der_csr, bad_csr)

        r = run_wolfssl("req",
                        "-CA", os.path.join(CERTS_DIR, "ca-cert.pem"),
                        "-CAkey", os.path.join(CERTS_DIR, "ca-key.pem"),
                        "-inform", "DER", "-in", bad_csr, "-out", out)
        self.assertNotEqual(r.returncode, 0)

    def test_ca_sign_without_in_request_fails(self):
        """-CA with no -in has nothing to certify and must fail.

        Unlike -x509, the CA path never invents a subject/key: without a
        request there is no public key to certify, so the run is rejected
        rather than falling through to an interactive name prompt."""
        out = _tmp("reqca_noin.pem")
        self._clean(out)
        r = run_wolfssl("req",
                        "-CA", os.path.join(CERTS_DIR, "ca-cert.pem"),
                        "-CAkey", os.path.join(CERTS_DIR, "ca-key.pem"),
                        "-out", out)
        self.assertNotEqual(r.returncode, 0)

    def _write_junk(self, name):
        """Write a file that exists but holds no PEM object."""
        path = _tmp(name)
        self._clean(path)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write("this is not a PEM object\n")
        return path

    def test_ca_sign_unparsable_ca_cert_fails(self):
        """A -CA file that exists but is not a certificate is rejected.

        Distinct from the missing-file case: the access() check passes and the
        failure has to come from the PEM read inside caSignCert."""
        junk = self._write_junk("reqca_junk_cert.pem")
        out = _tmp("reqca_junkcert.pem")
        self._clean(out)
        r = run_wolfssl("req", "-CA", junk,
                        "-CAkey", os.path.join(CERTS_DIR, "ca-key.pem"),
                        "-in", self.rsa_csr, "-out", out)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Unable to read ca cert", r.stdout + r.stderr)

    def test_ca_sign_unparsable_ca_key_fails(self):
        """A -CAkey file that exists but is not a key is rejected.

        The error must name the key, not the cert: both reads happen in
        caSignCert and the diagnostics are reported separately."""
        junk = self._write_junk("reqca_junk_key.pem")
        out = _tmp("reqca_junkkey.pem")
        self._clean(out)
        r = run_wolfssl("req",
                        "-CA", os.path.join(CERTS_DIR, "ca-cert.pem"),
                        "-CAkey", junk,
                        "-in", self.rsa_csr, "-out", out)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Unable to read ca key", r.stdout + r.stderr)

    def test_ca_sign_mismatched_ca_key_is_rejected(self):
        """A -CAkey that is not the -CA cert's key fails the issue.

        Signing would otherwise succeed and produce a certificate carrying the
        CA's issuer name over a signature that does not chain to it -- valid
        looking, and useless. The pair is checked before signing, so the error
        names the option that was wrong."""
        r, _ = self._ca_sign("reqca_wrongkey.pem", cakey="server-key.pem")
        self.assertNotEqual(r.returncode, 0, r.stderr)
        self.assertIn("does not match", r.stdout + r.stderr)

    def test_ca_sign_authority_key_id_matches_ca_subject_key_id(self):
        """The leaf's Authority Key Id equals the CA cert's Subject Key Id.

        This is the link that lets a verifier find the issuer, so the value
        must be copied from the CA -- asserting only that the extension is
        present would pass on an empty or self-derived id."""
        r, out = self._ca_sign("reqca_akid.pem")
        self.assertEqual(r.returncode, 0, r.stderr)

        ca_ski = _ext_value(
            self._text(os.path.join(CERTS_DIR, "ca-cert.pem")),
            "X509v3 Subject Key Identifier")
        self.assertIsNotNone(ca_ski, "CA cert has no Subject Key Identifier")

        leaf_akid = _ext_value(self._text(out),
                                    "X509v3 Authority Key Identifier")
        self.assertIsNotNone(leaf_akid, "leaf has no Authority Key Identifier")
        self.assertEqual(leaf_akid, ca_ski,
                         "leaf AKID should be the CA's SKID")

    def test_ca_sign_subject_key_id_is_leafs_own(self):
        """The leaf's Subject Key Id is derived from its own public key.

        It must differ from the CA's, otherwise the id was copied from the
        issuer instead of computed from the certified request key."""
        r, out = self._ca_sign("reqca_skid.pem")
        self.assertEqual(r.returncode, 0, r.stderr)

        text = self._text(out)
        leaf_skid = _ext_value(text, "X509v3 Subject Key Identifier")
        leaf_akid = _ext_value(text, "X509v3 Authority Key Identifier")
        self.assertIsNotNone(leaf_skid, "leaf has no Subject Key Identifier")
        self.assertNotEqual(leaf_skid, leaf_akid,
                            "leaf SKID should come from its own key, not the "
                            "CA's")

    def test_ca_sign_drops_request_subject_alt_name(self):
        """A subjectAltName the requester asked for is not issued.

        The name in a SAN is the one a TLS client actually matches, so a
        requester that could plant one would get a certificate for a host it
        does not own out of any CA that signs its CSRs. OpenSSL drops request
        extensions for the same reason unless -copy_extensions says otherwise.
        """
        req = run_wolfssl("req", "-in", self.san_csr, "-text", "-noout")
        self.assertEqual(req.returncode, 0, req.stderr)
        self.assertIn("notmine.example.com", req.stdout + req.stderr,
                      "the request under test must actually carry a SAN")

        r, out = self._ca_sign("reqca_dropsan.pem", csr=self.san_csr)
        self.assertEqual(r.returncode, 0, r.stderr)

        text = self._text(out)
        self.assertNotIn("notmine.example.com", text,
                         "the requested SAN must not reach the issued cert")
        self.assertNotIn("Subject Alternative Name", text)

    def test_ca_sign_drops_request_key_usage(self):
        """Nor is a keyUsage the requester asked for issued.

        Guards the same rule on a second extension: the fix is to build the
        leaf from the request's subject and key alone, not to special case
        the one extension that was noticed first."""
        req = run_wolfssl("req", "-in", self.ku_csr, "-text", "-noout")
        self.assertEqual(req.returncode, 0, req.stderr)
        self.assertIn("Key Usage", req.stdout + req.stderr,
                      "the request under test must actually carry a keyUsage")

        r, out = self._ca_sign("reqca_dropku.pem", csr=self.ku_csr)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("Key Usage", self._text(out))

    def test_ca_sign_says_it_is_dropping_the_request_extensions(self):
        """Dropping them is reported, so the omission is not a surprise.

        An operator who put the subjectAltName in the CSR would otherwise get
        a certificate quietly missing it, at exit 0, with nothing pointing at
        -copy_extensions."""
        r, out = self._ca_sign("reqca_dropnotice.pem", csr=self.san_csr)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("-copy_extensions", r.stdout + r.stderr)

    def test_ca_sign_no_drop_notice_when_copying(self):
        """The notice is about a drop, so copying must not print it."""
        r, out = self._ca_sign("reqca_nodropnotice.pem",
                               "-copy_extensions", "copy", csr=self.san_csr)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("Ignoring the extensions", r.stdout + r.stderr)

    def test_ca_sign_copy_extensions_carries_the_request_san(self):
        """-copy_extensions copy is the opt-in that does carry them over."""
        r, out = self._ca_sign("reqca_copysan.pem", "-copy_extensions", "copy",
                               csr=self.san_csr)
        self.assertEqual(r.returncode, 0, r.stderr)

        text = self._text(out)
        self.assertIn("Subject Alternative Name", text)
        self.assertIn("notmine.example.com", text)

    def test_ca_sign_copy_extensions_copyall_carries_the_request_san(self):
        """copyall is accepted as a synonym for copy.

        OpenSSL separates the two by whether extensions the issuer also sets
        are skipped, but wolfCLU applies its own Basic Constraints, SKID and
        AKID after the copy either way, so they land in the same place."""
        r, out = self._ca_sign("reqca_copyallsan.pem",
                               "-copy_extensions", "copyall", csr=self.san_csr)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("notmine.example.com", self._text(out))

    def test_ca_sign_copy_extensions_still_forces_ca_false(self):
        """Even with -copy_extensions the requester does not get CA:TRUE.

        The copy is an opt-in to the requester's *leaf* extensions; Basic
        Constraints stays the issuer's call, or the opt-in would quietly hand
        out the sub-CA the CA:TRUE downgrade exists to refuse."""
        r, out = self._ca_sign("reqca_copycatrue.pem",
                               "-copy_extensions", "copy", csr=self.ca_true_csr)
        self.assertEqual(r.returncode, 0, r.stderr)

        text = self._text(out)
        self.assertIn("CA:FALSE", text)
        self.assertNotIn("CA:TRUE", text)
        self.assertIn("Warning", r.stderr)

    def test_ca_sign_copy_extensions_rejects_an_unknown_value(self):
        """A misspelled value fails instead of silently meaning "none".

        Treating an unrecognized value as the default would issue a
        certificate missing the extensions the operator asked to carry, at
        exit 0."""
        r, out = self._ca_sign("reqca_copybogus.pem",
                               "-copy_extensions", "sure", csr=self.san_csr)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.exists(out),
                         "no certificate should be written on a bad value")

    def test_ca_sign_preserves_the_request_public_key(self):
        """The issued cert certifies the key the request carried.

        The leaf is built fresh rather than signed in place, so the public key
        has to be carried across deliberately; getting the CA's key here, or
        an empty one, would be certifying the wrong subject entirely."""
        r, out = self._ca_sign("reqca_pubkey.pem", csr=self.san_csr)
        self.assertEqual(r.returncode, 0, r.stderr)

        req_key = run_wolfssl("req", "-in", self.san_csr, "-text", "-noout")
        self.assertEqual(req_key.returncode, 0, req_key.stderr)

        def modulus(text):
            """The first line of the printed modulus, signature bytes look
            the same but do not follow a 'Modulus:' header."""
            m = re.search(r"Modulus:\s*\n\s*([0-9a-f:]+)", text)
            return m.group(1) if m else None

        req_mod = modulus(req_key.stdout)
        self.assertIsNotNone(req_mod, "no modulus found in the request")
        self.assertEqual(req_mod, modulus(self._text(out)),
                         "issued cert should carry the request's public key")

    def test_ca_sign_subject_key_id_does_not_depend_on_copy_extensions(self):
        """The leaf's SKID is the same whether or not extensions are copied.

        wolfSSL derives it from WOLFSSL_X509.pubKey, which holds the bare key
        bits on a parsed request but a whole SubjectPublicKeyInfo on a key
        installed with X509_set_pubkey(). Only the former is the RFC 5280
        4.2.1.2 value every other tool computes, so the two paths drifting
        apart here means the fresh-built leaf took the wrong hash."""
        plain, out_plain = self._ca_sign("reqca_skid_plain.pem",
                                         csr=self.san_csr)
        self.assertEqual(plain.returncode, 0, plain.stderr)
        copied, out_copied = self._ca_sign("reqca_skid_copy.pem",
                                           "-copy_extensions", "copy",
                                           csr=self.san_csr)
        self.assertEqual(copied.returncode, 0, copied.stderr)

        skid_plain = _ext_value(self._text(out_plain),
                                "X509v3 Subject Key Identifier")
        skid_copied = _ext_value(self._text(out_copied),
                                 "X509v3 Subject Key Identifier")
        self.assertIsNotNone(skid_plain, "leaf has no Subject Key Identifier")
        self.assertEqual(skid_plain, skid_copied)

    def test_copy_extensions_without_ca_is_reported_as_ignored(self):
        """-copy_extensions outside the -CA path says it is doing nothing.

        A CSR is built from the options given here, so there is nothing to
        copy; dropping the option silently would read as having applied it."""
        out = _tmp("reqca_copy_noca.csr")
        self._clean(out)
        r = run_wolfssl("req", "-new",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj", self.RSA_SUBJ,
                        "-copy_extensions", "copy", "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Ignoring -copy_extensions", r.stdout + r.stderr)

    def test_ca_sign_inform_der_request(self):
        """A DER-encoded request is accepted via -inform DER and certified."""
        der_csr = _tmp("test_reqca_in.der")
        out = _tmp("reqca_derin.pem")
        self._clean(der_csr, out)

        r = run_wolfssl("req", "-inform", "pem", "-outform", "der",
                        "-in", self.rsa_csr, "-out", der_csr)
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("req",
                        "-CA", os.path.join(CERTS_DIR, "ca-cert.pem"),
                        "-CAkey", os.path.join(CERTS_DIR, "ca-key.pem"),
                        "-inform", "DER", "-in", der_csr, "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)

        v = run_wolfssl("verify", "-CAfile",
                        os.path.join(CERTS_DIR, "ca-cert.pem"), out)
        self.assertEqual(v.returncode, 0, v.stderr)

    def test_ca_sign_ecc_ca_ecc_request(self):
        """An ECC CA certifying an ECC request produces a chaining leaf."""
        r, out = self._ca_sign("reqca_ecc_ecc.pem", csr=self.ecc_csr,
                               ca="ca-ecc-cert.pem", cakey="ca-ecc-key.pem")
        self.assertEqual(r.returncode, 0, r.stderr)

        v = run_wolfssl("verify", "-CAfile",
                        os.path.join(CERTS_DIR, "ca-ecc-cert.pem"), out)
        self.assertEqual(v.returncode, 0, v.stderr)

        subj = run_wolfssl("x509", "-in", out, "-subject", "-noout")
        self.assertIn("ecc.example.com", subj.stdout)

    def test_ca_sign_writes_pem_to_stdout_without_out(self):
        """With no -out the issued cert goes to stdout as PEM."""
        r = run_wolfssl("req",
                        "-CA", os.path.join(CERTS_DIR, "ca-cert.pem"),
                        "-CAkey", os.path.join(CERTS_DIR, "ca-key.pem"),
                        "-in", self.rsa_csr)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("-----BEGIN CERTIFICATE-----", r.stdout)
        self.assertIn("-----END CERTIFICATE-----", r.stdout)

    def test_ca_sign_noout_suppresses_certificate(self):
        """-noout still signs but emits no certificate."""
        r = run_wolfssl("req",
                        "-CA", os.path.join(CERTS_DIR, "ca-cert.pem"),
                        "-CAkey", os.path.join(CERTS_DIR, "ca-key.pem"),
                        "-in", self.rsa_csr, "-noout")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("BEGIN CERTIFICATE", r.stdout)

    def test_ca_sign_text_prints_a_certificate(self):
        """-text on the CA path renders a certificate, not a request.

        `-CA` issues a cert, so -text must use the certificate printer: it
        labels the output "Certificate:", reports v3, and shows the Issuer,
        none of which a request printer does. Both request printers hardcode
        the "Certificate Request:" header, so this is gated on the isCSR flag
        rather than on which printer the build provides."""
        r = run_wolfssl("req",
                        "-CA", os.path.join(CERTS_DIR, "ca-cert.pem"),
                        "-CAkey", os.path.join(CERTS_DIR, "ca-key.pem"),
                        "-in", self.rsa_csr, "-days", "365",
                        "-text", "-noout")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Certificate:", r.stdout)
        self.assertNotIn("Certificate Request:", r.stdout)
        self.assertIn("Version: 3 (0x2)", r.stdout)
        self.assertIn("Issuer:", r.stdout)
        self.assertIn("leaf.example.com", r.stdout)

    def test_req_text_still_prints_a_request(self):
        """Without -CA/-x509 the same -text path still prints a request.

        Guards the isCSR flag from the opposite direction: routing certs to
        the certificate printer must not drag plain CSR output along."""
        r = run_wolfssl("req", "-in", self.rsa_csr, "-text", "-noout")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Certificate Request:", r.stdout)
        self.assertIn("leaf.example.com", r.stdout)


class TestReqX509SelfSign(unittest.TestCase):
    """`req -x509` self-signing (the selfSignCert path).

    TestReqCASign pins -days and -set_serial against caSignCert, but
    selfSignCert carries its own copy of both blocks, so passing there says
    nothing about this path. These mirror the -CA versions.
    """

    SUBJ = "/O=wolfSSL/C=US/CN=selfsign.example.com"

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def _self_sign(self, out_name, *extra):
        """Run `req -new -x509` and return (result, out_path)."""
        out = _tmp(out_name)
        self._clean(out)
        r = run_wolfssl("req", "-new", "-x509",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj", self.SUBJ, "-out", out, *extra)
        return r, out

    def test_x509_set_serial(self):
        """-x509 -set_serial assigns the requested serial."""
        r, out = self._self_sign("reqx509_serial.pem", "-set_serial", "12345")
        self.assertEqual(r.returncode, 0, r.stderr)

        s = run_wolfssl("x509", "-in", out, "-serial", "-noout")
        self.assertEqual(s.returncode, 0, s.stderr)
        # 12345 == 0x3039
        self.assertEqual(s.stdout.strip(), "serial=3039")

    def test_x509_default_serial_is_wide_and_unique(self):
        """The default serial on the self-signed path is wide and non zero.

        Same reasoning as test_ca_sign_default_serial_is_wide_and_unique: a
        narrow draw collides after a few thousand certs, and a zero draw would
        have skipped set_serialNumber entirely back when this path gated on
        "serial > 0"."""
        seen = set()
        for i in range(4):
            r, out = self._self_sign("reqx509_defserial{}.pem".format(i))
            self.assertEqual(r.returncode, 0, r.stderr)

            s = run_wolfssl("x509", "-in", out, "-serial", "-noout")
            self.assertEqual(s.returncode, 0, s.stderr)
            hexval = s.stdout.strip().split("=", 1)[1]

            value = int(hexval, 16)
            self.assertGreater(value, 0, "serial must be positive and non zero")
            # same fixed 8 byte width as the -CA path above
            self.assertEqual(len(hexval), 16,
                             "serial {!r} is not 8 bytes wide".format(hexval))
            seen.add(hexval)

        self.assertEqual(len(seen), 4, "serials repeated: {}".format(seen))

    def test_x509_days_sets_validity_window(self):
        """-x509 -days N produces a notAfter exactly N days after notBefore."""
        r, out = self._self_sign("reqx509_days.pem", "-days", "100")
        self.assertEqual(r.returncode, 0, r.stderr)

        t = run_wolfssl("x509", "-in", out, "-text", "-noout")
        self.assertEqual(t.returncode, 0, t.stderr)
        text = t.stdout + t.stderr
        before = _parse_time(text, "Not Before")
        after = _parse_time(text, "Not After")
        self.assertEqual((after - before).days, 100,
                         "validity window should be 100 days")


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

    def test_basic_constraints_critical_position_independent(self):
        """"critical" must parse anywhere in the value, not just at the ends.

        The value was tokenized on ':' while the keyword branches consumed
        their value with ',', so the two delimiters crossed: after CA the
        next token scanned past the comma and came out as "critical,pathlen",
        which matched no keyword and rejected an otherwise valid value."""
        for value in ("critical,CA:TRUE,pathlen:1",
                      "CA:TRUE,critical,pathlen:1",
                      "CA:TRUE,pathlen:1,critical",
                      "CA:TRUE , critical , pathlen:1"):
            with self.subTest(value=value):
                tmp = _tmp("test_req_bc_crit.csr")
                self._clean(tmp)
                r = run_wolfssl("req", "-new",
                                "-key", os.path.join(CERTS_DIR,
                                                     "server-key.pem"),
                                "-subj", "/CN=bc.example.com",
                                "-addext", "basicConstraints=" + value,
                                "-out", tmp)
                self.assertEqual(r.returncode, 0, r.stderr)

                t = run_wolfssl("req", "-in", tmp, "-text", "-noout")
                self.assertEqual(t.returncode, 0, t.stderr)
                self.assertIn("CA:TRUE", t.stdout)
                self.assertIn("pathlen:1", t.stdout)
                self.assertIn("Basic Constraints: critical", t.stdout)

    def test_basic_constraints_bad_value_names_the_value(self):
        """A bad value must be reported as the value, not the keyword."""
        for value, expect in (("CA:MAYBE", "MAYBE"),
                              ("pathlen:zzz", "zzz"),
                              ("bogus:1", "bogus")):
            with self.subTest(value=value):
                tmp = _tmp("test_req_bc_bad.csr")
                self._clean(tmp)
                r = run_wolfssl("req", "-new",
                                "-key", os.path.join(CERTS_DIR,
                                                     "server-key.pem"),
                                "-subj", "/CN=bc.example.com",
                                "-addext", "basicConstraints=" + value,
                                "-out", tmp)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn(expect, r.stdout + r.stderr)


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

    def test_empty_passout_is_rejected(self):
        """"-passout pass:" must be rejected as an empty password.

        Pins the outcome rather than the mechanism: writeOutPkey() used to
        reach this by handing the stdin prompt a capacity of 0 (the password
        length and the buffer capacity shared one variable), which read
        nothing and fell into the same error."""
        if is_fips():
            self.skipTest("FIPS build")
        tmp = _tmp("test_req_emptypass.cert")
        key = _tmp("test_req_emptypass.pem")
        self._clean(tmp, key)
        r = run_wolfssl("req", "-new", "-newkey", "rsa:2048",
                        "-keyout", key, "-config", self.conf_file,
                        "-out", tmp, "-passout", "pass:",
                        stdin_data="unused password\n")
        self.assertNotEqual(r.returncode, 0,
                            "an empty -passout must not be accepted")
        self.assertIn("password", (r.stdout + r.stderr).lower())

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

    def test_ecc_and_ed25519_accepted_with_supplied_key(self):
        """The flags only ask for keygen; with -key there is nothing to
        generate, so the request must still be built."""
        for algo in ("-ecc", "-ed25519"):
            with self.subTest(algo=algo):
                out = _tmp("test_req_algo_key{}.csr".format(algo))
                self._clean(out)
                r = run_wolfssl("req", "-new", algo,
                                "-key", os.path.join(CERTS_DIR,
                                                     "server-ecc-key.pem"),
                                "-subj", "/C=US/CN=test", "-out", out)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertTrue(os.path.exists(out))

    def test_newkey_rsa_accepts_standard_sizes(self):
        """rsa:2048/3072/4096 are the sizes -newkey generates."""
        for bits in ("2048", "3072", "4096"):
            with self.subTest(bits=bits):
                out = _tmp("test_req_newkey_{}.csr".format(bits))
                self._clean(out)
                r = run_wolfssl("req", "-new", "-newkey",
                                "rsa:" + bits, "-nodes",
                                "-subj", "/C=US/CN=test", "-out", out)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_newkey_rsa_rejects_other_sizes(self):
        """Anything outside the three standard steps is rejected up front,
        rather than being coerced by XATOI and handed to keygen."""
        for bits in ("-5", "0", "512", "1024", "2049", "20488", "abc", ""):
            with self.subTest(bits=bits):
                r = run_wolfssl("req", "-new", "-newkey", "rsa:" + bits,
                                "-nodes", "-subj", "/C=US/CN=test")
                self.assertNotEqual(r.returncode, 0,
                                    "rsa:{} must be rejected".format(bits))



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




class TestReqAddExtNames(unittest.TestCase):
    """-addext support for each extension name wolfCLU recognizes.

    Covers the name=value dispatch in wolfCLU_parseAddExt and the per-NID
    cases it routes to in wolfCLU_parseExtension."""

    # names accepted on the left of the '=' that wolfSSL cannot store on a
    # WOLFSSL_X509, so wolfCLU has to report them instead of dropping them
    UNSUPPORTED = [
        "issuerAltName=DNS:a.example.com",
        "nameConstraints=permitted;DNS:a.example.com",
        "policyConstraints=requireExplicitPolicy:0",
        "policyMappings=1.2.3:1.2.4",
        "inhibitAnyPolicy=0",
    ]

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def _addext_text(self, addexts, crt_name):
        """Self-sign a cert with each string in `addexts` passed as its own
        -addext option, and return the `x509 -text` rendering of the result."""
        crt = _tmp(crt_name)
        self._clean(crt)
        args = ["req", "-new", "-days", "3650",
                "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                "-subj", "CN=test"]
        for ext in addexts:
            args += ["-addext", ext]
        args += ["-x509", "-out", crt]
        r = run_wolfssl(*args)
        self.assertEqual(r.returncode, 0, r.stderr)

        r2 = run_wolfssl("x509", "-in", crt, "-text", "-noout")
        self.assertEqual(r2.returncode, 0, r2.stderr)
        return r2.stdout

    def _addext_fails(self, addext, crt_name):
        crt = _tmp(crt_name)
        self._clean(crt)
        r = run_wolfssl("req", "-new", "-days", "3650",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj", "CN=test",
                        "-addext", addext,
                        "-x509", "-out", crt)
        self.assertNotEqual(r.returncode, 0,
                            "expected failure for -addext {!r}".format(addext))

    def test_addext_basic_constraints(self):
        """-addext basicConstraints=CA:TRUE marks the cert a CA."""
        text = self._addext_text(["basicConstraints=CA:TRUE"],
                                 "test_addext_bc.crt")
        self.assertIn("CA:TRUE", text)

    def test_addext_subject_key_identifier(self):
        """-addext subjectKeyIdentifier=hash derives the SKID from the key."""
        text = self._addext_text(["subjectKeyIdentifier=hash"],
                                 "test_addext_skid.crt")
        skid = _ext_value(text, "X509v3 Subject Key Identifier")
        self.assertIsNotNone(skid, "SKID not found in cert output")
        # a SHA-1 hash rendered as colon separated hex
        self.assertEqual(len(skid.split(":")), 20, "got {!r}".format(skid))

    def test_addext_authority_key_identifier_always_suffix(self):
        """The OpenSSL ":always" suffix on keyid is accepted."""
        text = self._addext_text(["authorityKeyIdentifier=keyid:always"],
                                 "test_addext_akid_always.crt")
        self.assertIn("X509v3 Authority Key Identifier", text)

    def test_addext_key_usage(self):
        """-addext keyUsage=... sets each named usage bit."""
        text = self._addext_text(
            ["keyUsage=digitalSignature,keyEncipherment"],
            "test_addext_ku.crt")
        usage = _ext_value(text, "X509v3 Key Usage")
        self.assertIsNotNone(usage, "key usage not found in cert output")
        self.assertIn("Digital Signature", usage)
        self.assertIn("Key Encipherment", usage)

    def test_addext_extended_key_usage(self):
        """-addext extendedKeyUsage=... sets every named purpose."""
        text = self._addext_text(
            ["extendedKeyUsage=serverAuth,clientAuth,OCSPSigning"],
            "test_addext_eku.crt")
        eku = _ext_value(text, "X509v3 Extended Key Usage")
        self.assertIsNotNone(eku, "extended key usage not found in output")
        self.assertIn("TLS Web Server Authentication", eku)
        self.assertIn("TLS Web Client Authentication", eku)
        self.assertIn("OCSP Signing", eku)

    def test_addext_key_usage_unknown_value_fails(self):
        """An unrecognized keyUsage bit is rejected, not silently dropped.

        keyUsage and extendedKeyUsage validate the same way; a typo in either
        must fail rather than issue a cert missing the requested bit."""
        self._addext_fails("keyUsage=digitalSignature,bogusUsage",
                           "test_addext_ku_bad.crt")

    def test_addext_key_usage_empty_fails(self):
        """keyUsage with no bits set is rejected."""
        self._addext_fails("keyUsage=", "test_addext_ku_empty.crt")

    def test_addext_extended_key_usage_tolerates_spaces(self):
        """Same for extendedKeyUsage, which used to reject a trailing space."""
        text = self._addext_text(
            ["extendedKeyUsage=serverAuth , clientAuth"],
            "test_addext_eku_spaces.crt")
        eku = _ext_value(text, "X509v3 Extended Key Usage")
        self.assertIsNotNone(eku, "extended key usage not found in output")
        self.assertIn("TLS Web Server Authentication", eku)
        self.assertIn("TLS Web Client Authentication", eku)

    def test_addext_basic_constraints_pathlen_round_trips(self):
        """pathlen must be emitted as the value asked for.

        A pathLenConstraint larger than requested permits more intermediate
        CAs than the operator intended, so a wrong value is worse than none.
        pathlen:0 is the case that matters most and the one most likely to
        regress, since 0 differs from the DER encoding length."""
        for n in ("0", "1", "5"):
            with self.subTest(pathlen=n):
                text = self._addext_text(
                    ["basicConstraints=CA:TRUE,pathlen:" + n],
                    "test_addext_pathlen{}.crt".format(n))
                bc = _ext_value(text, "X509v3 Basic Constraints")
                self.assertIsNotNone(bc, "basic constraints not found")
                self.assertIn("pathlen:" + n, bc)

    def test_addext_basic_constraints_pathlen_either_order(self):
        """pathlen before CA parses the same as CA before pathlen."""
        text = self._addext_text(["basicConstraints=pathlen:2,CA:TRUE"],
                                 "test_addext_pathlen_order.crt")
        bc = _ext_value(text, "X509v3 Basic Constraints")
        self.assertIsNotNone(bc, "basic constraints not found")
        self.assertIn("CA:TRUE", bc)
        self.assertIn("pathlen:2", bc)

    def test_addext_basic_constraints_critical_prefix_token_fails(self):
        """A token merely starting with "critical" is reported, not dropped."""
        self._addext_fails("basicConstraints=criticalfoo,CA:TRUE",
                           "test_addext_bc_crit_prefix.crt")

    def test_addext_basic_constraints_pathlen_out_of_range_fails(self):
        """A pathlen that cannot fit the encoder's byte is rejected."""
        self._addext_fails("basicConstraints=CA:TRUE,pathlen:999",
                           "test_addext_pathlen_big.crt")

    def test_addext_authority_key_identifier_issuer_only_is_skipped(self):
        """authorityKeyIdentifier=issuer is skipped, not an error.

        The issuer name/serial form needs the issuing certificate, so wolfCLU
        cannot build it -- but OpenSSL accepts the value, and the message says
        "Skipping", so the command must still succeed."""
        text = self._addext_text(["authorityKeyIdentifier=issuer"],
                                 "test_addext_akid_issuer.crt")
        self.assertNotIn("X509v3 Authority Key Identifier", text)

    def test_addext_authority_key_identifier_unknown_value_fails(self):
        """A typo'd authorityKeyIdentifier key word is rejected.

        "keyidalways" must not be accepted by the prefix match that exists to
        allow the "keyid:always" qualifier."""
        self._addext_fails("authorityKeyIdentifier=keyidalways",
                           "test_addext_akid_typo.crt")

    def test_addext_subject_key_identifier_unknown_value_fails(self):
        """A typo'd subjectKeyIdentifier key word is rejected, not dropped.

        Every failure path in the skid parser returns NULL, so a fail-open
        here emits a certificate silently missing the skid at exit 0."""
        self._addext_fails("subjectKeyIdentifier=typo",
                           "test_addext_skid_typo.crt")

    def test_addext_extended_key_usage_unknown_value_fails(self):
        """An unrecognized extendedKeyUsage purpose is rejected, not dropped."""
        self._addext_fails("extendedKeyUsage=serverAuth,bogusUsage",
                           "test_addext_eku_bad.crt")

    def test_addext_extended_key_usage_empty_fails(self):
        """extendedKeyUsage with no purposes is rejected."""
        self._addext_fails("extendedKeyUsage=", "test_addext_eku_empty.crt")

    def test_addext_unsupported_extensions_fail(self):
        """Extensions wolfSSL cannot store must error, not silently vanish."""
        for i, ext in enumerate(self.UNSUPPORTED):
            with self.subTest(addext=ext):
                self._addext_fails(ext,
                                   "test_addext_unsup{}.crt".format(i))

    def test_addext_unsupported_error_names_the_extension(self):
        """The error must name the extension, not print a raw nid.

        wolfSSL's extension NID_* macros are its internal OID sums, so
        NID_issuer_alt_name is 0x7fed1daa rather than OpenSSL's 86, and three
        of these five are absent from its object table -- neither nid2ln nor
        nid2obj can name them. Printing the number gave the operator a ten
        digit value matching nothing they could look up."""
        for i, ext in enumerate(self.UNSUPPORTED):
            name = ext.split("=")[0]
            with self.subTest(addext=name):
                crt = _tmp("test_addext_unsup_name{}.crt".format(i))
                self._clean(crt)
                r = run_wolfssl("req", "-new",
                                "-key", os.path.join(CERTS_DIR,
                                                     "server-key.pem"),
                                "-subj", "CN=test", "-addext", ext,
                                "-x509", "-out", crt)
                self.assertNotEqual(r.returncode, 0)
                out = r.stdout + r.stderr
                self.assertIn(name, out,
                              "error did not name the extension: " + out)

    def test_addext_truncated_name_fails(self):
        """A name shorter than a supported one must not match it.

        The comparison spans the name plus its '=', so "keyUsag=" differs
        from "keyUsage=" at the '=' rather than matching as a prefix."""
        self._addext_fails("keyUsag=digitalSignature",
                           "test_addext_truncated.crt")

    def test_addext_extended_key_usage_any_with_named_fails(self):
        """"any" beside a named purpose must be rejected, not half applied.

        wolfSSL's SetExtKeyUsage() short circuits on EXTKEYUSE_ANY and emits
        anyExtendedKeyUsage alone, so serverAuth here would be accepted and
        then dropped from the certificate at exit 0. OpenSSL emits both."""
        self._addext_fails("extendedKeyUsage=any,serverAuth",
                           "test_addext_eku_any_named.crt")

    def test_addext_extended_key_usage_any_alone_is_accepted(self):
        """"any" on its own is still a valid extendedKeyUsage."""
        text = self._addext_text(["extendedKeyUsage=any"],
                                 "test_addext_eku_any.crt")
        self.assertIsNotNone(_ext_value(text, "X509v3 Extended Key Usage"),
                             "extended key usage not found in output")

    def test_addext_subject_alt_name_empty_fails(self):
        """A subjectAltName naming nothing is reported, not dropped.

        Every sibling parser fails on an empty value; this one used to return
        success having added no names at all."""
        self._addext_fails("subjectAltName=",
                           "test_addext_san_empty.crt")

    def test_addext_subject_alt_name_critical_only_fails(self):
        """"critical" is a flag, so it cannot be the whole value."""
        self._addext_fails("subjectAltName=critical",
                           "test_addext_san_crit_only.crt")

    def test_addext_key_usage_is_always_emitted_critical(self):
        """wolfSSL always marks keyUsage critical, with or without the flag.

        EncodeExtensions() sets the criticality flag whenever a key usage is
        present and CopyX509ToCert() never carries keyUsageCrit across, so the
        two spellings have to produce the same extension. Pinned here because
        the diagnostic wolfCLU prints about it is easy to invert."""
        for i, val in enumerate(("keyCertSign,cRLSign",
                                 "critical,keyCertSign,cRLSign")):
            with self.subTest(keyUsage=val):
                text = self._addext_text(
                    ["keyUsage=" + val],
                    "test_addext_ku_crit{}.crt".format(i))
                self.assertIn("X509v3 Key Usage: critical", text,
                              "keyUsage was not emitted critical")


EXT_SECTION_CONF = """\
[ ext_all ]
basicConstraints = CA:TRUE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
keyUsage = critical,keyCertSign,cRLSign
extendedKeyUsage = serverAuth,clientAuth
subjectAltName = DNS:inline.example.com,IP:10.0.0.1

[ ext_section_san ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = section.example.com
IP.1 = 192.0.2.7

[ ext_bad_eku ]
extendedKeyUsage = serverAuth,bogusUsage

[ ext_missing_san_section ]
subjectAltName = @no_such_section
"""


class TestX509ExtFileExtensionTypes(unittest.TestCase):
    """Extensions applied from a config section by x509 -req -extfile.

    This is the wolfCLU_setExtensions path, as opposed to the -addext path
    above; both funnel into wolfCLU_parseExtension."""

    @classmethod
    def setUpClass(cls):
        cls.conf = _tmp("test_extfile_types.conf")
        with open(cls.conf, "w", encoding="utf-8", newline="\n") as f:
            f.write(EXT_SECTION_CONF)
        cls.csr = _tmp("test_extfile_types.csr")
        r = run_wolfssl("req", "-new",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj", "CN=test", "-out", cls.csr)
        assert r.returncode == 0, "setup CSR creation failed: " + r.stderr

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.conf, cls.csr)

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def _sign_with_section(self, section, crt_name):
        """Self-sign the shared CSR applying `section` from the config, and
        return the `x509 -text` rendering of the issued cert."""
        crt = _tmp(crt_name)
        self._clean(crt)
        r = run_wolfssl("x509", "-req", "-in", self.csr, "-days", "3650",
                        "-extfile", self.conf, "-extensions", section,
                        "-signkey",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-out", crt)
        self.assertEqual(r.returncode, 0, r.stderr)

        r2 = run_wolfssl("x509", "-in", crt, "-text", "-noout")
        self.assertEqual(r2.returncode, 0, r2.stderr)
        return r2.stdout

    def test_extfile_without_req_is_reported(self):
        """Applying extensions mutates the cert, and a mutated cert is only
        written out when -req makes it re-signed. Without -req the extensions
        were applied in memory, the original DER was written, and the command
        exited 0 -- the same situation -days already refused."""
        crt = _tmp("test_extfile_noreq.crt")
        self._clean(crt)
        r = run_wolfssl("x509", "-in", os.path.join(CERTS_DIR, "ca-cert.pem"),
                        "-extfile", self.conf, "-extensions", "ext_all",
                        "-out", crt)
        self.assertNotEqual(r.returncode, 0,
                            "-extfile without -req must not silently drop "
                            "the extensions")
        self.assertIn("-req", r.stdout + r.stderr)

    def test_extfile_extended_key_usage(self):
        """extendedKeyUsage is read from the config section.

        wolfCLU_setExtensions has to look the key up for the extension to be
        reachable from a config file at all."""
        text = self._sign_with_section("ext_all", "test_extfile_eku.crt")
        eku = _ext_value(text, "X509v3 Extended Key Usage")
        self.assertIsNotNone(eku, "extended key usage not found in output")
        self.assertIn("TLS Web Server Authentication", eku)
        self.assertIn("TLS Web Client Authentication", eku)

    def test_extfile_authority_key_identifier_matches_skid(self):
        """A self signed cert's AKID keyid equals its own SKID."""
        text = self._sign_with_section("ext_all", "test_extfile_akid.crt")
        skid = _ext_value(text, "X509v3 Subject Key Identifier")
        akid = _ext_value(text, "X509v3 Authority Key Identifier")
        self.assertIsNotNone(skid, "SKID not found in cert output")
        self.assertIsNotNone(akid, "AKID not found in cert output")
        self.assertEqual(akid, skid)

    def test_extfile_key_usage_and_basic_constraints(self):
        """keyUsage and basicConstraints come through the same section."""
        text = self._sign_with_section("ext_all", "test_extfile_ku.crt")
        self.assertIn("CA:TRUE", text)
        usage = _ext_value(text, "X509v3 Key Usage")
        self.assertIsNotNone(usage, "key usage not found in cert output")
        self.assertIn("Certificate Sign", usage)
        self.assertIn("CRL Sign", usage)

    def test_extfile_subject_alt_name_inline(self):
        """The inline "TYPE:value,..." subjectAltName form is applied."""
        text = self._sign_with_section("ext_all", "test_extfile_san.crt")
        san = _ext_value(text, "X509v3 Subject Alternative Name")
        self.assertIsNotNone(san, "SAN not found in cert output")
        self.assertIn("DNS:inline.example.com", san)
        self.assertIn("IP Address:10.0.0.1", san)

    def test_extfile_bad_extended_key_usage_fails(self):
        """A bad value in a config section fails the command.

        The config path used to discard wolfCLU_parseExtension's return, so a
        rejected value printed an error and still issued a certificate without
        the extension, at exit status 0 -- while the same value via -addext
        correctly failed."""
        crt = _tmp("test_extfile_bad_eku.crt")
        self._clean(crt)
        r = run_wolfssl("x509", "-req", "-in", self.csr, "-days", "3650",
                        "-extfile", self.conf, "-extensions", "ext_bad_eku",
                        "-signkey",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-out", crt)
        self.assertNotEqual(r.returncode, 0,
                            "a rejected extension value must fail the command")

    def test_extfile_subject_alt_name_section(self):
        """The "subjectAltName = @section" form is applied.

        This form has to be resolved by wolfCLU_setExtensions, which holds the
        conf handle; wolfCLU_parseExtension only ever sees the value string
        and so cannot look a section name up."""
        text = self._sign_with_section("ext_section_san",
                                       "test_extfile_san_sect.crt")
        san = _ext_value(text, "X509v3 Subject Alternative Name")
        self.assertIsNotNone(san, "SAN not found in cert output")
        self.assertIn("DNS:section.example.com", san)
        self.assertIn("IP Address:192.0.2.7", san)

    def test_extfile_subject_alt_name_missing_section_fails(self):
        """"subjectAltName = @section" naming a section that is not there
        fails the command.

        It used to leave ret at success, so the certificate was issued with no
        alt names at all and the operator was never told the section name was
        wrong."""
        crt = _tmp("test_extfile_san_missing_sect.crt")
        self._clean(crt)
        r = run_wolfssl("x509", "-req", "-in", self.csr, "-days", "3650",
                        "-extfile", self.conf,
                        "-extensions", "ext_missing_san_section",
                        "-signkey",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-out", crt)
        self.assertNotEqual(r.returncode, 0,
                            "a missing alt name section must fail the command")
        self.assertIn("no_such_section", r.stdout + r.stderr)


class TestReqOptionHandling(unittest.TestCase):
    """Option level behaviour: file aliasing, diagnostics, dropped values."""

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_keyout_same_file_as_out_keeps_both(self):
        """"-keyout f -out f" appends both objects to one file.

        Opening the path a second time with "wb" truncated the key that had
        just been written and left the two BIOs flushing from offset 0 into
        each other."""
        both = _tmp("test_req_keyout_same.pem")
        self._clean(both)

        r = run_wolfssl("req", "-new", "-newkey", "rsa:2048", "-nodes",
                        "-subj", "/C=US/CN=test",
                        "-keyout", both, "-out", both)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

        with open(both) as f:
            text = f.read()
        self.assertIn("PRIVATE KEY", text, "the key was lost")
        self.assertIn("BEGIN CERTIFICATE REQUEST", text,
                      "the request was lost")

        # both objects still have to parse out of the combined file
        v = run_wolfssl("req", "-in", both, "-noout", "-verify")
        self.assertEqual(v.returncode, 0, v.stdout + v.stderr)

    def test_inform_error_names_inform(self):
        """The -inform diagnostic used to name -outform, contradicting the
        usage line wolfCLU_checkInform prints just above it."""
        r = run_wolfssl("req", "-new", "-inform", "raw",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj", "/C=US/CN=test")
        self.assertNotEqual(r.returncode, 0)
        out = r.stdout + r.stderr
        self.assertIn("-inform", out)
        self.assertNotIn("pem or der to -outform", out)

    def test_help_exits_success_after_passout(self):
        """-help used to return from inside the parse loop, skipping the
        password wipe that -passout had just filled."""
        r = run_wolfssl("req", "-passout", "pass:secret", "-help")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_serial_and_days_reported_as_ignored_for_csr(self):
        """A PKCS#10 request has neither field, so say so rather than
        dropping the value silently."""
        out = _tmp("test_req_csr_serial.csr")
        self._clean(out)
        r = run_wolfssl("req", "-new", "-set_serial", "42", "-days", "30",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj", "/C=US/CN=test", "-out", out)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("Ignoring", r.stdout + r.stderr)

    def test_addext_akid_without_a_key_id_is_reported(self):
        """authorityKeyIdentifier values that name no key id must fail.

        "critical" on its own and an empty value both used to build no
        extension and still exit 0, silently dropping what was asked for --
        unlike every sibling extension parser."""
        for value in ("critical", ""):
            with self.subTest(value=value):
                crt = _tmp("test_req_akid_empty.crt")
                self._clean(crt)
                r = run_wolfssl("req", "-new", "-days", "3650",
                                "-key", os.path.join(CERTS_DIR,
                                                     "server-key.pem"),
                                "-subj", "/C=US/CN=test",
                                "-addext",
                                "authorityKeyIdentifier=" + value,
                                "-x509", "-out", crt)
                self.assertNotEqual(r.returncode, 0,
                                    "authorityKeyIdentifier={!r} must be "
                                    "reported".format(value))

        # "issuer" alone stays a success: it is the one documented skip, and
        # is covered by TestReqAddExtNames.
        #   test_addext_authority_key_identifier_issuer_only_is_skipped

    def test_newkey_algorithm_conflict_either_order(self):
        """The -newkey/-ecc agreement check must not depend on argv order."""
        for args in (("-ecc", "-newkey", "rsa:2048"),
                     ("-newkey", "rsa:2048", "-ecc")):
            with self.subTest(args=args):
                r = run_wolfssl("req", "-new", "-nodes",
                                "-subj", "/C=US/CN=test", *args)
                self.assertNotEqual(r.returncode, 0,
                                    "{} must be rejected".format(args))

    def test_duplicate_digest_rejected(self):
        """-sha and -sha1 are one digest under two names, so GetOpt's
        duplicate detection cannot see the repeat."""
        for args in (("-sha", "-sha1"), ("-sha256", "-sha512")):
            with self.subTest(args=args):
                r = run_wolfssl("req", "-new",
                                "-key", os.path.join(CERTS_DIR,
                                                     "server-key.pem"),
                                "-subj", "/C=US/CN=test", *args)
                self.assertNotEqual(r.returncode, 0,
                                    "{} must be rejected".format(args))

    def test_addext_name_may_be_spaced(self):
        """OpenSSL routes -addext through its conf parser, which trims around
        the '=', so "name = value" has to work here too."""
        crt = _tmp("test_req_addext_spaced.crt")
        self._clean(crt)
        r = run_wolfssl("req", "-new", "-days", "3650",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj", "/C=US/CN=test",
                        "-addext", "keyUsage = digitalSignature",
                        "-x509", "-out", crt)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

        t = run_wolfssl("x509", "-in", crt, "-text", "-noout")
        self.assertEqual(t.returncode, 0, t.stderr)
        self.assertIn("Digital Signature", t.stdout)

    def test_addext_empty_basic_constraints_is_reported(self):
        """An empty value used to add a CA:FALSE extension nobody asked for."""
        crt = _tmp("test_req_bc_empty.crt")
        self._clean(crt)
        r = run_wolfssl("req", "-new", "-days", "3650",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj", "/C=US/CN=test",
                        "-addext", "basicConstraints=",
                        "-x509", "-out", crt)
        self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_addext_eku_accepts_dotted_oids(self):
        """Conf files written for OpenSSL commonly spell an EKU as its OID."""
        crt = _tmp("test_req_eku_oid.crt")
        self._clean(crt)
        r = run_wolfssl("req", "-new", "-days", "3650",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj", "/C=US/CN=test",
                        "-addext",
                        "extendedKeyUsage=1.3.6.1.5.5.7.3.1,"
                        "1.3.6.1.5.5.7.3.2",
                        "-x509", "-out", crt)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

        t = run_wolfssl("x509", "-in", crt, "-text", "-noout")
        self.assertEqual(t.returncode, 0, t.stderr)
        self.assertIn("TLS Web Server Authentication", t.stdout)
        self.assertIn("TLS Web Client Authentication", t.stdout)

    def test_addext_san_critical_any_position(self):
        """"critical" is position independent for every other extension
        parser, so subjectAltName must not be the exception."""
        for value in ("critical,DNS:a.example.com",
                      "DNS:a.example.com,critical"):
            with self.subTest(value=value):
                crt = _tmp("test_req_san_crit.crt")
                self._clean(crt)
                r = run_wolfssl("req", "-new", "-days", "3650",
                                "-key", os.path.join(CERTS_DIR,
                                                     "server-key.pem"),
                                "-subj", "/C=US/CN=test",
                                "-addext", "subjectAltName=" + value,
                                "-x509", "-out", crt)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

                t = run_wolfssl("x509", "-in", crt, "-text", "-noout")
                self.assertEqual(t.returncode, 0, t.stderr)
                self.assertIn("a.example.com", t.stdout)

    def test_san_named_critical_is_still_a_dns_name(self):
        """A name that merely starts with "critical" is a name, not a flag."""
        crt = _tmp("test_req_san_critname.crt")
        self._clean(crt)
        r = run_wolfssl("req", "-new", "-days", "3650",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj", "/C=US/CN=test",
                        "-addext", "subjectAltName=DNS:critical.example.com",
                        "-x509", "-out", crt)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

        t = run_wolfssl("x509", "-in", crt, "-text", "-noout")
        self.assertEqual(t.returncode, 0, t.stderr)
        self.assertIn("critical.example.com", t.stdout)


if __name__ == "__main__":
    test_main()

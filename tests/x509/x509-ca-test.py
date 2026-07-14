#!/usr/bin/env python3
"""Tests for wolfssl ca (converted from x509-ca-test.sh)."""

import functools
import os
import shutil
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import WOLFSSL_BIN, CERTS_DIR, run_wolfssl, test_main

# Use absolute forward-slash paths so wolfSSL recognizes them as absolute.
# Temporary artefacts go under the build directory (CWD under automake),
# because the source tree is read-only during `make distcheck`.
_R = os.path.abspath(os.getcwd()).replace("\\", "/")
_CERTS = CERTS_DIR.replace("\\", "/")

CA_CONF = f"""\
[ ca ]
default_ca = CA_default

[ usr_cert ]

basicConstraints=CA:FALSE
nsComment            = "wolfSSL Generated Certificate using wolfSSL command line utility."
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

[ CA_default ]

dir = {_CERTS}
database = {_R}/index.txt
new_certs_dir = {_R}

certificate = {_CERTS}/ca-cert.pem
private_key = {_CERTS}/ca-key.pem
rand_serial = yes

default_days = 365
default_md = sha256

policy = policy_any

[ policy_any]
countryName            = supplied
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional
"""

CA_2_CONF = f"""\
[ ca ]
default_ca = CA_default

[ usr_cert ]

basicConstraints=CA:FALSE
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

[ CA_default ]

dir = {_CERTS}
database = {_R}/index.txt
new_certs_dir = {_R}
certificate = {_CERTS}/ca-cert.pem
private_key = {_CERTS}/ca-key.pem
RANDFILE = {_R}/rand-file-test
serial   = {_R}/serial-file-test
default_days = 365
default_md = sha256
unique_subject = yes

policy = policy_any

[ policy_any]
countryName            = supplied
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional
"""

CA_MATCH_CONF = f"""\
[ ca ]
default_ca = CA_default

[ usr_cert ]

basicConstraints=CA:FALSE

[ CA_default ]

dir = {_CERTS}
database = {_R}/index.txt
new_certs_dir = {_R}

certificate = {_CERTS}/ca-cert.pem
private_key = {_CERTS}/ca-key.pem
rand_serial = yes

default_days = 365
default_md = sha256

policy = policy_match

[ policy_match ]
countryName            = supplied
stateOrProvinceName    = optional
organizationName       = match
organizationalUnitName = optional
commonName             = match
emailAddress           = optional

crl_dir    = {_R}/crls-test
crlnumber  = {_R}/crlnumber-test
crl        = {_CERTS}/crl.pem
"""

CA_CRL_CONF = f"""\
[ ca ]
default_ca = CA_default

[ usr_cert ]

basicConstraints=CA:FALSE

[ CA_default ]

dir = {_CERTS}
database = {_R}/index.txt
new_certs_dir = {_R}

certificate = {_CERTS}/ca-cert.pem
private_key = {_CERTS}/ca-key.pem
rand_serial = yes

default_days = 365
default_md = sha256

policy = policy_any

[ policy_any]
countryName            = supplied
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional

crl_dir    = {_R}/crls-test
crlnumber  = {_R}/crlnumber-test
crl        = {_CERTS}/crl.pem
"""

CA_OUTDIR_CONF_TEMPLATE = f"""\
[ ca ]
default_ca = CA_default

[ CA_default ]
dir = {_CERTS}
database = {_R}/index.txt
new_certs_dir = {{new_certs_dir}}
certificate = {_CERTS}/ca-cert.pem
private_key = {_CERTS}/ca-key.pem
rand_serial = yes
default_days = 365
default_md = sha256
policy = policy_any

[ policy_any ]
countryName            = supplied
stateOrProvinceName    = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional
"""


def _tmp(name):
    """Return an absolute path for a temp file in the current working directory.

    Tests run from the build directory, which may differ from the source
    tree (e.g. under `make distcheck`, where the srcdir is read-only).
    Uses forward slashes so wolfSSL's path handling recognizes the path
    as absolute on Windows (it checks for leading '/')."""
    return os.path.abspath(os.path.join(os.getcwd(), name)).replace("\\", "/")


def _cleanup(*files):
    for f in files:
        if os.path.isdir(f):
            shutil.rmtree(f, ignore_errors=True)
        elif os.path.exists(f):
            os.remove(f)


def _touch(path):
    with open(path, "a"):
        pass


@functools.lru_cache(maxsize=None)
def _has_dilithium():
    """Return True if the current build supports Dilithium/ML-DSA."""
    r = run_wolfssl("-genkey", "-h")
    return "dilithium" in (r.stdout + r.stderr)


@functools.lru_cache(maxsize=None)
def _has_ed25519():
    """Return True if the current build supports Ed25519 key generation."""
    r = run_wolfssl("-genkey", "-h")
    return "ed25519" in (r.stdout + r.stderr).lower()


@functools.lru_cache(maxsize=None)
def _has_altextend():
    """Check whether chimera cert (altextend) support is available."""
    r = run_wolfssl("ca", "-help")
    combined = r.stdout + r.stderr
    return "altextend" in combined


@functools.lru_cache(maxsize=None)
def _can_mldsa_csr():
    """True if wolfCLU can generate a PKCS#10 CSR from an ML-DSA key.

    ML-DSA CSR generation (req -new) is built with raw wolfcrypt; probe at
    runtime so tests needing an ML-DSA CSR skip cleanly on a wolfSSL build
    lacking ML-DSA/cert-req support instead of failing."""
    if not _has_dilithium():
        return False
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        key = os.path.join(d, "probe")
        r = run_wolfssl("-genkey", "ml-dsa", "-level", "2", "-out", key,
                        "-output", "keypair", "-outform", "PEM")
        if r.returncode != 0:
            return False
        csr = os.path.join(d, "probe.csr")
        r = run_wolfssl("req", "-new", "-key", key + ".priv",
                        "-subj", "/CN=probe", "-out", csr)
        return r.returncode == 0


@functools.lru_cache(maxsize=None)
def _can_print_mldsa_cert():
    """True if `x509 -text` can render an ML-DSA certificate.

    Some wolfSSL builds cannot print an ML-DSA SubjectPublicKey, so a
    self-signed ML-DSA cert fails to print even though it is generated and
    written correctly. Probe so print-dependent assertions run only where the
    build supports them."""
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


class TestCAHelp(unittest.TestCase):
    """ca -h and -help should succeed."""

    def test_ca_h(self):
        r = run_wolfssl("ca", "-h")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_ca_help(self):
        r = run_wolfssl("ca", "-help")
        self.assertEqual(r.returncode, 0, r.stderr)



class TestCASelfSign(unittest.TestCase):
    """ca -selfsign tests."""

    @classmethod
    def setUpClass(cls):
        cls.conf = _tmp("ca_selfsign.conf")
        with open(cls.conf, "w", encoding="utf-8", newline="\n") as f:
            f.write(CA_CONF)
        _touch(_tmp("index.txt"))
        cls.csr = _tmp("ca_selfsign.csr")
        r = run_wolfssl("req", "-key",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj",
                        "/O=wolfSSL/C=US/ST=MT/L=Bozeman/CN=wolfSSL/OU=org-unit",
                        "-out", cls.csr)
        assert r.returncode == 0, "CSR creation failed: " + r.stderr

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.conf, cls.csr, _tmp("index.txt"))

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_bad_config_fails(self):
        """Reading nonexistent config file should fail."""
        r = run_wolfssl("ca", "-config", _tmp("ca-example.conf"),
                        "-in", self.csr, "-out", "tmp_bad.pem",
                        "-md", "sha256", "-selfsign",
                        "-keyfile", os.path.join(CERTS_DIR, "ca-key.pem"))
        self._clean(_tmp("tmp_bad.pem"))
        self.assertNotEqual(r.returncode, 0)

    def test_selfsign_key_mismatch_fails(self):
        """selfsign with wrong key (ca-key vs server-key CSR) should fail."""
        out_name = "tmp_selfsign_mm.pem"
        out = _tmp(out_name)
        self._clean(out)
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", out_name,
                        "-md", "sha256", "-selfsign",
                        "-keyfile", os.path.join(CERTS_DIR, "ca-key.pem"))
        self.assertNotEqual(r.returncode, 0)

    def test_selfsign_correct_key(self):
        """selfsign with matching key succeeds, subject == issuer."""
        out_name = "test_ca_selfsign.pem"
        out = _tmp(out_name)
        self._clean(out)
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", out_name,
                        "-md", "sha256", "-selfsign",
                        "-keyfile",
                        os.path.join(CERTS_DIR, "server-key.pem"))
        self.assertEqual(r.returncode, 0, r.stderr)

        subj = run_wolfssl("x509", "-in", out, "-subject", "-noout")
        issu = run_wolfssl("x509", "-in", out, "-issuer", "-noout")
        self.assertEqual(subj.stdout.strip(), issu.stdout.strip(),
                         "subject and issuer mismatch on self-signed cert")

    def test_selfsign_verify_fails_wrong_ca(self):
        """Self-signed cert should not verify with unrelated CAs."""
        out_name = "test_ca_selfsign_vf.pem"
        out = _tmp(out_name)
        self._clean(out)
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", out_name,
                        "-md", "sha256", "-selfsign",
                        "-keyfile",
                        os.path.join(CERTS_DIR, "server-key.pem"))
        self.assertEqual(r.returncode, 0, r.stderr)

        r1 = run_wolfssl("verify", "-CAfile",
                         os.path.join(CERTS_DIR, "server-cert.pem"), out)
        self.assertNotEqual(r1.returncode, 0)

        r2 = run_wolfssl("verify", "-CAfile",
                         os.path.join(CERTS_DIR, "ca-cert.pem"), out)
        self.assertNotEqual(r2.returncode, 0)



class TestCACreateAndVerify(unittest.TestCase):
    """ca certificate creation and verification."""

    @classmethod
    def setUpClass(cls):
        cls.conf = _tmp("ca_create.conf")
        with open(cls.conf, "w", encoding="utf-8", newline="\n") as f:
            f.write(CA_CONF)
        _cleanup(_tmp("index.txt"))
        _touch(_tmp("index.txt"))
        cls.csr = _tmp("ca_create.csr")
        r = run_wolfssl("req", "-key",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj",
                        "/O=wolfSSL/C=US/ST=MT/L=Bozeman/CN=wolfSSL/OU=org-unit",
                        "-out", cls.csr)
        assert r.returncode == 0, "CSR creation failed: " + r.stderr

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.conf, cls.csr, _tmp("index.txt"))

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_create_and_verify(self):
        """Create cert and verify with CA."""
        out_name = "test_ca_cv.pem"
        out = _tmp(out_name)
        self._clean(out)
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", out_name)
        self.assertEqual(r.returncode, 0, r.stderr)

        r2 = run_wolfssl("verify", "-CAfile",
                         os.path.join(CERTS_DIR, "ca-cert.pem"), out)
        self.assertEqual(r2.returncode, 0, r2.stderr)


class TestCAOverrideConfig(unittest.TestCase):
    """Override config options with command-line flags."""

    @classmethod
    def setUpClass(cls):
        cls.conf = _tmp("ca_override.conf")
        with open(cls.conf, "w", encoding="utf-8", newline="\n") as f:
            f.write(CA_CONF)
        _cleanup(_tmp("index.txt"))
        _touch(_tmp("index.txt"))
        cls.csr = _tmp("ca_override.csr")
        r = run_wolfssl("req", "-key",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj",
                        "/O=wolfSSL/C=US/ST=MT/L=Bozeman/CN=wolfSSL/OU=org-unit",
                        "-out", cls.csr)
        assert r.returncode == 0, "CSR creation failed: " + r.stderr

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.conf, cls.csr, _tmp("index.txt"))

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_override_extensions_md_days_cert_keyfile(self):
        """Override -extensions, -md, -days, -cert, -keyfile."""
        out_name = "test_ca_override.pem"
        out = _tmp(out_name)
        self._clean(out)
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", out_name,
                        "-extensions", "usr_cert",
                        "-md", "sha512",
                        "-days", "3650",
                        "-cert",
                        os.path.join(CERTS_DIR, "ca-ecc-cert.pem"),
                        "-keyfile",
                        os.path.join(CERTS_DIR, "ca-ecc-key.pem"))
        self.assertEqual(r.returncode, 0, r.stderr)



class TestCAKeyMismatch(unittest.TestCase):
    """ca with mismatched key should fail."""

    @classmethod
    def setUpClass(cls):
        cls.conf = _tmp("ca_keymm.conf")
        with open(cls.conf, "w", encoding="utf-8", newline="\n") as f:
            f.write(CA_CONF)
        _cleanup(_tmp("index.txt"))
        _touch(_tmp("index.txt"))
        cls.csr = _tmp("ca_keymm.csr")
        r = run_wolfssl("req", "-key",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj",
                        "/O=wolfSSL/C=US/ST=MT/L=Bozeman/CN=wolfSSL/OU=org-unit",
                        "-out", cls.csr)
        assert r.returncode == 0, "CSR creation failed: " + r.stderr

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.conf, cls.csr, _tmp("index.txt"))

    def test_key_mismatch(self):
        out_name = "test_ca_km.pem"
        out = _tmp(out_name)
        self.addCleanup(lambda: _cleanup(out))
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", out_name,
                        "-keyfile",
                        os.path.join(CERTS_DIR, "ecc-key.pem"))
        self.assertNotEqual(r.returncode, 0)



class TestCAUniqueSubjectAndSerial(unittest.TestCase):
    """unique_subject enforcement and serial number handling."""

    def setUp(self):
        self.conf = _tmp("ca_uniq.conf")
        with open(self.conf, "w", encoding="utf-8", newline="\n") as f:
            f.write(CA_2_CONF)
        _cleanup(_tmp("index.txt"), _tmp("serial-file-test"),
                 _tmp("rand-file-test"))
        _touch(_tmp("index.txt"))
        with open(_tmp("serial-file-test"), "w") as f:
            f.write("01\n")
        _touch(_tmp("rand-file-test"))
        self.csr = _tmp("ca_uniq.csr")
        r = run_wolfssl("req", "-key",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj",
                        "/O=wolfSSL/C=US/ST=MT/L=Bozeman/CN=wolfSSL/OU=org-unit",
                        "-out", self.csr)
        assert r.returncode == 0, "CSR creation failed: " + r.stderr

    def tearDown(self):
        _cleanup(self.conf, self.csr, _tmp("index.txt"),
                 _tmp("serial-file-test"), _tmp("rand-file-test"))

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_unique_subject_fail(self):
        """Creating same subject twice with unique_subject=yes should fail."""
        out_name = "test_ca_uniq.pem"
        out = _tmp(out_name)
        self._clean(out)
        # First cert succeeds
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", out_name)
        self.assertEqual(r.returncode, 0, r.stderr)
        # Second with same subject should fail
        r2 = run_wolfssl("ca", "-config", self.conf,
                         "-in", self.csr, "-out", out_name)
        self.assertNotEqual(r2.returncode, 0)

    def test_serial_number(self):
        """First cert should have serial=01."""
        out_name = "test_ca_serial.pem"
        out = _tmp(out_name)
        self._clean(out)
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", out_name)
        self.assertEqual(r.returncode, 0, r.stderr)

        r2 = run_wolfssl("x509", "-in", out, "-noout", "-serial")
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertEqual(r2.stdout.strip(), "serial=01")

    def test_serial_increment(self):
        """Second cert should have serial=02."""
        out1_name = "test_ca_serial1.pem"
        out2_name = "test_ca_serial2.pem"
        out1 = _tmp(out1_name)
        out2 = _tmp(out2_name)
        self._clean(out1, out2)

        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", out1_name)
        self.assertEqual(r.returncode, 0, r.stderr)

        # Reset index for unique_subject
        _cleanup(_tmp("index.txt"))
        _touch(_tmp("index.txt"))

        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", out2_name)
        self.assertEqual(r.returncode, 0, r.stderr)

        r2 = run_wolfssl("x509", "-in", out2, "-noout", "-serial")
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertEqual(r2.stdout.strip(), "serial=02")

    def test_rand_file_written(self):
        """Rand file should be 256 bytes after cert creation."""
        out_name = "test_ca_rand.pem"
        out = _tmp(out_name)
        self._clean(out)
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", out_name)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(_tmp("rand-file-test")))
        size = os.path.getsize(_tmp("rand-file-test"))
        self.assertEqual(size, 256,
                         "rand file is {} bytes, expected 256".format(size))

    def test_rand_file_changes(self):
        """Rand file should change between cert creations."""
        out1_name = "test_ca_randc1.pem"
        out2_name = "test_ca_randc2.pem"
        out1 = _tmp(out1_name)
        out2 = _tmp(out2_name)
        self._clean(out1, out2)

        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", out1_name)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(_tmp("rand-file-test"), "rb") as f:
            rand1 = f.read()

        _cleanup(_tmp("index.txt"))
        _touch(_tmp("index.txt"))

        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", out2_name)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(_tmp("rand-file-test"), "rb") as f:
            rand2 = f.read()

        self.assertNotEqual(rand1, rand2, "rand file did not change")



class TestCAPolicy(unittest.TestCase):
    """Policy section enforcement."""

    @classmethod
    def setUpClass(cls):
        cls.conf = _tmp("ca_policy.conf")
        cls.match_conf = _tmp("ca_policy_match.conf")
        with open(cls.conf, "w", encoding="utf-8", newline="\n") as f:
            f.write(CA_CONF)
        with open(cls.match_conf, "w", encoding="utf-8", newline="\n") as f:
            f.write(CA_MATCH_CONF)

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.conf, cls.match_conf)

    def setUp(self):
        _cleanup(_tmp("index.txt"))
        _touch(_tmp("index.txt"))

    def tearDown(self):
        _cleanup(_tmp("index.txt"))

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_no_common_name_supplied_fails(self):
        """CSR without commonName should fail when policy requires 'supplied'."""
        csr = _tmp("ca_pol_nocn.csr")
        out_name = "ca_pol_nocn.pem"
        out = _tmp(out_name)
        self._clean(csr, out)
        r = run_wolfssl("req", "-key",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj", "O=wolfSSL/C=US/ST=MT/L=Bozeman/OU=org-unit",
                        "-out", csr)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", csr, "-out", out_name,
                        "-md", "sha256",
                        "-keyfile", os.path.join(CERTS_DIR, "ca-key.pem"))
        self.assertNotEqual(r.returncode, 0)

    def test_no_common_name_match_fails(self):
        """CSR without commonName should also fail with match policy."""
        csr = _tmp("ca_pol_nocnm.csr")
        out_name = "ca_pol_nocnm.pem"
        out = _tmp(out_name)
        self._clean(csr, out)
        r = run_wolfssl("req", "-key",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj", "O=wolfSSL/C=US/ST=MT/L=Bozeman/OU=org-unit",
                        "-out", csr)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run_wolfssl("ca", "-config", self.match_conf,
                        "-in", csr, "-out", out_name,
                        "-md", "sha256",
                        "-keyfile", os.path.join(CERTS_DIR, "ca-key.pem"))
        self.assertNotEqual(r.returncode, 0)

    def test_common_name_supplied_succeeds(self):
        """CSR with commonName should pass policy_any."""
        csr = _tmp("ca_pol_cn.csr")
        out_name = "ca_pol_cn.pem"
        out = _tmp(out_name)
        self._clean(csr, out)
        r = run_wolfssl("req", "-key",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj",
                        "O=Sawtooth/CN=www.wolfclu.com/C=US/ST=MT/L=Bozeman/OU=org-unit",
                        "-out", csr)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", csr, "-out", out_name,
                        "-md", "sha256",
                        "-keyfile", os.path.join(CERTS_DIR, "ca-key.pem"))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_common_name_mismatch_fails(self):
        """CSR with non-matching commonName should fail policy_match."""
        csr = _tmp("ca_pol_cnmm.csr")
        out_name = "ca_pol_cnmm.pem"
        out = _tmp(out_name)
        self._clean(csr, out)
        r = run_wolfssl("req", "-key",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj",
                        "O=Sawtooth/CN=www.wolfclu.com/C=US/ST=MT/L=Bozeman/OU=org-unit",
                        "-out", csr)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run_wolfssl("ca", "-config", self.match_conf,
                        "-in", csr, "-out", out_name,
                        "-md", "sha256",
                        "-keyfile", os.path.join(CERTS_DIR, "ca-key.pem"))
        self.assertNotEqual(r.returncode, 0)



class TestCAChimera(unittest.TestCase):
    """Chimera certificate (altextend) tests."""

    @classmethod
    def setUpClass(cls):
        if not _has_altextend():
            raise unittest.SkipTest("altextend not available")
        cls.conf = _tmp("ca_chimera.conf")
        with open(cls.conf, "w", encoding="utf-8", newline="\n") as f:
            f.write(CA_CONF)

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.conf)

    def setUp(self):
        _cleanup(_tmp("index.txt"))
        _touch(_tmp("index.txt"))

    def tearDown(self):
        _cleanup(_tmp("index.txt"))

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_chimera_cert(self):
        """Create chimera (alt-extended) certificate chain."""
        ca_cert_name = "tmp_chimera_ca.pem"
        ca_chimera_name = "tmp_chimera_ca_chimera.pem"
        server_cert_name = "tmp_chimera_server.pem"
        server_chimera_name = "tmp_chimera_server_chimera.pem"
        ca_cert = _tmp(ca_cert_name)
        ca_chimera = _tmp(ca_chimera_name)
        server_csr = _tmp("tmp_chimera_server.csr")
        server_cert = _tmp(server_cert_name)
        server_chimera = _tmp(server_chimera_name)
        self._clean(ca_cert, ca_chimera, server_csr, server_cert,
                    server_chimera)

        r = run_wolfssl("req", "-new", "-x509",
                        "-key", os.path.join(CERTS_DIR, "ca-ecc-key.pem"),
                        "-subj",
                        "O=org-A/C=US/ST=WA/L=Seattle/CN=A/OU=org-unit-A",
                        "-out", ca_cert, "-outform", "PEM")
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("ca", "-altextend", "-in", ca_cert,
                        "-keyfile", os.path.join(CERTS_DIR, "ca-ecc-key.pem"),
                        "-altkey",
                        os.path.join(CERTS_DIR, "ca-mldsa44-key.pem"),
                        "-altpub",
                        os.path.join(CERTS_DIR, "ca-mldsa44-keyPub.pem"),
                        "-out", ca_chimera_name)
        self.assertEqual(r.returncode, 0, r.stderr)

        _cleanup(_tmp("index.txt"))
        _touch(_tmp("index.txt"))

        r = run_wolfssl("req", "-new",
                        "-key", os.path.join(CERTS_DIR, "server-ecc-key.pem"),
                        "-subj",
                        "O=org-B/C=US/ST=WA/L=Seattle/CN=B/OU=org-unit-B",
                        "-out", server_csr, "-outform", "PEM")
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("ca", "-in", server_csr,
                        "-keyfile", os.path.join(CERTS_DIR, "ca-ecc-key.pem"),
                        "-cert", ca_cert, "-out", server_cert_name)
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl(
            "ca", "-altextend", "-in", server_cert,
            "-keyfile", os.path.join(CERTS_DIR, "ca-ecc-key.pem"),
            "-altkey", os.path.join(CERTS_DIR, "ca-mldsa44-key.pem"),
            "-altpub",
            os.path.join(CERTS_DIR, "server-mldsa44-keyPub.pem"),
            "-subjkey", os.path.join(CERTS_DIR, "server-ecc-key.pem"),
            "-cert", ca_chimera, "-out", server_chimera_name)
        self.assertEqual(r.returncode, 0, r.stderr)



class TestCAOutdirPath(unittest.TestCase):
    """Test path concatenation for -out with new_certs_dir."""

    def setUp(self):
        self.outdir = _tmp("outdir-test")
        self.outdir_certs = (self.outdir + "/certs")
        os.makedirs(self.outdir_certs, exist_ok=True)
        self.conf = _tmp("ca_outdir.conf")
        with open(self.conf, "w", encoding="utf-8", newline="\n") as f:
            f.write(CA_OUTDIR_CONF_TEMPLATE.format(
                new_certs_dir=self.outdir_certs))
        _cleanup(_tmp("index.txt"))
        _touch(_tmp("index.txt"))
        self.csr = _tmp("ca_outdir.csr")
        r = run_wolfssl("req", "-key",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj",
                        "/O=wolfSSL/C=US/ST=MT/L=Bozeman/CN=wolfSSL/OU=org-unit",
                        "-out", self.csr)
        assert r.returncode == 0, "CSR creation failed: " + r.stderr

    def tearDown(self):
        _cleanup(self.conf, self.csr, _tmp("index.txt"), self.outdir)

    def test_absolute_out_path(self):
        """Absolute -out path should override new_certs_dir."""
        abs_out = (self.outdir + "/absolute-out.pem")
        self.addCleanup(lambda: _cleanup(abs_out))

        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", abs_out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(abs_out),
                        "File not found at {}".format(abs_out))

        # The file at the absolute location is the correct one;
        # just verify it was created (already checked above).

    @unittest.skipUnless(sys.platform == "win32", "Windows drive-letter test")
    def test_absolute_drive_letter_out_path(self):
        """On Windows, drive-letter paths (C:\\...) are treated as absolute."""
        import tempfile
        abs_out = os.path.join(tempfile.gettempdir(),
                               "wolfclu_test_abs.pem").replace("\\", "/")
        self.addCleanup(lambda: _cleanup(abs_out))

        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", abs_out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(abs_out),
                        "File not found at {}".format(abs_out))

    @unittest.skipUnless(sys.platform == "win32", "Windows backslash test")
    def test_absolute_backslash_out_path(self):
        """On Windows, backslash paths (\\\\...) are treated as absolute."""
        import tempfile
        abs_out = os.path.join(tempfile.gettempdir(),
                               "wolfclu_test_abs_bs.pem")
        self.addCleanup(lambda: _cleanup(abs_out))

        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", abs_out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(abs_out),
                        "File not found at {}".format(abs_out))

    def test_relative_out_path(self):
        """Relative -out path should be appended to new_certs_dir."""
        _cleanup(_tmp("index.txt"))
        _touch(_tmp("index.txt"))

        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", "relative-out.pem")
        self.assertEqual(r.returncode, 0, r.stderr)

        expected = os.path.join(self.outdir_certs, "relative-out.pem")
        self.assertTrue(os.path.isfile(expected),
                        "File not found at {}".format(expected))


@unittest.skipUnless(_has_dilithium(), "ML-DSA (Dilithium) not available")
class TestCAMLDSA(unittest.TestCase):
    """CA signing via wolfCLU_MLDSACertSign (ML-DSA keyfile path).

    Covers the CA-sign branch of wolfCLU_CertSign that calls
    wolfCLU_MLDSACertSign, ensuring the signed cert is actually written to disk
    (regression for the fall-through double-write bug) and is parseable.
    """

    @classmethod
    def setUpClass(cls):
        cls.conf = _tmp("ca_mldsa.conf")
        with open(cls.conf, "w", encoding="utf-8", newline="\n") as f:
            f.write(CA_CONF)

        # wolfCLU ML-DSA keys are private-only in .priv with companion .pub
        cls.mldsa_key = _tmp("ca_mldsa_key")
        r = run_wolfssl("-genkey", "ml-dsa", "-level", "2",
                        "-out", cls.mldsa_key,
                        "-output", "keypair", "-outform", "PEM")
        assert r.returncode == 0, "ML-DSA keygen failed: " + r.stderr
        cls.mldsa_priv = cls.mldsa_key + ".priv"

        # RSA CSR for the CA-sign test (different subject key from CA key)
        cls.rsa_csr = _tmp("ca_mldsa_rsa.csr")
        r = run_wolfssl("req",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj", "/O=wolfSSL/C=US/ST=MT/L=Bozeman/CN=server",
                        "-out", cls.rsa_csr)
        assert r.returncode == 0, "RSA CSR creation failed: " + r.stderr

        # ML-DSA self-signed CA cert used as the CA in the CA-sign test
        cls.mldsa_ca_cert = _tmp("ca_mldsa_selfcert.pem")
        r = run_wolfssl("req", "-new", "-x509",
                        "-key", cls.mldsa_priv,
                        "-subj", "/O=wolfSSL/C=US/ST=MT/L=Bozeman/CN=ML-DSA-CA",
                        "-days", "1",
                        "-out", cls.mldsa_ca_cert)
        assert r.returncode == 0, "ML-DSA CA cert creation failed: " + r.stderr

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.conf, cls.mldsa_key + ".priv", cls.mldsa_key + ".pub",
                 cls.rsa_csr, cls.mldsa_ca_cert, _tmp("index.txt"))

    def setUp(self):
        _cleanup(_tmp("index.txt"))
        _touch(_tmp("index.txt"))

    def tearDown(self):
        _cleanup(_tmp("index.txt"))

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def _assert_issuer_matches_ca(self, ca_cert, issued_cert):
        """Assert that issued_cert's issuer DN equals ca_cert's subject DN."""
        r_ca = run_wolfssl("x509", "-in", ca_cert, "-subject", "-noout")
        self.assertEqual(r_ca.returncode, 0,
                         "Could not read CA subject: " + r_ca.stderr)
        r_is = run_wolfssl("x509", "-in", issued_cert, "-issuer", "-noout")
        self.assertEqual(r_is.returncode, 0,
                         "Could not read issued cert issuer: " + r_is.stderr)
        ca_dn = r_ca.stdout.strip().split("=", 1)[-1].strip()
        is_dn = r_is.stdout.strip().split("=", 1)[-1].strip()
        self.assertEqual(ca_dn, is_dn,
                         "Issuer DN of signed cert does not match CA subject DN")

    def _make_mldsa_ca(self, level, tag):
        """Generate ML-DSA key + self-signed CA cert for level (2/3/5)."""
        key = _tmp("ca_mldsa_l{}_{}".format(level, tag))
        priv = key + ".priv"
        ca_cert = _tmp("ca_mldsa_l{}_{}_ca.pem".format(level, tag))
        self._clean(priv, key + ".pub", ca_cert)
        r = run_wolfssl("-genkey", "ml-dsa", "-level", str(level),
                        "-out", key, "-output", "keypair", "-outform", "PEM")
        self.assertEqual(r.returncode, 0,
                         "ML-DSA level {} keygen failed: {}".format(level,
                             r.stderr))
        r = run_wolfssl("req", "-new", "-x509", "-key", priv,
                        "-subj", "/O=wolfSSL/C=US/CN=ML-DSA-CA-L{}".format(level),
                        "-days", "1", "-out", ca_cert)
        self.assertEqual(r.returncode, 0,
                         "ML-DSA level {} CA cert failed: {}".format(level,
                             r.stderr))
        return priv, ca_cert

    def _ca_sign_rsa_csr(self, priv, ca_cert, out, conf=None, extra=None):
        """Sign the class RSA CSR with the given ML-DSA CA key/cert."""
        args = ["ca", "-config", conf or self.conf,
                "-in", self.rsa_csr, "-out", out,
                "-cert", ca_cert, "-keyfile", priv]
        if extra:
            args.extend(extra)
        return run_wolfssl(*args)

    def test_mldsa_ca_sign(self):
        """wolfCLU_MLDSACertSign: ML-DSA CA signs an RSA CSR; cert is written."""
        out = _tmp("tmp_mldsa_casign.pem")
        self._clean(out)
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.rsa_csr, "-out", out,
                        "-cert", self.mldsa_ca_cert,
                        "-keyfile", self.mldsa_priv)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(out),
                        "Signed cert not written to {}".format(out))
        self.assertGreater(os.path.getsize(out), 0, "Signed cert file is empty")

        # Cert must be parseable as X.509 PEM
        r2 = run_wolfssl("x509", "-in", out, "-text", "-noout")
        self.assertEqual(r2.returncode, 0,
                         "Signed cert not parseable: " + r2.stderr)
        r_v = run_wolfssl("verify", "-CAfile", self.mldsa_ca_cert, out)
        self.assertEqual(r_v.returncode, 0, r_v.stderr + r_v.stdout)
        self._assert_issuer_matches_ca(self.mldsa_ca_cert, out)

    def test_mldsa_ca_sign_level3(self):
        """ML-DSA level 3 CA signs an RSA CSR."""
        priv, ca_cert = self._make_mldsa_ca(3, "sign")
        out = _tmp("tmp_mldsa_l3_casign.pem")
        self._clean(out)
        r = self._ca_sign_rsa_csr(priv, ca_cert, out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(out))
        r_v = run_wolfssl("verify", "-CAfile", ca_cert, out)
        self.assertEqual(r_v.returncode, 0, r_v.stderr + r_v.stdout)

    def test_mldsa_ca_sign_level5(self):
        """ML-DSA level 5 CA signs an RSA CSR."""
        priv, ca_cert = self._make_mldsa_ca(5, "sign")
        out = _tmp("tmp_mldsa_l5_casign.pem")
        self._clean(out)
        r = self._ca_sign_rsa_csr(priv, ca_cert, out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(out))
        r_v = run_wolfssl("verify", "-CAfile", ca_cert, out)
        self.assertEqual(r_v.returncode, 0, r_v.stderr + r_v.stdout)

    @unittest.skipUnless(_can_mldsa_csr(),
                         "ML-DSA CSR generation unavailable in this build "
                         "(req -new); see wolfssl-req(1)")
    def test_mldsa_ca_sign_mldsa_subject_csr(self):
        """ML-DSA CA signs a CSR whose own subject key is ML-DSA.

        Every other ca-sign test feeds an RSA CSR; this drives the ML-DSA
        subject-key branch of wolfCLU_MLDSACertSign (wolfCLU_X509GetMLDSAPubKey
        CSR/BIT-STRING fallback + wolfCLU_MLDSAPubOidToWcType), which the
        RSA-subject CSRs never reach."""
        subj_key = _tmp("ca_mldsa_subj")
        subj_priv = subj_key + ".priv"
        mldsa_csr = _tmp("ca_mldsa_subj.csr")
        out = _tmp("tmp_mldsa_subj_casign.pem")
        self._clean(subj_priv, subj_key + ".pub", mldsa_csr, out)

        # Subject key + CSR are ML-DSA (CSR carries an ML-DSA subjectPublicKey)
        r = run_wolfssl("-genkey", "ml-dsa", "-level", "3",
                        "-out", subj_key, "-output", "keypair", "-outform", "PEM")
        self.assertEqual(r.returncode, 0,
                         "subject ML-DSA keygen failed: " + r.stderr)
        r = run_wolfssl("req", "-new", "-key", subj_priv,
                        "-subj", "/O=wolfSSL/C=US/CN=mldsa-subject",
                        "-out", mldsa_csr)
        self.assertEqual(r.returncode, 0,
                         "ML-DSA CSR creation failed: " + r.stderr)

        # ML-DSA CA signs the ML-DSA-subject CSR
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", mldsa_csr, "-out", out,
                        "-cert", self.mldsa_ca_cert,
                        "-keyfile", self.mldsa_priv)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(out),
                        "Signed cert not written to {}".format(out))
        # The issued cert carries an ML-DSA subject key; `x509 -text` can only
        # render that on builds able to print an ML-DSA SubjectPublicKey.
        if _can_print_mldsa_cert():
            r2 = run_wolfssl("x509", "-in", out, "-text", "-noout")
            self.assertEqual(r2.returncode, 0,
                             "Signed cert not parseable: " + r2.stderr)
        r_v = run_wolfssl("verify", "-CAfile", self.mldsa_ca_cert, out)
        self.assertEqual(r_v.returncode, 0, r_v.stderr + r_v.stdout)
        self._assert_issuer_matches_ca(self.mldsa_ca_cert, out)

    @unittest.skipUnless(_can_mldsa_csr(),
                         "ML-DSA CSR generation unavailable in this build "
                         "(req -new); see wolfssl-req(1)")
    def test_mldsa_ca_selfsign(self):
        """`ca -selfsign` with an ML-DSA key (caCert == x509 in
        wolfCLU_CertSign/wolfCLU_MLDSACertSign).

        This is the only path that reconciles the CA:FALSE default forced
        onto a CSR-supplied x509 with the CA:TRUE/keyUsage re-forced by
        wolfCLU_MLDSACertSign for self-signed CA generation. Every other
        ML-DSA CA test uses `-cert <ca-cert>` (caCert != x509); this drives
        the selfSigned branch instead, where the CSR-loaded cert is both
        signer and subject."""
        subj_key = _tmp("ca_mldsa_selfsign_subj")
        subj_priv = subj_key + ".priv"
        mldsa_csr = _tmp("ca_mldsa_selfsign.csr")
        out = _tmp("tmp_mldsa_selfsign.pem")
        self._clean(subj_priv, subj_key + ".pub", mldsa_csr, out)

        r = run_wolfssl("-genkey", "ml-dsa", "-level", "2",
                        "-out", subj_key, "-output", "keypair", "-outform", "PEM")
        self.assertEqual(r.returncode, 0,
                         "ML-DSA keygen failed: " + r.stderr)
        r = run_wolfssl("req", "-new", "-key", subj_priv,
                        "-subj", "/O=wolfSSL/C=US/CN=mldsa-selfsign",
                        "-out", mldsa_csr)
        self.assertEqual(r.returncode, 0,
                         "ML-DSA CSR creation failed: " + r.stderr)

        # -selfsign: the CSR-loaded cert is signed with its own ML-DSA key
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", mldsa_csr, "-out", out,
                        "-selfsign", "-keyfile", subj_priv)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(out),
                        "Self-signed cert not written to {}".format(out))
        self.assertGreater(os.path.getsize(out), 0,
                           "Self-signed cert file is empty")

        if _can_print_mldsa_cert():
            r2 = run_wolfssl("x509", "-in", out, "-text", "-noout")
            self.assertEqual(r2.returncode, 0,
                             "Self-signed cert not parseable: " + r2.stderr)
            self.assertIn("CA:TRUE", r2.stdout,
                         "Self-signed ML-DSA CA cert must carry CA:TRUE "
                         "(basicConstraints round-trip regression)")

        r_v = run_wolfssl("verify", "-CAfile", out, out)
        self.assertEqual(r_v.returncode, 0, r_v.stderr + r_v.stdout)

        subj = run_wolfssl("x509", "-in", out, "-subject", "-noout")
        issu = run_wolfssl("x509", "-in", out, "-issuer", "-noout")
        self.assertEqual(subj.stdout.strip(), issu.stdout.strip(),
                         "subject and issuer mismatch on self-signed cert")

    def test_mldsa_issued_cert_wrong_ca_fails(self):
        """A cert signed by ML-DSA-CA-1 is rejected when CA-2 is the trust
        anchor.  This exercises the issuer-DN check in wolfCLU_x509Verify
        (wolfSSL_X509_NAME_cmp) for the CA-signed (not self-signed) path."""
        priv1, ca1_cert = self._make_mldsa_ca(2, "wrongca1")
        priv2, ca2_cert = self._make_mldsa_ca(2, "wrongca2")
        out = _tmp("tmp_mldsa_wrongca_issued.pem")
        self._clean(out, priv2, priv2.replace(".priv", ".pub"), ca2_cert)
        r = self._ca_sign_rsa_csr(priv1, ca1_cert, out)
        self.assertEqual(r.returncode, 0, "CA-1 sign failed: " + r.stderr)
        r_v = run_wolfssl("verify", "-CAfile", ca2_cert, out)
        self.assertNotEqual(r_v.returncode, 0,
                            "Verify should fail: cert signed by CA-1, not CA-2")

    def test_mldsa_ca_sign_config_private_key(self):
        """ML-DSA CA key loaded from config private_key (no -keyfile)."""
        mldsa_conf = _tmp("ca_mldsa_privkey.conf")
        out = _tmp("tmp_mldsa_config_key.pem")
        self._clean(mldsa_conf, out)
        conf_body = CA_CONF.replace(
            f"private_key = {_CERTS}/ca-key.pem",
            f"private_key = {self.mldsa_priv}")
        with open(mldsa_conf, "w", encoding="utf-8", newline="\n") as f:
            f.write(conf_body)
        r = run_wolfssl("ca", "-config", mldsa_conf,
                        "-in", self.rsa_csr, "-out", out,
                        "-cert", self.mldsa_ca_cert)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(out))
        r_v = run_wolfssl("verify", "-CAfile", self.mldsa_ca_cert, out)
        self.assertEqual(r_v.returncode, 0, r_v.stderr + r_v.stdout)
        self._assert_issuer_matches_ca(self.mldsa_ca_cert, out)

    def test_mldsa_ca_sign_der(self):
        """ML-DSA CA signing honors -outform der."""
        out = _tmp("tmp_mldsa_casign.der")
        self._clean(out)
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.rsa_csr, "-out", out,
                        "-outform", "der",
                        "-cert", self.mldsa_ca_cert,
                        "-keyfile", self.mldsa_priv)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(out),
                        "Signed cert not written to {}".format(out))
        self.assertGreater(os.path.getsize(out), 0, "Signed cert file is empty")

        r2 = run_wolfssl("x509", "-in", out, "-inform", "der",
                         "-text", "-noout")
        self.assertEqual(r2.returncode, 0,
                         "DER signed cert not parseable: " + r2.stderr)
        r_v = run_wolfssl("verify", "-CAfile", self.mldsa_ca_cert, out)
        self.assertEqual(r_v.returncode, 0, r_v.stderr + r_v.stdout)

    def test_mldsa_ca_missing_companion_pub_fails(self):
        """ca -keyfile with no companion .pub fails cleanly."""
        key = _tmp("ca_mldsa_nopub")
        self._clean(key + ".priv", key + ".pub")
        r = run_wolfssl("-genkey", "ml-dsa", "-level", "2",
                        "-out", key, "-output", "keypair", "-outform", "PEM")
        if r.returncode != 0:
            self.skipTest("keygen failed: " + r.stderr)
        os.remove(key + ".pub")
        out = _tmp("tmp_nopub.pem")
        self._clean(out)
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.rsa_csr, "-out", out,
                        "-cert", self.mldsa_ca_cert,
                        "-keyfile", key + ".priv")
        self.assertNotEqual(r.returncode, 0,
                           "missing companion .pub should fail")
        self.assertIn("unable to open public key",
                      (r.stdout + r.stderr).lower(),
                      "expected a public-key companion error")

    def test_mldsa_ca_missing_out_fails(self):
        """Omitting -out on the ML-DSA CA sign path must fail cleanly."""
        out = _tmp("tmp_no_out.pem")
        self._clean(out)
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.rsa_csr,
                        "-cert", self.mldsa_ca_cert,
                        "-keyfile", self.mldsa_priv)
        self.assertNotEqual(r.returncode, 0,
                           "ML-DSA CA sign without -out should fail")
        msg = (r.stdout + r.stderr).lower()
        self.assertTrue(
            "no output file specified" in msg
            or "could not open output file" in msg,
            "expected an output-path error, got: " + msg)
        self.assertFalse(os.path.isfile(out) and os.path.getsize(out) > 0,
                         "no cert should be written without -out")

    def test_mldsa_ca_key_cert_mismatch_fails(self):
        """Mismatched -keyfile vs -cert is rejected."""
        other = _tmp("ca_mldsa_other")
        self._clean(other + ".priv", other + ".pub")
        r = run_wolfssl("-genkey", "ml-dsa", "-level", "2",
                        "-out", other, "-output", "keypair", "-outform", "PEM")
        if r.returncode != 0:
            self.skipTest("keygen failed: " + r.stderr)
        out = _tmp("tmp_mismatch.pem")
        self._clean(out)
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.rsa_csr, "-out", out,
                        "-cert", self.mldsa_ca_cert,
                        "-keyfile", other + ".priv")
        self.assertNotEqual(r.returncode, 0,
                           "mismatched CA key should fail")
        self.assertIn("does not match",
                      (r.stdout + r.stderr).lower(),
                      "expected private-key mismatch error")

    def test_mldsa_ca_sign_pkcs8_pem_key(self):
        """ca -keyfile accepts PKCS#8 PEM ML-DSA keys (PEM-to-DER fallback)."""
        pkcs8_key = _tmp("ca_mldsa_pkcs8.pem")
        pkcs8_pub = _tmp("ca_mldsa_pkcs8Pub.pem")
        out = _tmp("tmp_mldsa_pkcs8_casign.pem")
        self._clean(pkcs8_key, pkcs8_pub, out)

        shutil.copyfile(self.mldsa_priv, pkcs8_key)
        shutil.copyfile(self.mldsa_key + ".pub", pkcs8_pub)

        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.rsa_csr, "-out", out,
                        "-cert", self.mldsa_ca_cert,
                        "-keyfile", pkcs8_key)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(out),
                        "Signed cert not written for PKCS#8 PEM key")
        r_v = run_wolfssl("verify", "-CAfile", self.mldsa_ca_cert, out)
        self.assertEqual(r_v.returncode, 0, r_v.stderr + r_v.stdout)

    def test_mldsa_ca_sign_preserves_ip_san(self):
        """ML-DSA CA signing preserves IP SAN entries from the CSR."""
        san_conf = _tmp("ca_mldsa_ip_san.conf")
        csr = _tmp("ca_mldsa_ip_san.csr")
        out = _tmp("tmp_mldsa_ip_san.pem")
        self._clean(san_conf, csr, out)

        with open(san_conf, "w", encoding="utf-8", newline="\n") as f:
            f.write("""\
[ req ]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no
[ req_dn ]
C = US
CN = ip-san-test
[ v3_req ]
subjectAltName = @alt_names
[ alt_names ]
IP.1 = 192.168.1.42
DNS.1 = ip-san.example
""")

        r = run_wolfssl("req", "-config", san_conf, "-new",
                        "-extensions", "v3_req",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj", "/C=US/CN=ip-san-test",
                        "-out", csr)
        self.assertEqual(r.returncode, 0, "CSR with IP SAN failed: " + r.stderr)

        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", csr, "-out", out,
                        "-cert", self.mldsa_ca_cert,
                        "-keyfile", self.mldsa_priv)
        self.assertEqual(r.returncode, 0, r.stderr)

        r2 = run_wolfssl("x509", "-in", out, "-text", "-noout")
        self.assertEqual(r2.returncode, 0, r2.stderr)
        text = r2.stdout
        self.assertIn("192.168.1.42", text,
                      "IP SAN missing from signed cert")
        self.assertIn("ip-san.example", text,
                      "DNS SAN missing from signed cert")

    @unittest.skipUnless(_can_print_mldsa_cert(),
                         "build cannot print ML-DSA certs (x509 -text)")
    def test_mldsa_selfcert_is_ca(self):
        """wolfCLU_MakeMLDSASelfSignedCert: self-signed cert must have isCA=1.

        Exercises the MEDIUM-3 fix: the self-signed path hardcodes isCA=1
        regardless of CSR flags (CSR does not carry basicConstraints by
        default, so isCA would have been 0 before the fix).
        """
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            key = os.path.join(d, "k")
            cert = os.path.join(d, "c.pem")
            r = run_wolfssl("-genkey", "ml-dsa", "-level", "2",
                            "-out", key, "-output", "keypair",
                            "-outform", "PEM")
            self.assertEqual(r.returncode, 0,
                             "ml-dsa keygen failed: " + r.stderr)
            r = run_wolfssl("req", "-x509", "-key", key + ".priv",
                            "-subj", "/CN=ca-isca-test",
                            "-days", "1", "-out", cert)
            self.assertEqual(r.returncode, 0,
                             "ml-dsa self-signed cert failed: " + r.stderr)

            r = run_wolfssl("x509", "-in", cert, "-text", "-noout")
            self.assertEqual(r.returncode, 0, r.stderr)
            text = r.stdout + r.stderr
            self.assertIn("CA:TRUE", text,
                          "Self-signed ML-DSA cert must set isCA=1 "
                          "(CA:TRUE missing from -text output)")

    def test_mldsa_verify_rejects_non_ca_cafile(self):
        """A -CAfile that is an ML-DSA leaf (basicConstraints CA:FALSE) must be
        rejected on the ML-DSA verify fast path, mirroring the CA:TRUE
        requirement X509_verify_cert enforces for RSA/ECDSA. Exercises the
        isCA gate in wolfCLU_x509Verify (clu_x509_verify.c). The bundle scan
        skips a non-CA cert rather than hard-failing on it, so it can keep
        looking for a root elsewhere in the bundle; with only the CA:FALSE
        leaf present, no root is ever found."""
        leaf = _tmp("tmp_mldsa_leaf_cafalse.pem")
        self._clean(leaf)
        # ML-DSA CA signs the RSA CSR with usr_cert (basicConstraints CA:FALSE),
        # producing an ML-DSA-signed leaf that is explicitly not a CA.
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.rsa_csr, "-out", leaf,
                        "-extensions", "usr_cert",
                        "-cert", self.mldsa_ca_cert,
                        "-keyfile", self.mldsa_priv)
        self.assertEqual(r.returncode, 0, r.stderr)
        # Precondition: the signed leaf must not assert CA:TRUE.
        rt = run_wolfssl("x509", "-in", leaf, "-text", "-noout")
        self.assertEqual(rt.returncode, 0, rt.stderr)
        self.assertNotIn("CA:TRUE", rt.stdout,
                         "precondition: signed leaf must not be a CA")
        # Using that non-CA leaf as the trust anchor must be rejected.
        rv = run_wolfssl("verify", "-CAfile", leaf, leaf)
        self.assertNotEqual(rv.returncode, 0,
                            "ML-DSA verify must reject a CA:FALSE -CAfile")
        self.assertIn("does not contain a self-signed root CA",
                      rv.stdout + rv.stderr,
                      "expected rejection for lacking a root CA")

    def test_mldsa_ca_sign_rejects_csr_embedded_ca_true(self):
        """Regression test: a CSR with basicConstraints=CA:TRUE must not be issued
        as a CA when signed by an ML-DSA CA without an explicit -extensions override."""
        csr_conf = _tmp("ca_mldsa_evil_csr.conf")
        evil_csr = _tmp("ca_mldsa_evil.csr")
        out = _tmp("tmp_mldsa_evil_issued.pem")
        self._clean(csr_conf, evil_csr, out)

        with open(csr_conf, "w", encoding="utf-8", newline="\n") as f:
            f.write(
                "[ req ]\n"
                "distinguished_name = req_dn\n"
                "x509_extensions = v3_req\n"
                "prompt = no\n\n"
                "[ req_dn ]\n"
                "countryName = US\n"
                "CN = evil-csr\n\n"
                "[ v3_req ]\n"
                "basicConstraints = critical,CA:TRUE\n"
            )

        # CSR embeds CA:TRUE in basicConstraints.
        r = run_wolfssl("req", "-new",
                        "-key", os.path.join(CERTS_DIR, "server-key.pem"),
                        "-config", csr_conf,
                        "-out", evil_csr)
        self.assertEqual(r.returncode, 0, "evil CSR creation failed: " + r.stderr)

        # Sign with ML-DSA CA, no -extensions: CSR's CA:TRUE must not survive.
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", evil_csr, "-out", out,
                        "-cert", self.mldsa_ca_cert,
                        "-keyfile", self.mldsa_priv)
        self.assertEqual(r.returncode, 0, r.stderr)

        rt = run_wolfssl("x509", "-in", out, "-text", "-noout")
        self.assertEqual(rt.returncode, 0, rt.stderr)
        self.assertNotIn("CA:TRUE", rt.stdout + rt.stderr,
                         "CSR-embedded CA:TRUE must not survive ML-DSA CA "
                         "signing without an explicit -extensions override")

    @unittest.skipUnless(_can_mldsa_csr(),
                         "ML-DSA CSR generation unavailable in this build "
                         "(req -new); see wolfssl-req(1)")
    def test_mldsa_verify_partial_chain_intermediate(self):
        """An ML-DSA intermediate CA (CA:TRUE but not self-signed) is rejected
        as a -CAfile without -partial_chain and accepted with it. Exercises the
        self-signed-root requirement and its -partial_chain bypass in
        wolfCLU_x509Verify (clu_x509_verify.c)."""
        # Root ML-DSA CA (self-signed, CA:TRUE).
        root_priv, root_cert = self._make_mldsa_ca(2, "pcroot")

        # Config whose v3_ca section asserts CA:TRUE for the intermediate.
        ca_ext_conf = _tmp("ca_mldsa_v3ca.conf")
        self._clean(ca_ext_conf)
        with open(ca_ext_conf, "w", encoding="utf-8", newline="\n") as f:
            f.write(CA_CONF + "\n[ v3_ca ]\nbasicConstraints=critical,CA:TRUE\n")

        # Intermediate: ML-DSA key + CSR signed by the root with CA:TRUE.
        int_key = _tmp("ca_mldsa_int")
        int_priv = int_key + ".priv"
        int_csr = _tmp("ca_mldsa_int.csr")
        int_cert = _tmp("ca_mldsa_int.pem")
        leaf = _tmp("tmp_mldsa_pc_leaf.pem")
        self._clean(int_priv, int_key + ".pub", int_csr, int_cert, leaf)

        r = run_wolfssl("-genkey", "ml-dsa", "-level", "2", "-out", int_key,
                        "-output", "keypair", "-outform", "PEM")
        self.assertEqual(r.returncode, 0,
                         "intermediate ML-DSA keygen failed: " + r.stderr)
        r = run_wolfssl("req", "-new", "-key", int_priv,
                        "-subj", "/O=wolfSSL/C=US/CN=ML-DSA-Intermediate",
                        "-out", int_csr)
        self.assertEqual(r.returncode, 0,
                         "intermediate CSR creation failed: " + r.stderr)
        _cleanup(_tmp("index.txt"))
        _touch(_tmp("index.txt"))
        r = run_wolfssl("ca", "-config", ca_ext_conf,
                        "-in", int_csr, "-out", int_cert,
                        "-extensions", "v3_ca",
                        "-cert", root_cert, "-keyfile", root_priv)
        self.assertEqual(r.returncode, 0,
                         "root signing of intermediate failed: " + r.stderr)
        # Precondition: intermediate must assert CA:TRUE and not be self-signed.
        # The intermediate has an ML-DSA subject key, so this print-based check
        # only runs where `x509 -text` can render an ML-DSA SubjectPublicKey;
        # the verify assertions below are the substantive part of the test.
        if _can_print_mldsa_cert():
            rt = run_wolfssl("x509", "-in", int_cert, "-text", "-noout")
            self.assertEqual(rt.returncode, 0, rt.stderr)
            self.assertIn("CA:TRUE", rt.stdout,
                          "precondition: intermediate must be a CA")

        # Leaf signed by the intermediate (ML-DSA-signed, issuer=intermediate).
        _cleanup(_tmp("index.txt"))
        _touch(_tmp("index.txt"))
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.rsa_csr, "-out", leaf,
                        "-cert", int_cert, "-keyfile", int_priv)
        self.assertEqual(r.returncode, 0,
                         "intermediate signing of leaf failed: " + r.stderr)

        # Without -partial_chain: a non-self-signed CA must be rejected.
        rv = run_wolfssl("verify", "-CAfile", int_cert, leaf)
        self.assertNotEqual(rv.returncode, 0,
                            "non-root ML-DSA CA must fail without -partial_chain")
        self.assertIn("does not contain a self-signed root CA",
                      rv.stdout + rv.stderr,
                      "expected a non-root-CA rejection")
        # With -partial_chain: the intermediate is accepted as the anchor.
        rv = run_wolfssl("verify", "-partial_chain", "-CAfile", int_cert, leaf)
        self.assertEqual(rv.returncode, 0, rv.stderr + rv.stdout)

        # bundle order [intermediate, root] should still succeed.
        bundle = _tmp("ca_mldsa_int_then_root.pem")
        self._clean(bundle)
        with open(bundle, "w", encoding="utf-8", newline="\n") as out:
            for path in (int_cert, root_cert):
                with open(path, encoding="utf-8") as f:
                    out.write(f.read())
        rv = run_wolfssl("verify", "-CAfile", bundle, leaf)
        self.assertEqual(rv.returncode, 0, rv.stderr + rv.stdout)


if __name__ == "__main__":
    test_main()

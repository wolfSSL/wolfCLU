#!/usr/bin/env python3
"""Tests for wolfssl ca (converted from x509-ca-test.sh)."""

import os
import shutil
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import WOLFSSL_BIN, CERTS_DIR, run_wolfssl

_SKIP_WIN = sys.platform == "win32"
_WIN_REASON = "CA config file paths not supported on Windows UNC shares"

CA_CONF = """\
[ ca ]
default_ca = CA_default

[ usr_cert ]

basicConstraints=CA:FALSE
nsComment            = "wolfSSL Generated Certificate using wolfSSL command line utility."
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

[ CA_default ]

dir = ./certs
database = ./index.txt
new_certs_dir = ./

certificate = $dir/ca-cert.pem
private_key = $dir/ca-key.pem
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

CA_2_CONF = """\
[ ca ]
default_ca = CA_default

[ usr_cert ]

basicConstraints=CA:FALSE
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

[ CA_default ]

dir = ./certs
database = ./index.txt
new_certs_dir = ./
certificate = $dir/ca-cert.pem
private_key = $dir/ca-key.pem
RANDFILE = ./rand-file-test
serial   = ./serial-file-test
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

CA_MATCH_CONF = """\
[ ca ]
default_ca = CA_default

[ usr_cert ]

basicConstraints=CA:FALSE

[ CA_default ]

dir = ./certs
database = ./index.txt
new_certs_dir = ./

certificate = $dir/ca-cert.pem
private_key = $dir/ca-key.pem
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

crl_dir    = ./crls-test
crlnumber  = ./crlnumber-test
crl        = ./certs/crl.pem
"""

CA_CRL_CONF = """\
[ ca ]
default_ca = CA_default

[ usr_cert ]

basicConstraints=CA:FALSE

[ CA_default ]

dir = ./certs
database = ./index.txt
new_certs_dir = ./

certificate = $dir/ca-cert.pem
private_key = $dir/ca-key.pem
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

crl_dir    = ./crls-test
crlnumber  = ./crlnumber-test
crl        = ./certs/crl.pem
"""

CA_OUTDIR_CONF_TEMPLATE = """\
[ ca ]
default_ca = CA_default

[ CA_default ]
dir = ./certs
database = ./index.txt
new_certs_dir = {new_certs_dir}
certificate = $dir/ca-cert.pem
private_key = $dir/ca-key.pem
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


def _cleanup(*files):
    for f in files:
        if os.path.isdir(f):
            shutil.rmtree(f, ignore_errors=True)
        elif os.path.exists(f):
            os.remove(f)


def _touch(path):
    with open(path, "a"):
        pass


def _has_altextend():
    """Check whether chimera cert (altextend) support is available."""
    r = run_wolfssl("ca", "-help")
    combined = r.stdout + r.stderr
    return "altextend" in combined


class TestCAHelp(unittest.TestCase):
    """ca -h and -help should succeed."""

    def test_ca_h(self):
        r = run_wolfssl("ca", "-h")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_ca_help(self):
        r = run_wolfssl("ca", "-help")
        self.assertEqual(r.returncode, 0, r.stderr)


@unittest.skipIf(_SKIP_WIN, _WIN_REASON)
class TestCASelfSign(unittest.TestCase):
    """ca -selfsign tests."""

    @classmethod
    def setUpClass(cls):
        cls.conf = "ca_selfsign.conf"
        with open(cls.conf, "w") as f:
            f.write(CA_CONF)
        _touch("index.txt")
        cls.csr = "ca_selfsign.csr"
        r = run_wolfssl("req", "-key",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj",
                        "/O=wolfSSL/C=US/ST=MT/L=Bozeman/CN=wolfSSL/OU=org-unit",
                        "-out", cls.csr)
        assert r.returncode == 0, "CSR creation failed: " + r.stderr

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.conf, cls.csr, "index.txt")

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_bad_config_fails(self):
        """Reading nonexistent config file should fail."""
        r = run_wolfssl("ca", "-config", "ca-example.conf",
                        "-in", self.csr, "-out", "tmp_bad.pem",
                        "-md", "sha256", "-selfsign",
                        "-keyfile", os.path.join(CERTS_DIR, "ca-key.pem"))
        self._clean("tmp_bad.pem")
        self.assertNotEqual(r.returncode, 0)

    def test_selfsign_key_mismatch_fails(self):
        """selfsign with wrong key (ca-key vs server-key CSR) should fail."""
        out = "tmp_selfsign_mm.pem"
        self._clean(out)
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", out,
                        "-md", "sha256", "-selfsign",
                        "-keyfile", os.path.join(CERTS_DIR, "ca-key.pem"))
        self.assertNotEqual(r.returncode, 0)

    def test_selfsign_correct_key(self):
        """selfsign with matching key succeeds, subject == issuer."""
        out = "test_ca_selfsign.pem"
        self._clean(out)
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", out,
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
        out = "test_ca_selfsign_vf.pem"
        self._clean(out)
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", out,
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


@unittest.skipIf(_SKIP_WIN, _WIN_REASON)
class TestCACreateAndVerify(unittest.TestCase):
    """ca certificate creation and verification."""

    @classmethod
    def setUpClass(cls):
        cls.conf = "ca_create.conf"
        with open(cls.conf, "w") as f:
            f.write(CA_CONF)
        _cleanup("index.txt")
        _touch("index.txt")
        cls.csr = "ca_create.csr"
        r = run_wolfssl("req", "-key",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj",
                        "/O=wolfSSL/C=US/ST=MT/L=Bozeman/CN=wolfSSL/OU=org-unit",
                        "-out", cls.csr)
        assert r.returncode == 0, "CSR creation failed: " + r.stderr

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.conf, cls.csr, "index.txt")

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_create_and_verify(self):
        """Create cert and verify with CA."""
        out = "test_ca_cv.pem"
        self._clean(out)
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)

        r2 = run_wolfssl("verify", "-CAfile",
                         os.path.join(CERTS_DIR, "ca-cert.pem"), out)
        self.assertEqual(r2.returncode, 0, r2.stderr)


@unittest.skipIf(_SKIP_WIN, _WIN_REASON)
class TestCAOverrideConfig(unittest.TestCase):
    """Override config options with command-line flags."""

    @classmethod
    def setUpClass(cls):
        cls.conf = "ca_override.conf"
        with open(cls.conf, "w") as f:
            f.write(CA_CONF)
        _cleanup("index.txt")
        _touch("index.txt")
        cls.csr = "ca_override.csr"
        r = run_wolfssl("req", "-key",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj",
                        "/O=wolfSSL/C=US/ST=MT/L=Bozeman/CN=wolfSSL/OU=org-unit",
                        "-out", cls.csr)
        assert r.returncode == 0, "CSR creation failed: " + r.stderr

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.conf, cls.csr, "index.txt")

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_override_extensions_md_days_cert_keyfile(self):
        """Override -extensions, -md, -days, -cert, -keyfile."""
        out = "test_ca_override.pem"
        self._clean(out)
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", out,
                        "-extensions", "usr_cert",
                        "-md", "sha512",
                        "-days", "3650",
                        "-cert",
                        os.path.join(CERTS_DIR, "ca-ecc-cert.pem"),
                        "-keyfile",
                        os.path.join(CERTS_DIR, "ca-ecc-key.pem"))
        self.assertEqual(r.returncode, 0, r.stderr)


@unittest.skipIf(_SKIP_WIN, _WIN_REASON)
class TestCAKeyMismatch(unittest.TestCase):
    """ca with mismatched key should fail."""

    @classmethod
    def setUpClass(cls):
        cls.conf = "ca_keymm.conf"
        with open(cls.conf, "w") as f:
            f.write(CA_CONF)
        _cleanup("index.txt")
        _touch("index.txt")
        cls.csr = "ca_keymm.csr"
        r = run_wolfssl("req", "-key",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj",
                        "/O=wolfSSL/C=US/ST=MT/L=Bozeman/CN=wolfSSL/OU=org-unit",
                        "-out", cls.csr)
        assert r.returncode == 0, "CSR creation failed: " + r.stderr

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.conf, cls.csr, "index.txt")

    def test_key_mismatch(self):
        out = "test_ca_km.pem"
        self.addCleanup(lambda: _cleanup(out))
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", out,
                        "-keyfile",
                        os.path.join(CERTS_DIR, "ecc-key.pem"))
        self.assertNotEqual(r.returncode, 0)


@unittest.skipIf(_SKIP_WIN, _WIN_REASON)
class TestCAUniqueSubjectAndSerial(unittest.TestCase):
    """unique_subject enforcement and serial number handling."""

    def setUp(self):
        self.conf = "ca_uniq.conf"
        with open(self.conf, "w") as f:
            f.write(CA_2_CONF)
        _cleanup("index.txt", "serial-file-test", "rand-file-test")
        _touch("index.txt")
        with open("serial-file-test", "w") as f:
            f.write("01\n")
        _touch("rand-file-test")
        self.csr = "ca_uniq.csr"
        r = run_wolfssl("req", "-key",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj",
                        "/O=wolfSSL/C=US/ST=MT/L=Bozeman/CN=wolfSSL/OU=org-unit",
                        "-out", self.csr)
        assert r.returncode == 0, "CSR creation failed: " + r.stderr

    def tearDown(self):
        _cleanup(self.conf, self.csr, "index.txt",
                 "serial-file-test", "rand-file-test")

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_unique_subject_fail(self):
        """Creating same subject twice with unique_subject=yes should fail."""
        out = "test_ca_uniq.pem"
        self._clean(out)
        # First cert succeeds
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        # Second with same subject should fail
        r2 = run_wolfssl("ca", "-config", self.conf,
                         "-in", self.csr, "-out", out)
        self.assertNotEqual(r2.returncode, 0)

    def test_serial_number(self):
        """First cert should have serial=01."""
        out = "test_ca_serial.pem"
        self._clean(out)
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)

        r2 = run_wolfssl("x509", "-in", out, "-noout", "-serial")
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertEqual(r2.stdout.strip(), "serial=01")

    def test_serial_increment(self):
        """Second cert should have serial=02."""
        out1 = "test_ca_serial1.pem"
        out2 = "test_ca_serial2.pem"
        self._clean(out1, out2)

        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", out1)
        self.assertEqual(r.returncode, 0, r.stderr)

        # Reset index for unique_subject
        _cleanup("index.txt")
        _touch("index.txt")

        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", out2)
        self.assertEqual(r.returncode, 0, r.stderr)

        r2 = run_wolfssl("x509", "-in", out2, "-noout", "-serial")
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertEqual(r2.stdout.strip(), "serial=02")

    def test_rand_file_written(self):
        """Rand file should be 256 bytes after cert creation."""
        out = "test_ca_rand.pem"
        self._clean(out)
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile("rand-file-test"))
        size = os.path.getsize("rand-file-test")
        self.assertEqual(size, 256,
                         "rand file is {} bytes, expected 256".format(size))

    def test_rand_file_changes(self):
        """Rand file should change between cert creations."""
        out1 = "test_ca_randc1.pem"
        out2 = "test_ca_randc2.pem"
        self._clean(out1, out2)

        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", out1)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open("rand-file-test", "rb") as f:
            rand1 = f.read()

        _cleanup("index.txt")
        _touch("index.txt")

        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", out2)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open("rand-file-test", "rb") as f:
            rand2 = f.read()

        self.assertNotEqual(rand1, rand2, "rand file did not change")


@unittest.skipIf(_SKIP_WIN, _WIN_REASON)
class TestCAPolicy(unittest.TestCase):
    """Policy section enforcement."""

    @classmethod
    def setUpClass(cls):
        cls.conf = "ca_policy.conf"
        cls.match_conf = "ca_policy_match.conf"
        with open(cls.conf, "w") as f:
            f.write(CA_CONF)
        with open(cls.match_conf, "w") as f:
            f.write(CA_MATCH_CONF)

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.conf, cls.match_conf)

    def setUp(self):
        _cleanup("index.txt")
        _touch("index.txt")

    def tearDown(self):
        _cleanup("index.txt")

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_no_common_name_supplied_fails(self):
        """CSR without commonName should fail when policy requires 'supplied'."""
        csr = "ca_pol_nocn.csr"
        out = "ca_pol_nocn.pem"
        self._clean(csr, out)
        r = run_wolfssl("req", "-key",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj", "O=wolfSSL/C=US/ST=MT/L=Bozeman/OU=org-unit",
                        "-out", csr)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", csr, "-out", out,
                        "-md", "sha256",
                        "-keyfile", os.path.join(CERTS_DIR, "ca-key.pem"))
        self.assertNotEqual(r.returncode, 0)

    def test_no_common_name_match_fails(self):
        """CSR without commonName should also fail with match policy."""
        csr = "ca_pol_nocnm.csr"
        out = "ca_pol_nocnm.pem"
        self._clean(csr, out)
        r = run_wolfssl("req", "-key",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj", "O=wolfSSL/C=US/ST=MT/L=Bozeman/OU=org-unit",
                        "-out", csr)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run_wolfssl("ca", "-config", self.match_conf,
                        "-in", csr, "-out", out,
                        "-md", "sha256",
                        "-keyfile", os.path.join(CERTS_DIR, "ca-key.pem"))
        self.assertNotEqual(r.returncode, 0)

    def test_common_name_supplied_succeeds(self):
        """CSR with commonName should pass policy_any."""
        csr = "ca_pol_cn.csr"
        out = "ca_pol_cn.pem"
        self._clean(csr, out)
        r = run_wolfssl("req", "-key",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj",
                        "O=Sawtooth/CN=www.wolfclu.com/C=US/ST=MT/L=Bozeman/OU=org-unit",
                        "-out", csr)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", csr, "-out", out,
                        "-md", "sha256",
                        "-keyfile", os.path.join(CERTS_DIR, "ca-key.pem"))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_common_name_mismatch_fails(self):
        """CSR with non-matching commonName should fail policy_match."""
        csr = "ca_pol_cnmm.csr"
        out = "ca_pol_cnmm.pem"
        self._clean(csr, out)
        r = run_wolfssl("req", "-key",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj",
                        "O=Sawtooth/CN=www.wolfclu.com/C=US/ST=MT/L=Bozeman/OU=org-unit",
                        "-out", csr)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run_wolfssl("ca", "-config", self.match_conf,
                        "-in", csr, "-out", out,
                        "-md", "sha256",
                        "-keyfile", os.path.join(CERTS_DIR, "ca-key.pem"))
        self.assertNotEqual(r.returncode, 0)


@unittest.skipIf(_SKIP_WIN, _WIN_REASON)
class TestCAChimera(unittest.TestCase):
    """Chimera certificate (altextend) tests."""

    @classmethod
    def setUpClass(cls):
        if not _has_altextend():
            raise unittest.SkipTest("altextend not available")
        cls.conf = "ca_chimera.conf"
        with open(cls.conf, "w") as f:
            f.write(CA_CONF)

    @classmethod
    def tearDownClass(cls):
        _cleanup(cls.conf)

    def setUp(self):
        _cleanup("index.txt")
        _touch("index.txt")

    def tearDown(self):
        _cleanup("index.txt")

    def _clean(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: _cleanup(p))

    def test_chimera_cert(self):
        """Create chimera (alt-extended) certificate chain."""
        ca_cert = "tmp_chimera_ca.pem"
        ca_chimera = "tmp_chimera_ca_chimera.pem"
        server_csr = "tmp_chimera_server.csr"
        server_cert = "tmp_chimera_server.pem"
        server_chimera = "tmp_chimera_server_chimera.pem"
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
                        "-out", ca_chimera)
        self.assertEqual(r.returncode, 0, r.stderr)

        _cleanup("index.txt")
        _touch("index.txt")

        r = run_wolfssl("req", "-new",
                        "-key", os.path.join(CERTS_DIR, "server-ecc-key.pem"),
                        "-subj",
                        "O=org-B/C=US/ST=WA/L=Seattle/CN=B/OU=org-unit-B",
                        "-out", server_csr, "-outform", "PEM")
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("ca", "-in", server_csr,
                        "-keyfile", os.path.join(CERTS_DIR, "ca-ecc-key.pem"),
                        "-cert", ca_cert, "-out", server_cert)
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl(
            "ca", "-altextend", "-in", server_cert,
            "-keyfile", os.path.join(CERTS_DIR, "ca-ecc-key.pem"),
            "-altkey", os.path.join(CERTS_DIR, "ca-mldsa44-key.pem"),
            "-altpub",
            os.path.join(CERTS_DIR, "server-mldsa44-keyPub.pem"),
            "-subjkey", os.path.join(CERTS_DIR, "server-ecc-key.pem"),
            "-cert", ca_chimera, "-out", server_chimera)
        self.assertEqual(r.returncode, 0, r.stderr)


@unittest.skipIf(_SKIP_WIN, _WIN_REASON)
class TestCAOutdirPath(unittest.TestCase):
    """Test path concatenation for -out with new_certs_dir."""

    def setUp(self):
        self.outdir = "outdir-test"
        self.outdir_certs = os.path.join(self.outdir, "certs")
        os.makedirs(self.outdir_certs, exist_ok=True)
        self.conf = "ca_outdir.conf"
        with open(self.conf, "w") as f:
            f.write(CA_OUTDIR_CONF_TEMPLATE.format(
                new_certs_dir="./" + os.path.join(self.outdir, "certs")))
        _cleanup("index.txt")
        _touch("index.txt")
        self.csr = "ca_outdir.csr"
        r = run_wolfssl("req", "-key",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-subj",
                        "/O=wolfSSL/C=US/ST=MT/L=Bozeman/CN=wolfSSL/OU=org-unit",
                        "-out", self.csr)
        assert r.returncode == 0, "CSR creation failed: " + r.stderr

    def tearDown(self):
        _cleanup(self.conf, self.csr, "index.txt", self.outdir)

    def test_absolute_out_path(self):
        """Absolute -out path should override new_certs_dir."""
        abs_out = os.path.abspath(
            os.path.join(self.outdir, "absolute-out.pem"))
        self.addCleanup(lambda: _cleanup(abs_out))

        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", abs_out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(abs_out),
                        "File not found at {}".format(abs_out))

        # The file at the absolute location is the correct one;
        # just verify it was created (already checked above).

    def test_relative_out_path(self):
        """Relative -out path should be appended to new_certs_dir."""
        _cleanup("index.txt")
        _touch("index.txt")

        r = run_wolfssl("ca", "-config", self.conf,
                        "-in", self.csr, "-out", "relative-out.pem")
        self.assertEqual(r.returncode, 0, r.stderr)

        expected = os.path.join(self.outdir_certs, "relative-out.pem")
        self.assertTrue(os.path.isfile(expected),
                        "File not found at {}".format(expected))


if __name__ == "__main__":
    unittest.main()

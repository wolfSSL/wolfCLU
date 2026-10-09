#!/usr/bin/env python3
"""pkey tests for wolfCLU."""

import base64
import filecmp
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import CERTS_DIR, run_wolfssl, test_main

ML_DSA_SETS = (44, 65, 87)

ECC_PUBKEY_PEM = """\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuzOsTCdQSsZKpQTDPN6fNttyLc6U
6iv6yyAJOSwW6GEC6a9N0wKTmjFbl5Ihf/DPGNqREQI0huggWDMLgDSJ2A==
-----END PUBLIC KEY-----"""

ECC_PRIVKEY_PEM = """\
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEW2aQJznGyFoThbcujox6zEA41TNQT6bCjcNI3hqAmMoAoGCCqGSM49
AwEHoUQDQgAEuzOsTCdQSsZKpQTDPN6fNttyLc6U6iv6yyAJOSwW6GEC6a9N0wKT
mjFbl5Ihf/DPGNqREQI0huggWDMLgDSJ2A==
-----END EC PRIVATE KEY-----"""


class PkeyTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

        config_log = os.path.join(".", "config.log")
        if os.path.isfile(config_log):
            with open(config_log, "r") as f:
                if "disable-filesystem" in f.read():
                    raise unittest.SkipTest("filesystem support disabled")

    def _cleanup(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: os.remove(p)
                            if os.path.exists(p) else None)

    def test_pubin_ecc(self):
        r = run_wolfssl("pkey", "-pubin", "-in",
                        os.path.join(CERTS_DIR, "ecc-keyPub.pem"))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), ECC_PUBKEY_PEM)

    def test_fail_pubin_private_key(self):
        r = run_wolfssl("pkey", "-pubin", "-in",
                        os.path.join(CERTS_DIR, "ecc-key.pem"))
        self.assertNotEqual(r.returncode, 0)

    def test_pem_der_pem_private(self):
        self._cleanup("ecc.der", "ecc.pem")

        r = run_wolfssl("pkey", "-in",
                        os.path.join(CERTS_DIR, "ecc-key.pem"),
                        "-outform", "der", "-out", "ecc.der")
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("pkey", "-in", "ecc.der", "-inform", "der",
                        "-outform", "pem", "-out", "ecc.pem")
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("pkey", "-in", "ecc.pem")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), ECC_PRIVKEY_PEM)

    def test_pem_der_pem_public(self):
        self._cleanup("ecc.der", "ecc.pem")

        r = run_wolfssl("pkey", "-pubin", "-in",
                        os.path.join(CERTS_DIR, "ecc-keyPub.pem"),
                        "-outform", "der", "-out", "ecc.der")
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("pkey", "-pubin", "-in", "ecc.der", "-inform", "der",
                        "-outform", "pem", "-out", "ecc.pem")
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("pkey", "-pubin", "-in", "ecc.pem")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), ECC_PUBKEY_PEM)


    def test_help(self):
        for flag in ("-help", "-h"):
            r = run_wolfssl("pkey", flag)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("wolfssl pkey", r.stdout + r.stderr)

    def test_pubout_from_private(self):
        r = run_wolfssl("pkey", "-in",
                        os.path.join(CERTS_DIR, "ecc-key.pem"), "-pubout")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), ECC_PUBKEY_PEM)

    def test_out_to_file(self):
        out = "pkey-out.pem"
        self._cleanup(out)
        r = run_wolfssl("pkey", "-in",
                        os.path.join(CERTS_DIR, "ecc-key.pem"),
                        "-pubout", "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(out), "pkey -out did not create file")
        with open(out, "r") as f:
            self.assertIn("BEGIN PUBLIC KEY", f.read())


class PkeyMlDsaTest(unittest.TestCase):
    """ML-DSA PEM<->DER conversion through `wolfssl pkey`."""

    @classmethod
    def setUpClass(cls):
        config_log = os.path.join(".", "config.log")
        if os.path.isfile(config_log):
            with open(config_log, "r") as f:
                if "disable-filesystem" in f.read():
                    raise unittest.SkipTest("filesystem support disabled")

        r = run_wolfssl("genkey", "ml-dsa", "-level", "2", "-out",
                        "mldsa-probe", "-output", "keypair", "-outform", "pem")
        for path in ("mldsa-probe.priv", "mldsa-probe.pub"):
            if os.path.exists(path):
                os.remove(path)
        if r.returncode != 0 or "not enabled" in (r.stdout + r.stderr):
            raise unittest.SkipTest("ML-DSA support not compiled in")

    def _cleanup(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: os.remove(p)
                            if os.path.exists(p) else None)

    def _genkey(self, level, outform="pem"):
        """Generate an ML-DSA keypair, returning the paths as a tuple:
            (private, public)."""
        stem = "mldsa-l%d" % level
        priv, pub = stem + ".priv", stem + ".pub"
        self._cleanup(priv, pub)

        r = run_wolfssl("genkey", "ml-dsa", "-level", str(level), "-out", stem,
                        "-output", "keypair", "-outform", outform)
        self.assertEqual(r.returncode, 0, r.stderr)
        return priv, pub

    def _assert_der(self, path):
        """A DER output must not be PEM text that slipped through."""
        with open(path, "rb") as f:
            head = f.read(1)
        self.assertEqual(head, b"\x30",
                         "%s is not DER (expected a SEQUENCE tag)" % path)

    def _pem_to_der(self, path):
        """Decode a PUBLIC KEY PEM file to its DER bytes."""
        with open(path, "r") as f:
            lines = f.read().splitlines()
        self.assertEqual(lines[0], "-----BEGIN PUBLIC KEY-----")
        return base64.b64decode("".join(l for l in lines
                                        if not l.startswith("-----")))

    def _file_matrix(self):
        """Yield (path, stem, pubin) for the seed-form private key and SPKI
        public key of each ML-DSA parameter set. stem names output files."""
        for n in ML_DSA_SETS:
            for name, kind, pubin in (
                    ("mldsa%d_seed-only.der" % n, "priv", ()),
                    ("mldsa%d_pub-spki.der" % n, "pub", ("-pubin",))):
                path = os.path.join(CERTS_DIR, "mldsa", name)
                if not os.path.isfile(path):
                    self.fail("%s not found" % path)
                yield path, "pkey-mldsa%d-%s" % (n, kind), pubin

    def test_round_trip(self):
        """ML-DSA private and public keys survive DER->PEM->DER."""
        for src, stem, pubin in self._file_matrix():
            with self.subTest(key=src):
                pem, der = stem + ".pem", stem + ".der"
                self._cleanup(pem, der)

                r = run_wolfssl("pkey", *pubin, "-in", src, "-inform", "der",
                                "-outform", "pem", "-out", pem)
                self.assertEqual(r.returncode, 0, r.stderr)

                r = run_wolfssl("pkey", *pubin, "-in", pem, "-inform", "pem",
                                "-outform", "der", "-out", der)
                self.assertEqual(r.returncode, 0, r.stderr)
                self._assert_der(der)

                self.assertTrue(filecmp.cmp(src, der, shallow=False),
                                "%s changed over DER->PEM->DER" % src)

    def test_pem_to_pem_is_identity(self):
        """ML-DSA PEM->PEM leaves the key byte-identical."""
        src = os.path.join(CERTS_DIR, "mldsa", "mldsa44-key.pem")
        if not os.path.isfile(src):
            self.fail("%s not found" % src)
        out = "pkey-mldsa44-key.pem"
        self._cleanup(out)

        r = run_wolfssl("pkey", "-in", src, "-inform", "pem",
                        "-outform", "pem", "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(filecmp.cmp(src, out, shallow=False),
                        "%s changed over PEM->PEM" % src)

    def test_pubout_from_private_key(self):
        """ML-DSA -pubout only outputs the public key."""
        priv = os.path.join(CERTS_DIR, "mldsa", "mldsa44-key.pem")
        pub = os.path.join(CERTS_DIR, "mldsa", "mldsa44-keyPub.der")
        out = "pkey-mldsa44-pubout.der"
        self._cleanup(out)

        r = run_wolfssl("pkey", "-in", priv, "-inform", "pem", "-pubout",
                        "-outform", "der", "-out", out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(filecmp.cmp(pub, out, shallow=False),
                        "-pubout did not produce the matching public key")

    def test_pubout_and_pubin_pem(self):
        """ML-DSA -pubout and -pubin PEM->PEM output the public key."""
        priv = os.path.join(CERTS_DIR, "mldsa", "mldsa44-key.pem")
        with open(os.path.join(CERTS_DIR, "mldsa", "mldsa44-keyPub.der"),
                  "rb") as f:
            pub = f.read()
        pubout, pubin = "pkey-mldsa44-pubout.pem", "pkey-mldsa44-pubin.pem"
        self._cleanup(pubout, pubin)

        r = run_wolfssl("pkey", "-in", priv, "-pubout", "-out", pubout)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self._pem_to_der(pubout), pub,
                         "-pubout did not produce the matching public key")

        r = run_wolfssl("pkey", "-pubin", "-in", pubout, "-out", pubin)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self._pem_to_der(pubin), pub,
                         "-pubin changed the public key")

    def test_genkey_round_trip(self):
        """A genkey ML-DSA private key survives DER->PEM->DER."""
        priv, _ = self._genkey(2, "der")
        pem, der = priv + ".pem", priv + ".der"
        self._cleanup(pem, der)

        r = run_wolfssl("pkey", "-in", priv, "-inform", "der",
                        "-outform", "pem", "-out", pem)
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("pkey", "-in", pem, "-inform", "pem",
                        "-outform", "der", "-out", der)
        self.assertEqual(r.returncode, 0, r.stderr)
        self._assert_der(der)

        self.assertTrue(filecmp.cmp(priv, der, shallow=False),
                        "%s changed over DER->PEM->DER" % priv)


if __name__ == "__main__":
    test_main()

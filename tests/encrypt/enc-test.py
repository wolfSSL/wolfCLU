#!/usr/bin/env python3
"""Encryption/decryption tests for wolfCLU."""

import filecmp
import os
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import CERTS_DIR, WOLFSSL_BIN, run_wolfssl


def run_enc(*args, password=""):
    """Run wolfssl enc with a -k password argument appended."""
    cmd = [WOLFSSL_BIN] + list(args) + ["-k", password]
    return subprocess.run(cmd, capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, timeout=60)


class EncDecryptTest(unittest.TestCase):

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

    def test_decrypt_nosalt(self):
        dec = "test-dec.der"
        self._cleanup(dec)

        r = run_enc("enc", "-d", "-aes-256-cbc", "-nosalt",
                     "-in", os.path.join(CERTS_DIR, "crl.der.enc"),
                     "-out", dec, password="")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(
            filecmp.cmp(os.path.join(CERTS_DIR, "crl.der"), dec, shallow=False),
            "decryption 1 mismatch")

    def test_decrypt_base64_nosalt(self):
        dec = "test-dec.der"
        self._cleanup(dec)

        r = run_enc("enc", "-base64", "-d", "-aes-256-cbc", "-nosalt",
                     "-in", os.path.join(CERTS_DIR, "crl.der.enc.base64"),
                     "-out", dec, password="")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(
            filecmp.cmp(os.path.join(CERTS_DIR, "crl.der"), dec, shallow=False),
            "decryption 2 mismatch")

    def test_fail_nonexistent_file(self):
        dec = "test-dec.der"
        self._cleanup(dec)

        r = run_enc("enc", "-base64", "-d", "-aes-256-cbc", "-nosalt",
                     "-in", os.path.join(CERTS_DIR, "file-does-not-exist"),
                     "-out", dec, password="")
        self.assertNotEqual(r.returncode, 0)

    def test_encrypt_decrypt_base64(self):
        enc = "test-enc.der"
        dec = "test-dec.der"
        orig = os.path.join(CERTS_DIR, "crl.der")
        self._cleanup(enc, dec)

        r = run_enc("enc", "-base64", "-aes-256-cbc",
                     "-in", orig, "-out", enc,
                     password="test password")
        self.assertEqual(r.returncode, 0, r.stderr)

        # Bad password should fail
        r = run_enc("enc", "-base64", "-d", "-aes-256-cbc",
                     "-in", enc, "-out", dec,
                     password="bad password")
        self.assertNotEqual(r.returncode, 0)

        r = run_enc("enc", "-base64", "-d", "-aes-256-cbc",
                     "-in", enc, "-out", dec,
                     password="test password")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(filecmp.cmp(orig, dec, shallow=False),
                        "decryption 3 mismatch")

    def test_aes128_roundtrip(self):
        # Use a file that exists on both Linux and Windows
        orig = os.path.join(CERTS_DIR, "server-key.der")
        enc = "roundtrip.enc"
        dec = "roundtrip.dec"
        self._cleanup(enc, dec)

        r = run_enc("enc", "-aes-128-cbc", "-in", orig, "-out", enc,
                     password="test")
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_enc("enc", "-d", "-aes-128-cbc", "-in", enc, "-out", dec,
                     password="test")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(filecmp.cmp(orig, dec, shallow=False),
                        "decrypted file does not match original")

    def test_small_file(self):
        small = "enc_small.txt"
        enc = "enc_small.txt.enc"
        dec = "enc_small.txt.dec"
        self._cleanup(small, enc, dec)

        with open(small, "w") as f:
            f.write(" \n")

        r = run_enc("enc", "-aes-128-cbc", "-in", small, "-out", enc,
                     password="test")
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_enc("enc", "-d", "-aes-128-cbc", "-in", enc, "-out", dec,
                     password="test")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(filecmp.cmp(small, dec, shallow=False),
                        "small file decryption mismatch")


class EncInteropTest(unittest.TestCase):
    """Test interoperability with OpenSSL (skipped if openssl not available)."""

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")
        if shutil.which("openssl") is None:
            raise unittest.SkipTest("openssl not found")

    def _cleanup(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: os.remove(p)
                            if os.path.exists(p) else None)

    def test_openssl_enc_wolfssl_dec(self):
        enc = "test-enc.der"
        dec = "test-dec.der"
        orig = os.path.join(CERTS_DIR, "crl.der")
        self._cleanup(enc, dec)

        ossl = subprocess.run(["openssl", "enc", "-base64", "-aes-256-cbc",
                                "-k", "test password", "-in", orig, "-out", enc],
                               capture_output=True, timeout=60)
        self.assertEqual(ossl.returncode, 0, ossl.stderr)

        r = run_enc("enc", "-base64", "-d", "-aes-256-cbc",
                     "-in", enc, "-out", dec, password="test password")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(filecmp.cmp(orig, dec, shallow=False))

    def test_wolfssl_enc_openssl_dec(self):
        enc = "test-enc.der"
        dec = "test-dec.der"
        orig = os.path.join(CERTS_DIR, "crl.der")
        self._cleanup(enc, dec)

        r = run_enc("enc", "-base64", "-aes-256-cbc",
                     "-in", orig, "-out", enc, password="test password")
        self.assertEqual(r.returncode, 0, r.stderr)

        ossl = subprocess.run(["openssl", "enc", "-base64", "-d", "-aes-256-cbc",
                                "-k", "test password", "-in", enc, "-out", dec],
                               capture_output=True, timeout=60)
        self.assertEqual(ossl.returncode, 0, ossl.stderr)
        self.assertTrue(filecmp.cmp(orig, dec, shallow=False))

    def test_pbkdf2_openssl_enc_wolfssl_dec(self):
        enc = "test-enc.der"
        dec = "test-dec.der"
        orig = os.path.join(CERTS_DIR, "crl.der")
        self._cleanup(enc, dec)

        ossl = subprocess.run(["openssl", "enc", "-base64", "-pbkdf2", "-aes-256-cbc",
                                "-k", "long test password", "-in", orig, "-out", enc],
                               capture_output=True, timeout=60)
        self.assertEqual(ossl.returncode, 0, ossl.stderr)

        r = run_enc("enc", "-base64", "-d", "-pbkdf2", "-aes-256-cbc",
                     "-in", enc, "-out", dec, password="long test password")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(filecmp.cmp(orig, dec, shallow=False))

    def test_pbkdf2_wolfssl_enc_openssl_dec(self):
        enc = "test-enc.der"
        dec = "test-dec.der"
        orig = os.path.join(CERTS_DIR, "crl.der")
        self._cleanup(enc, dec)

        r = run_enc("enc", "-base64", "-pbkdf2", "-aes-256-cbc",
                     "-in", orig, "-out", enc, password="long test password")
        self.assertEqual(r.returncode, 0, r.stderr)

        ossl = subprocess.run(["openssl", "enc", "-base64", "-d", "-pbkdf2",
                                "-aes-256-cbc", "-k", "long test password",
                                "-in", enc, "-out", dec],
                               capture_output=True, timeout=60)
        self.assertEqual(ossl.returncode, 0, ossl.stderr)
        self.assertTrue(filecmp.cmp(orig, dec, shallow=False))

    def test_pbkdf2_wolfssl_pass_flag(self):
        enc = "test-enc.der"
        dec = "test-dec.der"
        orig = os.path.join(CERTS_DIR, "crl.der")
        self._cleanup(enc, dec)

        r = run_enc("enc", "-base64", "-pbkdf2", "-aes-256-cbc",
                     "-in", orig, "-out", enc, password="long test password")
        self.assertEqual(r.returncode, 0, r.stderr)

        # Decrypt using -pass flag instead of -k
        r = subprocess.run(
            [WOLFSSL_BIN, "enc", "-base64", "-d", "-pbkdf2", "-aes-256-cbc",
             "-pass", "pass:long test password", "-in", enc, "-out", dec],
            capture_output=True, text=True, stdin=subprocess.DEVNULL,
            timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(filecmp.cmp(orig, dec, shallow=False))


class EncLegacyNamesTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

    def _cleanup(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: os.remove(p)
                            if os.path.exists(p) else None)

    def _roundtrip(self, enc_algo, dec_algo, msg):
        enc = "test-enc.der"
        dec = "test-dec.der"
        orig = os.path.join(CERTS_DIR, "crl.der")
        self._cleanup(enc, dec)

        r = run_enc("enc", enc_algo, "-in", orig, "-out", enc,
                     password="test password")
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_enc("enc", "-d", dec_algo, "-in", enc, "-out", dec,
                     password="test password")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(filecmp.cmp(orig, dec, shallow=False), msg)

    def test_legacy_aes_cbc_256_roundtrip(self):
        self._roundtrip("-aes-cbc-256", "-aes-cbc-256",
                        "legacy aes-cbc-256 round trip failed")

    def test_legacy_enc_canonical_dec(self):
        self._roundtrip("-aes-cbc-256", "-aes-256-cbc",
                        "legacy enc / canonical dec failed")

    def test_canonical_enc_legacy_dec(self):
        self._roundtrip("-aes-256-cbc", "-aes-cbc-256",
                        "canonical enc / legacy dec failed")

    def test_legacy_aes_cbc_128_roundtrip(self):
        self._roundtrip("-aes-cbc-128", "-aes-cbc-128",
                        "legacy aes-cbc-128 round trip failed")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Encryption/decryption tests for wolfCLU."""

import filecmp
import os
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import CERTS_DIR, WOLFSSL_BIN, run_wolfssl, test_main


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


def _camellia_available():
    """Check if Camellia support is enabled in the wolfssl binary."""
    crl = os.path.join(CERTS_DIR, "crl.der")
    if not os.path.isfile(crl):
        return False
    probe = "test-cam-probe.enc"
    try:
        r = run_enc("enc", "-camellia-128-cbc", "-in", crl, "-out", probe,
                    password="testpass")
        return r.returncode == 0
    finally:
        if os.path.exists(probe):
            os.remove(probe)


class EncStdinInputTest(unittest.TestCase):
    """Regression tests for stack buffer overflow fix (scanf -> fgets).

    When -in or -out is omitted, wolfCLU prompts for the filename on stdin.
    These tests exercise the fgets-based input paths, including the
    empty-line re-prompt and the too-long-input flush branches.
    """

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

        config_log = os.path.join(".", "config.log")
        if os.path.isfile(config_log):
            with open(config_log, "r") as f:
                if "disable-filesystem" in f.read():
                    raise unittest.SkipTest("filesystem support disabled")

        cls.has_camellia = _camellia_available()

    def _cleanup(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: os.remove(p)
                            if os.path.exists(p) else None)

    def _run_enc_stdin(self, stdin_data, *args, password="testpass"):
        """Run wolfssl enc with stdin input (for filename prompts)."""
        cmd = [WOLFSSL_BIN, "enc"] + list(args) + ["-k", password]
        return subprocess.run(cmd, input=stdin_data,
                              capture_output=True, text=True, timeout=60)

    # -- AES (EVP path) --

    def test_aes_inname_via_stdin(self):
        """-in omitted; filename supplied via stdin (inName path)."""
        enc = "test-stdin-in.enc"
        dec = "test-stdin-in.dec"
        orig = os.path.join(CERTS_DIR, "crl.der")
        self._cleanup(enc, dec)

        r = self._run_enc_stdin(f"{orig}\n", "-aes-128-cbc", "-out", enc)
        self.assertEqual(r.returncode, 0,
                         f"enc with stdin input failed: {r.stderr}")

        r = run_enc("enc", "-d", "-aes-128-cbc", "-in", enc, "-out", dec,
                    password="testpass")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(filecmp.cmp(orig, dec, shallow=False),
                        "stdin enc/dec roundtrip mismatch")

    def test_aes_inname_empty_line_reprompt(self):
        """Empty line on stdin is rejected; next valid filename accepted."""
        enc = "test-empty-in.enc"
        dec = "test-empty-in.dec"
        orig = os.path.join(CERTS_DIR, "crl.der")
        self._cleanup(enc, dec)

        r = self._run_enc_stdin(f"\n{orig}\n", "-aes-128-cbc", "-out", enc)
        self.assertEqual(r.returncode, 0,
                         f"enc should accept filename after empty line: "
                         f"{r.stderr}")

        r = run_enc("enc", "-d", "-aes-128-cbc", "-in", enc, "-out", dec,
                    password="testpass")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(filecmp.cmp(orig, dec, shallow=False),
                        "enc/dec roundtrip mismatch after empty-line reprompt")

    def test_aes_inname_too_long_reprompt(self):
        """Overlong input is flushed; next valid filename accepted."""
        enc = "test-toolong-in.enc"
        dec = "test-toolong-in.dec"
        orig = os.path.join(CERTS_DIR, "crl.der")
        self._cleanup(enc, dec)

        long_input = " " * 255
        r = self._run_enc_stdin(f"{long_input}\n{orig}\n",
                                "-aes-128-cbc", "-out", enc)
        self.assertEqual(r.returncode, 0,
                         f"enc should recover after too-long input: "
                         f"{r.stderr}")

        r = run_enc("enc", "-d", "-aes-128-cbc", "-in", enc, "-out", dec,
                    password="testpass")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(filecmp.cmp(orig, dec, shallow=False),
                        "enc/dec roundtrip mismatch after too-long reprompt")

    # -- Camellia (non-EVP path) --

    def test_camellia_outname_via_stdin(self):
        """-out omitted; output filename supplied via stdin (non-EVP path)."""
        if not self.has_camellia:
            self.skipTest("Camellia not available")
        enc = "test-cam-stdin.enc"
        dec = "test-cam-stdin.dec"
        orig = os.path.join(CERTS_DIR, "crl.der")
        self._cleanup(enc, dec)

        r = self._run_enc_stdin(f"{enc}\n", "-camellia-128-cbc", "-in", orig)
        self.assertEqual(r.returncode, 0,
                         f"Camellia enc with stdin output name failed: "
                         f"{r.stderr}")

        r = self._run_enc_stdin(f"{dec}\n", "-d", "-camellia-128-cbc",
                                "-in", enc)
        self.assertEqual(r.returncode, 0,
                         f"Camellia dec with stdin output name failed: "
                         f"{r.stderr}")
        self.assertTrue(filecmp.cmp(orig, dec, shallow=False),
                        "Camellia stdin outName roundtrip mismatch")

    def test_camellia_outname_empty_line_reprompt(self):
        """Empty line rejected; next valid output name accepted (non-EVP)."""
        if not self.has_camellia:
            self.skipTest("Camellia not available")
        enc = "test-cam-empty.enc"
        dec = "test-cam-empty.dec"
        orig = os.path.join(CERTS_DIR, "crl.der")
        self._cleanup(enc, dec)

        r = self._run_enc_stdin(f"\n{enc}\n", "-camellia-128-cbc", "-in", orig)
        self.assertEqual(r.returncode, 0,
                         f"Camellia enc should accept output name after "
                         f"empty line: {r.stderr}")

        r = self._run_enc_stdin(f"\n{dec}\n", "-d", "-camellia-128-cbc",
                                "-in", enc)
        self.assertEqual(r.returncode, 0,
                         f"Camellia dec should accept output name after "
                         f"empty line: {r.stderr}")
        self.assertTrue(filecmp.cmp(orig, dec, shallow=False),
                        "Camellia roundtrip mismatch after empty-line "
                        "reprompt")

    def test_camellia_outname_too_long_reprompt(self):
        """Overlong input flushed; next valid output name accepted (non-EVP)."""
        if not self.has_camellia:
            self.skipTest("Camellia not available")
        enc = "test-cam-toolong.enc"
        dec = "test-cam-toolong.dec"
        orig = os.path.join(CERTS_DIR, "crl.der")
        self._cleanup(enc, dec)

        long_input = " " * 255
        r = self._run_enc_stdin(f"{long_input}\n{enc}\n",
                                "-camellia-128-cbc", "-in", orig)
        self.assertEqual(r.returncode, 0,
                         f"Camellia enc should recover after too-long output "
                         f"name: {r.stderr}")

        r = self._run_enc_stdin(f"{long_input}\n{dec}\n",
                                "-d", "-camellia-128-cbc", "-in", enc)
        self.assertEqual(r.returncode, 0,
                         f"Camellia dec should recover after too-long output "
                         f"name: {r.stderr}")
        self.assertTrue(filecmp.cmp(orig, dec, shallow=False),
                        "Camellia roundtrip mismatch after too-long reprompt")


if __name__ == "__main__":
    test_main()

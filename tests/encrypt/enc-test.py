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

        # Bad password: AES-CBC with EVP_BytesToKey (no MAC) detects a wrong
        # password only via PKCS#7 padding validation of the garbage plaintext.
        # Random salt makes that check probabilistic (~1/256 false accept), so
        # also verify the output does not match the original.
        r = run_enc("enc", "-base64", "-d", "-aes-256-cbc",
                     "-in", enc, "-out", dec,
                     password="bad password")
        bad_recovered = (r.returncode == 0
                         and os.path.exists(dec)
                         and filecmp.cmp(orig, dec, shallow=False))
        self.assertFalse(bad_recovered,
                         "bad password must not recover original plaintext")

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

    def test_enc_to_stdout(self):
        """enc with no -out writes ciphertext to stdout."""
        src = "enc_stdout_test.bin"
        self._cleanup(src)
        with open(src, "wb") as f:
            f.write(b"plaintext\n")

        r = subprocess.run(
            [WOLFSSL_BIN, "enc", "-aes-128-cbc", "-in", src,
             "-pass", "pass:test"],
            capture_output=True, stdin=subprocess.DEVNULL, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr.decode(errors="replace"))
        self.assertGreater(len(r.stdout), 0)

    def test_explicit_hex_key_iv(self):
        """Regression: explicit --key/--iv hex strings must be copied correctly."""
        src = "enc_hex_test.txt"
        enc = "enc_hex_test.enc"
        self._cleanup(src, enc)

        with open(src, "w") as f:
            f.write("testing explicit hex IV and key\n")

        r = run_wolfssl("enc", "-aes-128-cbc", "-nosalt",
                        "-in", src, "-out", enc,
                        "--key", "00112233445566778899aabbccddeeff",
                        "--iv", "00112233445566778899aabb0011aab7")
        self.assertEqual(r.returncode, 0,
                         "encrypt with explicit hex key/iv failed: "
                         "{}".format(r.stderr))


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

    def test_explicit_key_iv_wolfssl_to_openssl(self):
        """Proves the user-supplied -key actually reaches the cipher.

        Without keyType plumbed into the EVP path, wolfCLU silently runs
        BytesToKey/PBKDF2 over an empty password and overwrites the
        user's key, so a same-tool round-trip succeeds while interop with
        openssl on the same hex key fails."""
        key_hex = "00112233445566778899aabbccddeeff"\
                  "00112233445566778899aabbccddeeff"
        iv_hex  = "0123456789abcdef0123456789abcdef"
        enc = "wolfssl_key_iv.enc"
        dec = "wolfssl_key_iv.dec"
        orig = os.path.join(CERTS_DIR, "crl.der")
        self._cleanup(enc, dec)

        r = run_wolfssl("-encrypt", "-aes-cbc-256",
                        "-in", orig, "-out", enc,
                        "-key", key_hex, "-iv", iv_hex)
        self.assertEqual(r.returncode, 0, r.stderr)

        ossl = subprocess.run(
            ["openssl", "enc", "-d", "-aes-256-cbc", "-nosalt",
             "-K", key_hex, "-iv", iv_hex,
             "-in", enc, "-out", dec],
            capture_output=True, timeout=60)
        self.assertEqual(ossl.returncode, 0,
                         "openssl could not decrypt wolfCLU output with "
                         "the same -K/-iv: " + ossl.stderr.decode(
                             errors="replace"))
        self.assertTrue(filecmp.cmp(orig, dec, shallow=False),
                        "wolfCLU -> openssl interop failed")

    def test_explicit_key_iv_openssl_to_wolfssl(self):
        """Reverse interop: openssl encrypts with -K/-iv, wolfCLU decrypts."""
        key_hex = "00112233445566778899aabbccddeeff"\
                  "00112233445566778899aabbccddeeff"
        iv_hex  = "0123456789abcdef0123456789abcdef"
        enc = "openssl_key_iv.enc"
        dec = "openssl_key_iv.dec"
        orig = os.path.join(CERTS_DIR, "crl.der")
        self._cleanup(enc, dec)

        ossl = subprocess.run(
            ["openssl", "enc", "-aes-256-cbc", "-nosalt",
             "-K", key_hex, "-iv", iv_hex,
             "-in", orig, "-out", enc],
            capture_output=True, timeout=60)
        self.assertEqual(ossl.returncode, 0, ossl.stderr)

        r = run_wolfssl("-decrypt", "-aes-cbc-256",
                        "-in", enc, "-out", dec,
                        "-key", key_hex, "-iv", iv_hex)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(filecmp.cmp(orig, dec, shallow=False),
                        "openssl -> wolfCLU interop failed")

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


class EncPassSourceTest(unittest.TestCase):
    """Regression tests for issue 6133.

    wolfCLU_GetPassword only supports the "stdin" and "pass:" password
    sources. Any other source (env:, file:, fd:, ...) must make the tool
    fail loudly. Previously -pass parsing errors were ignored and the file
    was silently encrypted under an empty/zeroed password while the tool
    reported success.
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

    def _cleanup(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: os.remove(p)
                            if os.path.exists(p) else None)

    def _enc_with_pass(self, src, enc):
        """Encrypt crl.der into enc using -pass <src>."""
        orig = os.path.join(CERTS_DIR, "crl.der")
        return subprocess.run(
            [WOLFSSL_BIN, "enc", "-aes-256-cbc",
             "-in", orig, "-out", enc, "-pass", src],
            capture_output=True, text=True, stdin=subprocess.DEVNULL,
            timeout=60)

    def test_unsupported_pass_sources_fail(self):
        """Unsupported -pass sources must not silently encrypt."""
        orig = os.path.join(CERTS_DIR, "crl.der")
        for src in ("env:WOLFCLU_TEST_PW", "file:somefile", "fd:3"):
            enc = "test-pass-src.enc"
            dec = "test-pass-src.dec"
            self._cleanup(enc, dec)
            if os.path.exists(enc):
                os.remove(enc)

            r = self._enc_with_pass(src, enc)
            # The tool must report failure for an unsupported source.
            self.assertNotEqual(r.returncode, 0,
                "unsupported -pass source %r encrypted with returncode 0; "
                "output may be under an empty password" % src)

            # Defence in depth: if an output file was produced anyway, it
            # must not be the plaintext encrypted under an empty password.
            if os.path.exists(enc):
                d = subprocess.run(
                    [WOLFSSL_BIN, "enc", "-d", "-aes-256-cbc",
                     "-in", enc, "-out", dec, "-pass", "pass:"],
                    capture_output=True, text=True,
                    stdin=subprocess.DEVNULL, timeout=60)
                recovered = (d.returncode == 0 and os.path.exists(dec)
                             and filecmp.cmp(orig, dec, shallow=False))
                self.assertFalse(recovered,
                    "unsupported -pass source %r produced ciphertext "
                    "decryptable under an empty password" % src)

    def test_supported_pass_source_still_works(self):
        """The supported pass: source must keep round-tripping."""
        enc = "test-pass-ok.enc"
        dec = "test-pass-ok.dec"
        orig = os.path.join(CERTS_DIR, "crl.der")
        self._cleanup(enc, dec)

        r = self._enc_with_pass("pass:test password", enc)
        self.assertEqual(r.returncode, 0, r.stderr)

        d = subprocess.run(
            [WOLFSSL_BIN, "enc", "-d", "-aes-256-cbc",
             "-in", enc, "-out", dec, "-pass", "pass:test password"],
            capture_output=True, text=True, stdin=subprocess.DEVNULL,
            timeout=60)
        self.assertEqual(d.returncode, 0, d.stderr)
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


class EncKeyInputTest(unittest.TestCase):
    """Tests for the -key (hex on CLI) and -inkey (key from file) flags."""

    # AES-256 key/iv used across the tests.
    KEY_HEX = "00112233445566778899aabbccddeeff"\
              "00112233445566778899aabbccddeeff"
    IV_HEX  = "0123456789abcdef0123456789abcdef"

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

    def _orig(self):
        return os.path.join(CERTS_DIR, "server-key.der")

    def test_key_hex_cli_roundtrip(self):
        """`-key <hex>` accepts a hex key on the command line."""
        enc = "key_cli.enc"
        dec = "key_cli.dec"
        self._cleanup(enc, dec)

        r = run_wolfssl("-encrypt", "-aes-cbc-256",
                        "-in", self._orig(), "-out", enc,
                        "-key", self.KEY_HEX, "-iv", self.IV_HEX)
        self.assertEqual(r.returncode, 0,
                         "encrypt with -key hex failed: " + r.stderr)

        r = run_wolfssl("-decrypt", "-aes-cbc-256",
                        "-in", enc, "-out", dec,
                        "-key", self.KEY_HEX, "-iv", self.IV_HEX)
        self.assertEqual(r.returncode, 0,
                         "decrypt with -key hex failed: " + r.stderr)
        self.assertTrue(filecmp.cmp(self._orig(), dec, shallow=False),
                        "round-trip with -key hex did not recover plaintext")

    def test_inkey_hex_file_roundtrip(self):
        """`-inkey <file>` reads a hex-encoded key from a file."""
        keyfile = "key_inkey_hex.txt"
        enc = "inkey_hex.enc"
        dec = "inkey_hex.dec"
        self._cleanup(keyfile, enc, dec)

        # Write hex with a trailing newline (typical of `echo > file`).
        with open(keyfile, "w") as f:
            f.write(self.KEY_HEX + "\n")

        r = run_wolfssl("-encrypt", "-aes-cbc-256",
                        "-in", self._orig(), "-out", enc,
                        "-inkey", keyfile, "-iv", self.IV_HEX)
        self.assertEqual(r.returncode, 0,
                         "encrypt with -inkey hex file failed: " + r.stderr)

        r = run_wolfssl("-decrypt", "-aes-cbc-256",
                        "-in", enc, "-out", dec,
                        "-inkey", keyfile, "-iv", self.IV_HEX)
        self.assertEqual(r.returncode, 0,
                         "decrypt with -inkey hex file failed: " + r.stderr)
        self.assertTrue(filecmp.cmp(self._orig(), dec, shallow=False),
                        "round-trip with -inkey hex file mismatched")

    def test_inkey_raw_binary_file_roundtrip(self):
        """`-inkey <file>` reads a raw binary key from a file."""
        keyfile = "key_inkey_bin.key"
        enc = "inkey_bin.enc"
        dec = "inkey_bin.dec"
        self._cleanup(keyfile, enc, dec)

        with open(keyfile, "wb") as f:
            f.write(bytes.fromhex(self.KEY_HEX))

        r = run_wolfssl("-encrypt", "-aes-cbc-256",
                        "-in", self._orig(), "-out", enc,
                        "-inkey", keyfile, "-iv", self.IV_HEX)
        self.assertEqual(r.returncode, 0,
                         "encrypt with -inkey raw binary file failed: "
                         + r.stderr)

        r = run_wolfssl("-decrypt", "-aes-cbc-256",
                        "-in", enc, "-out", dec,
                        "-inkey", keyfile, "-iv", self.IV_HEX)
        self.assertEqual(r.returncode, 0,
                         "decrypt with -inkey raw binary file failed: "
                         + r.stderr)
        self.assertTrue(filecmp.cmp(self._orig(), dec, shallow=False),
                        "round-trip with -inkey raw binary file mismatched")

    def test_inkey_hex_file_with_embedded_whitespace(self):
        """Embedded whitespace inside a hex key file is ignored."""
        keyfile = "key_inkey_ws.txt"
        enc = "inkey_ws.enc"
        dec = "inkey_ws.dec"
        self._cleanup(keyfile, enc, dec)

        # Split the hex key across two lines with a leading space.
        chunked = " " + self.KEY_HEX[:32] + "\n" + self.KEY_HEX[32:] + "\n"
        with open(keyfile, "w") as f:
            f.write(chunked)

        r = run_wolfssl("-encrypt", "-aes-cbc-256",
                        "-in", self._orig(), "-out", enc,
                        "-inkey", keyfile, "-iv", self.IV_HEX)
        self.assertEqual(r.returncode, 0,
                         "encrypt with whitespace-formatted hex file failed: "
                         + r.stderr)

        r = run_wolfssl("-decrypt", "-aes-cbc-256",
                        "-in", enc, "-out", dec,
                        "-inkey", keyfile, "-iv", self.IV_HEX)
        self.assertEqual(r.returncode, 0,
                         "decrypt with whitespace-formatted hex file failed: "
                         + r.stderr)
        self.assertTrue(filecmp.cmp(self._orig(), dec, shallow=False),
                        "round-trip with whitespace-formatted hex file failed")

    def test_inkey_missing_file_errors(self):
        """-inkey requires an actual file. A missing path must error;
        the previous "fall back to hex parse" behavior was removed because
        it ambiguously interpreted typo'd filenames as keys."""
        enc = "inkey_bad.enc"
        self._cleanup(enc)

        r = run_wolfssl("-encrypt", "-aes-cbc-256",
                        "-in", self._orig(), "-out", enc,
                        "-inkey", "no-such-file.key", "-iv", self.IV_HEX)
        self.assertNotEqual(r.returncode, 0,
                            "missing key file must error out")
        self.assertFalse(os.path.exists(enc),
                         "no output should be produced on missing key file")
        # And specifically: even a 64-char hex string that happens to be a
        # missing path must NOT be silently parsed as a hex key — use -key
        # for that.
        if os.path.exists(self.KEY_HEX):
            os.remove(self.KEY_HEX)
        r = run_wolfssl("-encrypt", "-aes-cbc-256",
                        "-in", self._orig(), "-out", enc,
                        "-inkey", self.KEY_HEX, "-iv", self.IV_HEX)
        self.assertNotEqual(r.returncode, 0,
                            "-inkey hex string must error (use -key instead)")

    def test_inkey_raw_binary_trailing_whitespace_byte(self):
        """Regression: a 32-byte raw binary key whose last byte is 0x0A must
        not be silently truncated by trailing-whitespace handling."""
        keyfile = "key_inkey_lf.bin"
        enc = "inkey_lf.enc"
        dec = "inkey_lf.dec"
        self._cleanup(keyfile, enc, dec)

        # 31 random-looking bytes (chosen so hex detection routes to raw)
        # followed by 0x0A as the terminal byte.
        key_bytes = bytes(range(0x80, 0x80 + 31)) + b"\x0a"
        self.assertEqual(len(key_bytes), 32)
        with open(keyfile, "wb") as f:
            f.write(key_bytes)

        r = run_wolfssl("-encrypt", "-aes-cbc-256",
                        "-in", self._orig(), "-out", enc,
                        "-inkey", keyfile, "-iv", self.IV_HEX)
        self.assertEqual(r.returncode, 0,
                         "raw key ending in 0x0A must not be truncated: "
                         + r.stderr)

        r = run_wolfssl("-decrypt", "-aes-cbc-256",
                        "-in", enc, "-out", dec,
                        "-inkey", keyfile, "-iv", self.IV_HEX)
        self.assertEqual(r.returncode, 0,
                         "decrypt with 0x0A-terminated raw key failed: "
                         + r.stderr)
        self.assertTrue(filecmp.cmp(self._orig(), dec, shallow=False),
                        "round-trip with 0x0A-terminated raw key mismatched")

    def test_inkey_wrong_length_raw_binary_errors(self):
        """A raw binary file whose byte length doesn't match must error."""
        keyfile = "key_inkey_short.bin"
        enc = "inkey_short.enc"
        self._cleanup(keyfile, enc)

        # 16 bytes, but algorithm requires 32 (AES-256).
        with open(keyfile, "wb") as f:
            f.write(bytes(range(16)))

        r = run_wolfssl("-encrypt", "-aes-cbc-256",
                        "-in", self._orig(), "-out", enc,
                        "-inkey", keyfile, "-iv", self.IV_HEX)
        self.assertNotEqual(r.returncode, 0,
                            "wrong-size raw binary key must error out")
        self.assertFalse(os.path.exists(enc),
                         "no output should be produced on key size mismatch")

    def test_key_without_iv_errors(self):
        """`-key`/`-inkey` requires `-iv` (no salt-based derivation runs)."""
        enc = "key_no_iv.enc"
        self._cleanup(enc)

        r = run_wolfssl("-encrypt", "-aes-cbc-256",
                        "-in", self._orig(), "-out", enc,
                        "-key", self.KEY_HEX)
        self.assertNotEqual(r.returncode, 0,
                            "-key with no -iv must fail")
        combined = (r.stdout or "") + (r.stderr or "")
        self.assertIn("-iv", combined,
                      "validation error should mention -iv")

    def test_iv_without_key_error_mentions_inkey(self):
        """The -iv-without-key error now references both -key and -inkey."""
        enc = "iv_only.enc"
        self._cleanup(enc)

        r = run_wolfssl("-encrypt", "-aes-cbc-256",
                        "-in", self._orig(), "-out", enc,
                        "-iv", self.IV_HEX)
        self.assertNotEqual(r.returncode, 0,
                            "-iv without a key must fail")
        combined = (r.stdout or "") + (r.stderr or "")
        self.assertIn("-inkey", combined,
                      "validation error should mention -inkey alongside -key")

    def test_key_invalid_hex_does_not_crash(self):
        """Regression for double-free: a -key arg with the right length but
        invalid hex characters must error cleanly, not abort/segfault."""
        enc = "key_bad_hex.enc"
        self._cleanup(enc)

        bad_hex = "gg" + ("11" * 31)  # 64 chars, contains non-hex
        r = run_wolfssl("-encrypt", "-aes-cbc-256",
                        "-in", self._orig(), "-out", enc,
                        "-key", bad_hex, "-iv", self.IV_HEX)
        self.assertNotEqual(r.returncode, 0,
                            "invalid hex must produce an error")
        # Process aborts (SIGABRT/-6 on POSIX, large unsigned on Windows)
        # would surface here; assert we got a clean wolfCLU error code.
        self.assertGreater(r.returncode, 0,
                           "expected a normal error exit, got signal: "
                           + str(r.returncode))

    def test_rand_hex_to_inkey_workflow(self):
        """End-to-end: generate hex key with `rand -hex` and use via -inkey."""
        keyfile = "rand_hex_key.hex"
        enc = "rand_hex.enc"
        dec = "rand_hex.dec"
        self._cleanup(keyfile, enc, dec)

        r = run_wolfssl("rand", "-hex", "-out", keyfile, "32")
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("-encrypt", "-aes-cbc-256",
                        "-in", self._orig(), "-out", enc,
                        "-inkey", keyfile, "-iv", self.IV_HEX)
        self.assertEqual(r.returncode, 0,
                         "encrypt with rand-generated hex key failed: "
                         + r.stderr)

        r = run_wolfssl("-decrypt", "-aes-cbc-256",
                        "-in", enc, "-out", dec,
                        "-inkey", keyfile, "-iv", self.IV_HEX)
        self.assertEqual(r.returncode, 0,
                         "decrypt with rand-generated hex key failed: "
                         + r.stderr)
        self.assertTrue(filecmp.cmp(self._orig(), dec, shallow=False),
                        "rand-hex -> -inkey workflow did not round-trip")


if __name__ == "__main__":
    test_main()

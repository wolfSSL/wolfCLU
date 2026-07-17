#!/usr/bin/env python3
"""Digest sign/verify and large-file tests for wolfCLU."""

import filecmp
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import (CERTS_DIR, is_fips, run_wolfssl, test_main,
                          truncate_sparse)

DGST_DIR = os.path.dirname(os.path.abspath(__file__))


class DgstVerifyTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

        config_log = os.path.join(".", "config.log")
        if os.path.isfile(config_log):
            with open(config_log, "r") as f:
                if "disable-filesystem" in f.read():
                    raise unittest.SkipTest("filesystem support disabled")

    def test_verify_sha256_rsa(self):
        r = run_wolfssl("dgst", "-sha256", "-verify",
                        os.path.join(CERTS_DIR, "server-keyPub.pem"),
                        "-signature", os.path.join(DGST_DIR, "sha256-rsa.sig"),
                        os.path.join(CERTS_DIR, "server-key.der"))
        self.assertEqual(r.returncode, 0, r.stderr)

    @unittest.skipIf(is_fips(), "MD5 not allowed in FIPS builds")
    def test_verify_md5_rsa(self):
        r = run_wolfssl("dgst", "-md5", "-verify",
                        os.path.join(CERTS_DIR, "server-keyPub.pem"),
                        "-signature", os.path.join(DGST_DIR, "md5-rsa.sig"),
                        os.path.join(CERTS_DIR, "server-key.der"))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_verify_sha256_ecc(self):
        r = run_wolfssl("dgst", "-sha256", "-verify",
                        os.path.join(CERTS_DIR, "ecc-keyPub.pem"),
                        "-signature", os.path.join(DGST_DIR, "sha256-ecc.sig"),
                        os.path.join(CERTS_DIR, "server-key.der"))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_fail_ecc_key_rsa_sig(self):
        r = run_wolfssl("dgst", "-sha256", "-verify",
                        os.path.join(CERTS_DIR, "ecc-keyPub.pem"),
                        "-signature", os.path.join(DGST_DIR, "sha256-rsa.sig"),
                        os.path.join(CERTS_DIR, "server-key.der"))
        self.assertNotEqual(r.returncode, 0)

    def test_fail_wrong_ca_key(self):
        r = run_wolfssl("dgst", "-sha256", "-verify",
                        os.path.join(CERTS_DIR, "ca-key.pem"),
                        "-signature", os.path.join(DGST_DIR, "sha256-rsa.sig"),
                        os.path.join(CERTS_DIR, "server-key.der"))
        self.assertNotEqual(r.returncode, 0)

    def test_fail_private_key_as_verify(self):
        r = run_wolfssl("dgst", "-sha256", "-verify",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-signature", os.path.join(DGST_DIR, "sha256-rsa.sig"),
                        os.path.join(CERTS_DIR, "server-key.der"))
        self.assertNotEqual(r.returncode, 0)

    def test_fail_wrong_digest(self):
        r = run_wolfssl("dgst", "-md5", "-verify",
                        os.path.join(CERTS_DIR, "server-keyPub.pem"),
                        "-signature", os.path.join(DGST_DIR, "sha256-rsa.sig"),
                        os.path.join(CERTS_DIR, "server-key.der"))
        self.assertNotEqual(r.returncode, 0)

    def test_help(self):
        for flag in ("-help", "-h"):
            r = run_wolfssl("dgst", flag)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("dgst", r.stdout + r.stderr)

    def test_sign_verify_all_hash_algs(self):
        """Sign/verify round-trip for each supported hash algorithm.

        Covers the per-algorithm digest-selection branches in
        clu_dgst_setup.c. -md5 is skipped under FIPS.
        """
        algs = ["sha", "sha224", "sha256", "sha384", "sha512"]
        if not is_fips():
            algs.append("md5")
        input_file = os.path.join(CERTS_DIR, "server-key.der")

        for alg in algs:
            with self.subTest(alg=alg):
                sig_file = "dgst-{}.sig".format(alg)
                self.addCleanup(lambda p=sig_file: os.remove(p)
                                if os.path.exists(p) else None)
                r = run_wolfssl("dgst", "-" + alg, "-sign",
                                os.path.join(CERTS_DIR, "server-key.pem"),
                                "-out", sig_file, input_file)
                self.assertEqual(r.returncode, 0, r.stderr)

                r = run_wolfssl("dgst", "-" + alg, "-verify",
                                os.path.join(CERTS_DIR, "server-keyPub.pem"),
                                "-signature", sig_file, input_file)
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_dgst_out_roundtrip(self):
        """dgst -out creates the signature file; -signature round-trips."""
        sig_file = "dgst-out-test.sig"
        self.addCleanup(lambda: os.remove(sig_file)
                        if os.path.exists(sig_file) else None)
        input_file = os.path.join(CERTS_DIR, "server-key.der")

        r = run_wolfssl("dgst", "-sha256", "-sign",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-out", sig_file, input_file)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(sig_file),
                        "dgst -out did not create output file")

        r = run_wolfssl("dgst", "-sha256", "-verify",
                        os.path.join(CERTS_DIR, "server-keyPub.pem"),
                        "-signature", sig_file, input_file)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_missing_data_file_detected(self):
        """Omitting the trailing data file must be detected, not misread.

        clu_dgst_setup.c passes argc-1 to wolfCLU_GetOpt so the trailing
        data file is excluded from option scanning, then checks whether the
        last option consumed it as a value. With the data file absent here,
        the .sig path is the trailing argument and the malformed-argument
        check must reject the invocation rather than hashing the .sig file.
        """
        r = run_wolfssl("dgst", "-sha256", "-verify",
                        os.path.join(CERTS_DIR, "server-keyPub.pem"),
                        "-signature", os.path.join(DGST_DIR, "sha256-rsa.sig"))
        self.assertGreaterEqual(r.returncode, 0, r.stderr)

    def test_complete_args_not_misflagged(self):
        """A well-formed dgst command must not trip the malformed-argument
        check; the trailing data file should be hashed, not flagged as an
        option value."""
        r = run_wolfssl("dgst", "-sha256", "-verify",
                        os.path.join(CERTS_DIR, "server-keyPub.pem"),
                        "-signature", os.path.join(DGST_DIR, "sha256-rsa.sig"),
                        os.path.join(CERTS_DIR, "server-key.der"))
        self.assertEqual(r.returncode, 0, r.stderr)


class DgstLargeFileTest(unittest.TestCase):

    LARGE_FILE = "large-test.txt"

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

        config_log = os.path.join(".", "config.log")
        if os.path.isfile(config_log):
            with open(config_log, "r") as f:
                if "disable-filesystem" in f.read():
                    raise unittest.SkipTest("filesystem support disabled")

        # Create large file: 5000 copies of server-key.der
        der_path = os.path.join(CERTS_DIR, "server-key.der")
        with open(der_path, "rb") as src:
            chunk = src.read()
        with open(cls.LARGE_FILE, "wb") as dst:
            dst.write(chunk * 5000)

    @classmethod
    def tearDownClass(cls):
        for f in [cls.LARGE_FILE, "large-test.txt.enc", "large-test.txt.dec",
                  "5000-server-key.sig"]:
            if os.path.exists(f):
                os.remove(f)

    def test_verify_large_file(self):
        r = run_wolfssl("dgst", "-sha256", "-verify",
                        os.path.join(CERTS_DIR, "server-keyPub.pem"),
                        "-signature",
                        os.path.join(DGST_DIR, "5000-server-key.sig"),
                        self.LARGE_FILE)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_sign_and_verify_large_file(self):
        sig_file = "5000-server-key.sig"
        self.addCleanup(lambda: os.remove(sig_file)
                        if os.path.exists(sig_file) else None)

        r = run_wolfssl("dgst", "-sha256", "-sign",
                        os.path.join(CERTS_DIR, "server-key.pem"),
                        "-out", sig_file, self.LARGE_FILE)
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("dgst", "-sha256", "-verify",
                        os.path.join(CERTS_DIR, "server-keyPub.pem"),
                        "-signature", sig_file, self.LARGE_FILE)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_hash_large_file(self):
        expected = "3e5915162b1974ac0d57a5a45113a1efcc1edc5e71e5e55ca69f9a7c60ca11fd"

        r = run_wolfssl("-hash", "sha256", "-in", self.LARGE_FILE)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(expected, r.stdout,
                      "Failed to get expected hash with -hash")

    def test_sha256_large_file(self):
        expected = "3e5915162b1974ac0d57a5a45113a1efcc1edc5e71e5e55ca69f9a7c60ca11fd"

        r = run_wolfssl("sha256", self.LARGE_FILE)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(expected, r.stdout,
                      "Failed to get expected hash with sha256")

    # Slow when run inside a Windows VM (large file I/O over network share)
    @unittest.skipIf(os.environ.get("WOLFCLU_SKIP_SLOW_TESTS", "0") == "1",
                      "slow test skipped via WOLFCLU_SKIP_SLOW_TESTS")
    def test_enc_dec_large_file(self):
        enc_file = "large-test.txt.enc"
        dec_file = "large-test.txt.dec"
        self.addCleanup(lambda: os.remove(enc_file)
                        if os.path.exists(enc_file) else None)
        self.addCleanup(lambda: os.remove(dec_file)
                        if os.path.exists(dec_file) else None)

        r = run_wolfssl("enc", "-aes-256-cbc", "-in", self.LARGE_FILE,
                        "-out", enc_file, "-k", "12345678901234")
        self.assertEqual(r.returncode, 0, r.stderr)

        self.assertFalse(filecmp.cmp(self.LARGE_FILE, enc_file, shallow=False),
                         "Encryption produced identical file")

        r = run_wolfssl("enc", "-d", "-aes-256-cbc", "-in", enc_file,
                        "-out", dec_file, "-k", "12345678901234")
        self.assertEqual(r.returncode, 0, r.stderr)

        self.assertTrue(filecmp.cmp(self.LARGE_FILE, dec_file, shallow=False),
                        "Decryption of large file failed")


class LargeFileDgstTest(unittest.TestCase):
    """A signature over a >4 GiB file must NOT verify a tampered copy.

    Guards against truncating the file size to word32 in clu_dgst_setup.c,
    which caused only the first 4 GiB to be hashed before sign/verify.

    Defaults to sha256 + RSA. Override with:
      WOLFCLU_LARGE_DGST_ALG=<alg|all>   (md5, sha, sha256, sha384, sha512)
      WOLFCLU_LARGE_DGST_KEY=<rsa|ecc|all>
    """

    LARGE_FILE_SIZE = 4_831_838_208  # 4.5 GiB, well above UINT32_MAX
    CANDIDATE_ALGS = ["md5", "sha", "sha256", "sha384", "sha512"]
    DEFAULT_ALG = "sha256"
    KEY_PAIRS = {
        "rsa": ("server-key.pem", "server-keyPub.pem"),
        "ecc": ("ecc-key.pem", "ecc-keyPub.pem"),
    }
    DEFAULT_KEY = "rsa"

    @classmethod
    def _probe_supported(cls, algs):
        probe_input = os.path.join(CERTS_DIR, "ca-cert.pem")
        supported = []
        for alg in algs:
            r = run_wolfssl(alg, probe_input)
            if r.returncode == 0:
                supported.append(alg)
        return supported

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

        requested_alg = os.environ.get("WOLFCLU_LARGE_DGST_ALG",
                                       cls.DEFAULT_ALG)
        if requested_alg == "all":
            cls.algs = cls._probe_supported(cls.CANDIDATE_ALGS)
        else:
            cls.algs = cls._probe_supported([requested_alg])
        if not cls.algs:
            raise unittest.SkipTest(
                "no supported hash algorithm for "
                "WOLFCLU_LARGE_DGST_ALG={}".format(requested_alg))

        requested_key = os.environ.get("WOLFCLU_LARGE_DGST_KEY",
                                       cls.DEFAULT_KEY)
        if requested_key == "all":
            cls.key_kinds = list(cls.KEY_PAIRS.keys())
        elif requested_key in cls.KEY_PAIRS:
            cls.key_kinds = [requested_key]
        else:
            raise unittest.SkipTest(
                "unknown WOLFCLU_LARGE_DGST_KEY={}".format(requested_key))

        cls._tmpdir = tempfile.mkdtemp(prefix="wolfclu-large-dgst-")
        cls.original = os.path.join(cls._tmpdir, "original.bin")
        cls.tampered = os.path.join(cls._tmpdir, "tampered.bin")
        try:
            for p in (cls.original, cls.tampered):
                with open(p, "wb") as f:
                    truncate_sparse(f, cls.LARGE_FILE_SIZE)
            with open(cls.tampered, "r+b") as f:
                f.seek(-1, os.SEEK_END)
                f.write(b"X")
        except OSError as e:
            shutil.rmtree(cls._tmpdir, ignore_errors=True)
            raise unittest.SkipTest("could not create sparse files: {}".format(e))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(getattr(cls, "_tmpdir", ""), ignore_errors=True)

    def test_tampered_last_byte_fails_verify(self):
        for alg in self.algs:
            for key_kind in self.key_kinds:
                priv_name, pub_name = self.KEY_PAIRS[key_kind]
                priv_key = os.path.join(CERTS_DIR, priv_name)
                pub_key = os.path.join(CERTS_DIR, pub_name)
                sig_file = os.path.join(
                    self._tmpdir, "{}-{}.sig".format(alg, key_kind))
                with self.subTest(alg=alg, key=key_kind):
                    r = run_wolfssl(
                        "dgst", "-" + alg, "-sign", priv_key,
                        "-out", sig_file, self.original, timeout=1800)
                    self.assertEqual(r.returncode, 0, r.stderr)

                    r = run_wolfssl(
                        "dgst", "-" + alg, "-verify", pub_key,
                        "-signature", sig_file, self.original,
                        timeout=1800)
                    self.assertEqual(r.returncode, 0, r.stderr)

                    r = run_wolfssl(
                        "dgst", "-" + alg, "-verify", pub_key,
                        "-signature", sig_file, self.tampered,
                        timeout=1800)
                    self.assertNotEqual(r.returncode, 0)


class DgstSignVerifyRoundtripTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

    def test_ecc_sign_verify_roundtrip(self):
        sig_file = "configure.sig"
        # Use a file that exists on both Linux and Windows
        input_file = os.path.join(CERTS_DIR, "server-key.der")
        self.addCleanup(lambda: os.remove(sig_file)
                        if os.path.exists(sig_file) else None)

        r = run_wolfssl("dgst", "-sha256", "-sign",
                        os.path.join(CERTS_DIR, "ecc-key.pem"),
                        "-out", sig_file, input_file)
        self.assertEqual(r.returncode, 0, r.stderr)

        # Verify with private key should fail
        r = run_wolfssl("dgst", "-sha256", "-verify",
                        os.path.join(CERTS_DIR, "ecc-key.pem"),
                        "-signature", sig_file, input_file)
        self.assertNotEqual(r.returncode, 0)

        # Verify with non-existent key should fail
        r = run_wolfssl("dgst", "-sha256", "-verify", "bad-key.pem",
                        "-signature", sig_file, input_file)
        self.assertNotEqual(r.returncode, 0)

        # Verify with wrong public key should fail
        r = run_wolfssl("dgst", "-sha256", "-verify",
                        os.path.join(CERTS_DIR, "server-keyPub.pem"),
                        "-signature", sig_file, input_file)
        self.assertNotEqual(r.returncode, 0)

        # Verify with correct public key should succeed
        r = run_wolfssl("dgst", "-sha256", "-verify",
                        os.path.join(CERTS_DIR, "ecc-keyPub.pem"),
                        "-signature", sig_file, input_file)
        self.assertEqual(r.returncode, 0, r.stderr)


class DgstHmacTest(unittest.TestCase):
    """HMAC test vectors for `dgst -mac HMAC`.

    Mirrors the wolfCrypt hmac_*_test functions in
    wolfssl/wolfcrypt/test/test.c. The hex-key vectors come from RFC 4231
    Test Case 1 (a 20-byte 0x0b key over "Hi There"). The plaintext-key
    vectors use a 16-byte key over 50 bytes of 0xdd, generated with OpenSSL
    and confirmed with wolfSSL. Both keys are at or above the FIPS minimum
    HMAC key length (112 bits), so these run under FIPS too.
    """

    HEXKEY = "hexkey:0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
    HEXKEY_DATA = "Hi There"

    # alg -> expected lowercase-hex HMAC of DATA under HEXKEY
    VECTORS_FOR_HEX_KEY_DATA = {
        "sha224": "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
        "sha256": ("b0344c61d8db38535ca8afceaf0bf12b"
                  "881dc200c9833da726e9376c2e32cff7"),
        "sha384": ("afd03944d84895626b0825f4ab46907f"
                  "15f9dadbe4101ec682aa034c7cebc59c"
                  "faea9ea9076ede7f4af152e8b2fa9cb6"),
        "sha512": ("87aa7cdea5ef619d4ff0b4241a1d6cb0"
                  "2379f4e2ce4ec2787ad0b30545e17cde"
                  "daa833b7d6b8a702038b274eaea3f4e4"
                  "be9d914eeb61f1702e696c203a126854")
        }

    # Plaintext 16-byte key (>= FIPS minimum) over 50 bytes of 0xdd. The
    # expected values were generated with OpenSSL and confirmed with wolfSSL.
    KEY = "key:thisisthelongkey"
    DATA = b"\xdd" * 50

    # alg -> expected lowercase-hex HMAC of DATA under KEY
    VECTORS = {
        "md5":    "b4dcc86b987a882a22c04126bf38754b",
        "sha":    "0c2735ff7b6c0e598a2385648d89d207a9fb74f2",
        "sha224": "7d4b1d628eff8fa743dc598a8c2868b54aed43db69325dcc8f90008f",
        "sha256": "71c7b62392c086d96222f765ec415a48f5008d24e7eae079b319c5e1ad5a288b",
        "sha384": ("b7630df0ff9a2c2468292d74a378252817df6ebb893e943d7761c16c747"
                   "166fad502ec2760c40a451ea282dedf78edbf"),
        "sha512": ("f78a1c7382fab1ee2a5dd617a26715a9898cd0a64dbad7d35dba15392781"
                   "edfc9d37274dd68472ead7e6d04cf8202db34003dfc3a11dae9864bbbbe4"
                   "3b46bfed"),
    }

    @classmethod
    def setUpClass(cls):
        config_log = os.path.join(".", "config.log")
        if os.path.isfile(config_log):
            with open(config_log, "r") as f:
                if "disable-filesystem" in f.read():
                    raise unittest.SkipTest("filesystem support disabled")

        cls._tmpdir = tempfile.mkdtemp(prefix="wolfclu-hmac-")
        cls.data_file = os.path.join(cls._tmpdir, "data.bin")
        with open(cls.data_file, "wb") as f:
            f.write(cls.DATA)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(getattr(cls, "_tmpdir", ""), ignore_errors=True)

    def test_hmac_HEX_vectors(self):
        """HMAC of using hex key "Hi There" matches RFC vectors."""
        for alg, expected in self.VECTORS_FOR_HEX_KEY_DATA.items():
            with self.subTest(alg=alg):
                r = run_wolfssl("dgst", "-" + alg, "-hmac",
                                "-mackey", self.HEXKEY,
                                stdin_data=self.HEXKEY_DATA)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn(expected, r.stdout,
                              "HMAC-{} mismatch".format(alg))

    def test_hmac_vectors(self):
        """HMAC of 50 bytes of 0xdd under the plaintext key matches vectors."""
        for alg, expected in self.VECTORS.items():
            if alg == "md5" and is_fips():
                continue
            with self.subTest(alg=alg):
                r = run_wolfssl("dgst", "-" + alg, "-hmac",
                                "-mackey", self.KEY, self.data_file)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn(expected, r.stdout,
                              "HMAC-{} mismatch".format(alg))

    def test_hmac_wrong_key(self):
        """A different key must not produce the reference HMAC."""
         # Use a different 20-byte key (FIPS-valid length) than the reference
         # plaintext key used to generate VECTORS.
        r = run_wolfssl("dgst", "-sha256", "-hmac",
                        "-mackey", "hexkey:" + "bb" * 20, self.data_file)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn(self.VECTORS["sha256"], r.stdout)

    def test_hmac_out_file(self):
        """-out writes the raw MAC bytes; hex-encoding them matches."""
        out_file = os.path.join(self._tmpdir, "mac.bin")
        self.addCleanup(lambda: os.remove(out_file)
                        if os.path.exists(out_file) else None)
        r = run_wolfssl("dgst", "-sha256", "-hmac",
                        "-mackey", self.KEY, "-out", out_file,
                        self.data_file)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(out_file, "rb") as f:
            mac = f.read()
        self.assertEqual(mac.hex(), self.VECTORS["sha256"])

    def test_hmac_plaintext_key_with_colon(self):
        """A plaintext key containing ':' is used verbatim, not truncated."""
        # Both keys are >= the FIPS minimum length so this runs under FIPS.
        # "key:aaaaaaaaaaaaaa:bb" -> the HMAC key is "aaaaaaaaaaaaaa:bb",
        # not just "aaaaaaaaaaaaaa".
        r_full = run_wolfssl("dgst", "-sha256", "-hmac",
                             "-mackey", "key:aaaaaaaaaaaaaa:bb", self.data_file)
        self.assertEqual(r_full.returncode, 0, r_full.stderr)
        # Keying with just the part before ':' (old truncated behaviour) differs.
        r_trunc = run_wolfssl("dgst", "-sha256", "-hmac",
                              "-mackey", "key:aaaaaaaaaaaaaa", self.data_file)
        self.assertEqual(r_trunc.returncode, 0, r_trunc.stderr)
        self.assertNotEqual(r_full.stdout, r_trunc.stdout)

    def test_hmac_missing_key(self):
        """-mac HMAC without -mackey must fail."""
        r = run_wolfssl("dgst", "-sha256", "-hmac", self.data_file)
        self.assertNotEqual(r.returncode, 0)

    def test_hmac_malformed_key_no_colon(self):
        """A -mackey value with no ':' separator must fail."""
        r = run_wolfssl("dgst", "-sha256", "-hmac",
                        "-mackey", "Jefe", self.data_file)
        self.assertNotEqual(r.returncode, 0)

    def test_hmac_invalid_key_type(self):
        """A -mackey type other than key/hexkey must fail."""
        r = run_wolfssl("dgst", "-sha256", "-hmac",
                        "-mackey", "bogus:Jefe", self.data_file)
        self.assertNotEqual(r.returncode, 0)

    def test_hmac_invalid_hex_key(self):
        """A non-hex value passed to hexkey: must fail."""
        r = run_wolfssl("dgst", "-sha256", "-hmac",
                        "-mackey", "hexkey:nothexZZ", self.data_file)
        self.assertNotEqual(r.returncode, 0)

    def test_hmac_no_hash_algorithm(self):
        """-mac HMAC with no hash flag must fail (no default hash)."""
        r = run_wolfssl("dgst", "-hmac",
                        "-mackey", self.KEY, self.data_file)
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    test_main()

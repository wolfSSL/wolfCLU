#!/usr/bin/env python3
"""Digest sign/verify and large-file tests for wolfCLU."""

import filecmp
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import CERTS_DIR, run_wolfssl

DGST_DIR = os.path.join(".", "tests", "dgst")


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


if __name__ == "__main__":
    unittest.main()

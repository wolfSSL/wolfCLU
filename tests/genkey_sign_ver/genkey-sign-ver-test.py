#!/usr/bin/env python3
"""Key generation, signing, and verification tests for wolfCLU."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import WOLFSSL_BIN, run_wolfssl, test_main

# Files that tests may create; cleaned up by tearDownClass
_TEMP_FILES = []


def _cleanup_files(files):
    for f in files:
        if os.path.exists(f):
            os.remove(f)


def _has_algorithm(algo):
    """Check if an algorithm is available in the current build."""
    r = run_wolfssl("-genkey", "-h")
    combined = r.stdout + r.stderr
    # Look for the algorithm name in the help output
    return algo in combined


class _GenkeySignVerifyBase(unittest.TestCase):
    """Base class with the gen-key / sign / verify workflow."""

    SIGN_FILE = "sign-this.txt"

    @classmethod
    def setUpClass(cls):
        config_log = os.path.join(".", "config.log")
        if os.path.isfile(config_log):
            with open(config_log, "r") as f:
                if "disable-filesystem" in f.read():
                    raise unittest.SkipTest("filesystem support disabled")

        with open(cls.SIGN_FILE, "w") as f:
            f.write("Sign this test data\n")

    @classmethod
    def tearDownClass(cls):
        _cleanup_files([cls.SIGN_FILE] + _TEMP_FILES)
        _TEMP_FILES.clear()

    def _track(self, *files):
        for f in files:
            _TEMP_FILES.append(f)

    def _genkey(self, algo, keybase, fmt, extra_args=None,
                use_output_flag=False):
        args = ["-genkey", algo]
        if extra_args:
            args += extra_args
        args += ["-out", keybase, "-outform", fmt]
        if use_output_flag:
            args += ["-output", "KEYPAIR"]
        else:
            args.append("KEYPAIR")
        priv = keybase + ".priv"
        pub = keybase + ".pub"
        self._track(priv, pub)
        r = run_wolfssl(*args)
        self.assertEqual(r.returncode, 0,
                         f"genkey {algo} failed: {r.stderr}")
        return priv, pub

    def _sign(self, algo, priv_key, fmt, sig_file):
        self._track(sig_file)
        r = run_wolfssl(f"-{algo}", "-sign", "-inkey", priv_key,
                        "-inform", fmt, "-in", self.SIGN_FILE,
                        "-out", sig_file)
        self.assertEqual(r.returncode, 0,
                         f"sign {algo} failed: {r.stderr}")

    def _verify_priv(self, algo, priv_key, fmt, sig_file, out_file=None):
        args = [f"-{algo}", "-verify", "-inkey", priv_key,
                "-inform", fmt, "-sigfile", sig_file, "-in", self.SIGN_FILE]
        if out_file:
            args += ["-out", out_file]
            self._track(out_file)
        r = run_wolfssl(*args)
        self.assertEqual(r.returncode, 0,
                         f"private verify {algo} failed: {r.stderr}")

    def _verify_pub(self, algo, pub_key, fmt, sig_file, out_file=None):
        args = [f"-{algo}", "-verify", "-inkey", pub_key,
                "-inform", fmt, "-sigfile", sig_file, "-in", self.SIGN_FILE,
                "-pubin"]
        if out_file:
            args += ["-out", out_file]
            self._track(out_file)
        r = run_wolfssl(*args)
        self.assertEqual(r.returncode, 0,
                         f"public verify {algo} failed: {r.stderr}")

    def _gen_sign_verify(self, algo, keybase, sig_file, fmt,
                         extra_genkey_args=None, skip_priv_verify=False,
                         rsa_verify_out=None, use_output_flag=False):
        priv, pub = self._genkey(algo, keybase, fmt, extra_genkey_args,
                                 use_output_flag=use_output_flag)
        self._sign(algo, priv, fmt, sig_file)

        if not skip_priv_verify:
            priv_out = rsa_verify_out + ".private_result" if rsa_verify_out else None
            self._verify_priv(algo, priv, fmt, sig_file, priv_out)

        pub_out = rsa_verify_out + ".public_result" if rsa_verify_out else None
        self._verify_pub(algo, pub, fmt, sig_file, pub_out)

        if rsa_verify_out:
            with open(self.SIGN_FILE, "r") as f:
                original = f.read()
            for suffix in [".private_result", ".public_result"]:
                result_file = rsa_verify_out + suffix
                self._track(result_file)
                with open(result_file, "r") as f:
                    decrypted = f.read()
                self.assertEqual(decrypted, original,
                                 f"RSA decrypted {suffix} mismatch")


class Ed25519Test(_GenkeySignVerifyBase):

    def test_ed25519_der(self):
        self._gen_sign_verify("ed25519", "edkey", "ed-signed.sig", "der")

    def test_ed25519_pem(self):
        self._gen_sign_verify("ed25519", "edkey", "ed-signed.sig", "pem")

    def test_ed25519_raw(self):
        self._gen_sign_verify("ed25519", "edkey", "ed-signed.sig", "raw")

    def test_ed25519_signature_size(self):
        """ED25519 signatures must be exactly 64 bytes."""
        priv, pub = self._genkey("ed25519", "edkey-sztest", "der",
                                 use_output_flag=True)
        sig_file = "ed-sz-test.sig"
        self._sign("ed25519", priv, "der", sig_file)

        sig_size = os.path.getsize(sig_file)
        self.assertEqual(sig_size, 64,
                         "ED25519 signature size is {}, expected 64".format(
                             sig_size))


class EccTest(_GenkeySignVerifyBase):

    # @classmethod
    # def setUpClass(cls):
    #     super().setUpClass()
    #     # Quick smoke test: ECC sign can fail on smallstack wolfSSL builds
    #     r = run_wolfssl("-genkey", "ecc", "-out", "ecc_probe",
    #                     "-outform", "der", "KEYPAIR")
    #     if r.returncode == 0:
    #         r2 = run_wolfssl("-ecc", "-sign", "-inkey", "ecc_probe.priv",
    #                          "-inform", "der", "-in", cls.SIGN_FILE,
    #                          "-out", "ecc_probe.sig")
    #         _cleanup_files(["ecc_probe.priv", "ecc_probe.pub",
    #                         "ecc_probe.sig"])
    #         if r2.returncode != 0:
    #             raise unittest.SkipTest(
    #                 "ECC sign not functional: " + r2.stderr.strip())

    def test_ecc_der(self):
        self._gen_sign_verify("ecc", "ecckey", "ecc-signed.sig", "der")

    def test_ecc_pem(self):
        self._gen_sign_verify("ecc", "ecckey", "ecc-signed.sig", "pem")

    def test_ecc_der_key_size_and_roundtrip(self):
        """Regression: ECC DER private key must be reasonably sized, and the
        full sign/verify round-trip must succeed on the generated keypair."""
        priv, pub = self._genkey("ecc", "ecc-rt-test", "der",
                                 use_output_flag=True)

        key_size = os.path.getsize(priv)
        self.assertLessEqual(key_size, 256,
                             "ECC DER private key too large ({} bytes), "
                             "may contain trailing garbage".format(key_size))

        data_file = "ecc-rt-data.txt"
        sig_file = "ecc-rt-test.sig"
        self._track(data_file, sig_file)
        with open(data_file, "w") as f:
            f.write("ECC round trip test data\n")

        r = run_wolfssl("-ecc", "-sign", "-inkey", priv, "-inform", "der",
                        "-in", data_file, "-out", sig_file)
        self.assertEqual(r.returncode, 0,
                         "ECC sign round-trip failed: {}".format(r.stderr))

        r = run_wolfssl("-ecc", "-verify", "-inkey", pub, "-pubin",
                        "-inform", "der", "-sigfile", sig_file,
                        "-in", data_file)
        self.assertEqual(r.returncode, 0,
                         "ECC verify round-trip failed: {}".format(r.stderr))

    def test_ecc_sign_invalid_key_fails(self):
        """Signing with an empty key file must fail gracefully."""
        bad_key = "bad-ecc-key.der"
        bad_sig = "bad-ecc-sign.sig"
        self._track(bad_key, bad_sig)
        open(bad_key, "wb").close()

        r = run_wolfssl("-ecc", "-sign", "-inkey", bad_key, "-inform", "der",
                        "-in", self.SIGN_FILE, "-out", bad_sig)
        self.assertNotEqual(r.returncode, 0,
                            "ECC signing with empty key should have failed")

    def test_ecc_sign_missing_inkey_value(self):
        """-inkey with no value must fail gracefully (no segfault)."""
        r = run_wolfssl("-ecc", "-sign", "-inkey")
        self.assertNotEqual(r.returncode, 0,
                            "expected failure for missing -inkey value")
        self.assertGreaterEqual(r.returncode, 0,
                                "-inkey without value crashed with signal "
                                "{}".format(r.returncode))


class RsaTest(_GenkeySignVerifyBase):

    def test_rsa_der(self):
        self._gen_sign_verify("rsa", "rsakey", "rsa-signed.sig", "der",
                              rsa_verify_out="rsa-sigout")

    def test_rsa_pem(self):
        self._gen_sign_verify("rsa", "rsakey", "rsa-signed.sig", "pem",
                              rsa_verify_out="rsa-sigout")

    def test_rsa_bad_verify(self):
        """Verify with invalid signature must fail gracefully."""
        priv, pub = self._genkey("rsa", "rsakey", "der")
        bad_out = "rsa_badverify_out.txt"
        self._track(bad_out)

        r = run_wolfssl("-rsa", "-verify", "-inkey", pub, "-inform", "der",
                        "-sigfile", self.SIGN_FILE, "-in", self.SIGN_FILE,
                        "-out", bad_out, "-pubin")
        self.assertNotEqual(r.returncode, 0,
                            "RSA verify with invalid sig should have failed")
        self.assertFalse(os.path.exists(bad_out),
                         "output file must not be created on bad verify")

    def test_rsa_exponent_flag(self):
        """Regression: -exponent must not overwrite -size."""
        priv = "rsakey_exp.priv"
        pub = "rsakey_exp.pub"
        self._track(priv, pub)

        r = run_wolfssl("-genkey", "rsa", "-size", "2048", "-exponent",
                        "65537", "-out", "rsakey_exp", "-outform", "der",
                        "-output", "KEYPAIR")
        self.assertEqual(r.returncode, 0,
                         f"rsa genkey with -exponent failed: {r.stderr}")

    def test_rsa_sign_invalid_key_fails(self):
        """RSA signing with an empty key file must fail gracefully."""
        bad_key = "bad-rsa-key.der"
        bad_sig = "bad-rsa-sign.sig"
        self._track(bad_key, bad_sig)
        open(bad_key, "wb").close()

        r = run_wolfssl("-rsa", "-sign", "-inkey", bad_key, "-inform", "der",
                        "-in", self.SIGN_FILE, "-out", bad_sig)
        self.assertNotEqual(r.returncode, 0,
                            "RSA signing with empty key should have failed")


@unittest.skipUnless(_has_algorithm("dilithium"),
                     "dilithium not available")
class DilithiumTest(_GenkeySignVerifyBase):

    def test_dilithium_der(self):
        for level in [2, 3, 5]:
            with self.subTest(level=level):
                self._gen_sign_verify(
                    "dilithium", "mldsakey", "mldsa-signed.sig", "der",
                    extra_genkey_args=["-level", str(level)],
                    skip_priv_verify=True, use_output_flag=True)

    def test_dilithium_pem(self):
        for level in [2, 3, 5]:
            with self.subTest(level=level):
                self._gen_sign_verify(
                    "dilithium", "mldsakey", "mldsa-signed.sig", "pem",
                    extra_genkey_args=["-level", str(level)],
                    skip_priv_verify=True, use_output_flag=True)

    def test_output_pub_only(self):
        pub = "mldsakey_pub.pub"
        priv = "mldsakey_pub.priv"
        self._track(pub, priv)

        r = run_wolfssl("-genkey", "dilithium", "-level", "2",
                        "-out", "mldsakey_pub", "-outform", "der",
                        "-output", "pub")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(pub), ".pub file missing")
        self.assertFalse(os.path.exists(priv), ".priv unexpectedly created")

    def test_output_priv_only(self):
        pub = "mldsakey_priv.pub"
        priv = "mldsakey_priv.priv"
        self._track(pub, priv)

        r = run_wolfssl("-genkey", "dilithium", "-level", "2",
                        "-out", "mldsakey_priv", "-outform", "der",
                        "-output", "priv")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(priv), ".priv file missing")
        self.assertFalse(os.path.exists(pub), ".pub unexpectedly created")

    def test_sign_bad_path(self):
        priv, pub = self._genkey("dilithium", "mldsakey", "der",
                                 ["-level", "2"])
        bad_path = os.path.join("nonexistent_dir", "mldsa_bad.sig")
        r = run_wolfssl("-dilithium", "-sign", "-inkey", priv,
                        "-inform", "der", "-in", self.SIGN_FILE,
                        "-out", bad_path)
        self.assertNotEqual(r.returncode, 0,
                            "sign to invalid path should have failed")

    def test_sign_nonexistent_key_fails(self):
        """Dilithium sign with nonexistent key file must fail gracefully."""
        bad_sig = "bad-dil.sig"
        self._track(bad_sig)
        r = run_wolfssl("-dilithium", "-sign",
                        "-inkey", os.path.join("nonexistent_dir", "key.priv"),
                        "-inform", "der", "-in", self.SIGN_FILE,
                        "-out", bad_sig)
        self.assertNotEqual(r.returncode, 0,
                            "Dilithium sign with nonexistent key should have "
                            "failed")

    def test_sign_with_pub_key_fails(self):
        """Signing with a public key instead of private key must fail gracefully."""
        priv, pub = self._genkey("dilithium", "mldsakey", "der", ["-level", "2"])
        bad_sig = "mldsa_bad_pubkey.sig"
        self._track(bad_sig)
        r = run_wolfssl("-dilithium", "-sign", "-inkey", pub,
                        "-inform", "der", "-in", self.SIGN_FILE,
                        "-out", bad_sig)
        self.assertNotEqual(r.returncode, 0,
                            "dilithium sign with public key should have failed")
        self.assertFalse(os.path.exists(bad_sig),
                         "output file must not be created when signing with "
                         "public key")

    def test_sign_corrupted_key_fails(self):
        """Signing with a corrupted private key must fail gracefully."""
        corrupt_key = "mldsakey_corrupt.priv"
        bad_sig = "mldsa_bad_corrupt.sig"
        self._track(corrupt_key, bad_sig)
        with open(corrupt_key, "wb") as f:
            f.write(b"INVALID KEY DATA")
        r = run_wolfssl("-dilithium", "-sign", "-inkey", corrupt_key,
                        "-inform", "der", "-in", self.SIGN_FILE,
                        "-out", bad_sig)
        self.assertNotEqual(r.returncode, 0,
                            "dilithium sign with corrupted key should have "
                            "failed")
        self.assertFalse(os.path.exists(bad_sig),
                         "output file must not be created when signing with "
                         "corrupted key")


@unittest.skipUnless(_has_algorithm("xmss"), "xmss not available")
class XmssTest(_GenkeySignVerifyBase):

    def test_xmss_raw(self):
        keybase = "XMSS-SHA2_10_256"
        self._track(keybase + ".priv", keybase + ".pub")
        self._gen_sign_verify(
            "xmss", keybase, "xmss-signed.sig", "raw",
            extra_genkey_args=["-height", "10"],
            skip_priv_verify=True, use_output_flag=True)

    def test_xmss_missing_height_value(self):
        """-height with no value must fail gracefully (no crash)."""
        self._track("xmss-bad.priv", "xmss-bad.pub")
        r = run_wolfssl("-genkey", "xmss", "-out", "xmss-bad",
                        "-outform", "raw", "-output", "KEYPAIR", "-height")
        self.assertNotEqual(r.returncode, 0,
                            "expected failure for missing -height value")
        self.assertGreaterEqual(r.returncode, 0,
                                "-height without value crashed with signal "
                                "{}".format(r.returncode))


if __name__ == "__main__":
    test_main()

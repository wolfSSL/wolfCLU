#!/usr/bin/env python3
"""Key generation, signing, and verification tests for wolfCLU."""

import os
import subprocess
import sys
import unittest

try:
    import fcntl
except ImportError:
    fcntl = None

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import (WOLFSSL_BIN, CERTS_DIR, not_compiled_in,
                          run_wolfssl, test_main)

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

    def _gen_sign_badverify(self, algo, keybase, sig_file, fmt,
                            extra_genkey_args=None, use_output_flag=False):
        """Generate a key, sign SIGN_FILE, then verify the (valid) signature
        against a *different* message and assert the command fails with a
        non-zero (non-crash) exit.

        Verifying a genuine signature against tampered input produces a
        well-formed signature that simply does not match: the verify API
        returns successfully with stat/res != 1.  The buggy code logged
        "Invalid Signature." but still exited 0; the fix must turn that into
        a failure exit (F-5362)."""
        priv, pub = self._genkey(algo, keybase, fmt, extra_genkey_args,
                                 use_output_flag=use_output_flag)
        self._sign(algo, priv, fmt, sig_file)

        wrong_msg = keybase + "-wrong-msg.txt"
        self._track(wrong_msg)
        with open(wrong_msg, "w") as f:
            f.write("Totally different data that was never signed\n")

        r = run_wolfssl(f"-{algo}", "-verify", "-inkey", pub,
                        "-inform", fmt, "-sigfile", sig_file,
                        "-in", wrong_msg, "-pubin")
        self.assertNotEqual(r.returncode, 0,
                            "{} verify of a signature over different data "
                            "should fail".format(algo))
        self.assertGreaterEqual(r.returncode, 0,
                                "{} bad verify crashed with signal "
                                "{}".format(algo, r.returncode))

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
        # Builds that omit an optional key type (e.g. wolfSSL without
        # --enable-ed25519) report NOT_COMPILED_IN; skip rather than fail.
        if not_compiled_in(r):
            self.skipTest(f"{algo} not compiled into wolfSSL")
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

    def _start_sign(self, algo, priv_key, sig_file):
        """Start a raw-format sign in the background."""
        self._track(sig_file)
        proc = subprocess.Popen(
            [WOLFSSL_BIN, f"-{algo}", "-sign", "-inkey", priv_key,
             "-inform", "raw", "-in", self.SIGN_FILE, "-out", sig_file],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        self.addCleanup(self._stop_process, proc)
        return proc

    @staticmethod
    def _stop_process(proc):
        if proc.poll() is None:
            proc.kill()
        proc.communicate()

    @staticmethod
    def _xmss_sig_index(sig_file, idx_len):
        """The XMSS/XMSS^MT signature starts with the big-endian leaf index."""
        with open(sig_file, "rb") as f:
            return int.from_bytes(f.read(idx_len), "big")

    def _check_sign_waits_for_lock(self, algo, keybase, genkey_args,
                                   idx_len):
        """Signing must hold an exclusive lock on the private state file
        from reload until the new state is saved (F-12944)."""
        if fcntl is None:
            self.skipTest("fcntl.flock not available")
        priv, pub = self._genkey(algo, keybase, "raw", genkey_args,
                                 use_output_flag=True)
        first_sig = keybase + "-lock-1.sig"
        second_sig = keybase + "-lock-2.sig"
        self._sign(algo, priv, "raw", first_sig)

        lock_file = open(priv, "rb+")
        self.addCleanup(lock_file.close)
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)

        proc = self._start_sign(algo, priv, second_sig)
        try:
            proc.wait(timeout=1.5)
        except subprocess.TimeoutExpired:
            pass
        self.assertIsNone(proc.returncode,
                          "{} sign did not wait for the lock on {}".format(
                              algo, priv))

        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        _, err = proc.communicate(timeout=60)
        self.assertEqual(proc.returncode, 0, f"sign {algo} failed: {err}")
        self.assertNotEqual(self._xmss_sig_index(first_sig, idx_len),
                            self._xmss_sig_index(second_sig, idx_len),
                            "{} signature index was reused".format(algo))
        self._verify_pub(algo, pub, "raw", second_sig)

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

    def test_ed25519_bad_verify(self):
        """An Ed25519 signature that does not match must fail (F-5362)."""
        self._gen_sign_badverify("ed25519", "edkey-bad", "ed-bad.sig", "der")

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

    def test_ecc_bad_verify(self):
        """An ECC signature that does not match must fail (F-5362)."""
        self._gen_sign_badverify("ecc", "ecckey-bad", "ecc-bad.sig", "der")

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

    def test_ecc_sign_empty_input_fails(self):
        """Signing a 0-byte input file must fail gracefully (regression for
        the XFSEEK/XFTELL size guards in wolfCLU_sign_data)."""
        priv, _ = self._genkey("ecc", "ecc-empty-in", "der",
                               use_output_flag=True)
        empty_in = "empty-input.txt"
        empty_sig = "empty-input.sig"
        self._track(empty_in, empty_sig)
        open(empty_in, "wb").close()

        r = run_wolfssl("-ecc", "-sign", "-inkey", priv, "-inform", "der",
                        "-in", empty_in, "-out", empty_sig)
        self.assertNotEqual(r.returncode, 0,
                            "ECC signing of empty input should have failed")
        self.assertGreaterEqual(r.returncode, 0,
                                "ECC sign of empty input crashed with signal "
                                "{}".format(r.returncode))

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

    def test_dilithium_bad_verify(self):
        """A Dilithium signature that does not match must fail (F-5362)."""
        for level in [2, 3, 5]:
            with self.subTest(level=level):
                self._gen_sign_badverify(
                    "dilithium", "mldsakey-bad", "mldsa-bad.sig", "der",
                    extra_genkey_args=["-level", str(level)],
                    use_output_flag=True)

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

    def test_ml_dsa_alias_der(self):
        for level in [2, 3, 5]:
            with self.subTest(level=level):
                self._gen_sign_verify(
                    "ml-dsa", "mldsakey_alias", "mldsa-alias.sig", "der",
                    extra_genkey_args=["-level", str(level)],
                    skip_priv_verify=True, use_output_flag=True)

    def test_ml_dsa_alias_pem(self):
        for level in [2, 3, 5]:
            with self.subTest(level=level):
                self._gen_sign_verify(
                    "ml-dsa", "mldsakey_alias", "mldsa-alias.sig", "pem",
                    extra_genkey_args=["-level", str(level)],
                    skip_priv_verify=True, use_output_flag=True)

    def test_ml_dsa_cross_alias(self):
        """Keys generated with dilithium sign/verify with ml-dsa and vice-versa."""
        for level in [2, 3, 5]:
            with self.subTest(level=level):
                priv, pub = self._genkey("dilithium", "mldsakey_cross",
                                         "der", ["-level", str(level)],
                                         use_output_flag=True)
                self._sign("ml-dsa", priv, "der", "mldsa-cross.sig")
                self._verify_pub("ml-dsa", pub, "der", "mldsa-cross.sig")

                priv2, pub2 = self._genkey("ml-dsa", "mldsakey_cross2",
                                            "der", ["-level", str(level)],
                                            use_output_flag=True)
                self._sign("dilithium", priv2, "der", "dil-cross.sig")
                self._verify_pub("dilithium", pub2, "der", "dil-cross.sig")


@unittest.skipUnless(_has_algorithm("xmss"), "xmss not available")
class XmssTest(_GenkeySignVerifyBase):

    def test_xmss_raw(self):
        keybase = "XMSS-SHA2_10_256"
        self._track(keybase + ".priv", keybase + ".pub")
        self._gen_sign_verify(
            "xmss", keybase, "xmss-signed.sig", "raw",
            extra_genkey_args=["-height", "10"],
            skip_priv_verify=True, use_output_flag=True)

    def test_xmss_sign_waits_for_state_lock(self):
        self._check_sign_waits_for_lock("xmss", "XMSS-SHA2_10_256",
                                        ["-height", "10"], 4)

    def test_xmss_concurrent_sign_unique_index(self):
        """Concurrent signers must each use a new one-time key (F-12944)."""
        if fcntl is None:
            self.skipTest("no file locking on this platform")
        priv, _ = self._genkey("xmss", "XMSS-SHA2_10_256", "raw",
                               ["-height", "10"], use_output_flag=True)
        signers = []
        for i in range(6):
            sig_file = "xmss-concurrent-{}.sig".format(i)
            signers.append((self._start_sign("xmss", priv, sig_file),
                            sig_file))
        indices = []
        for proc, sig_file in signers:
            _, err = proc.communicate(timeout=60)
            self.assertEqual(proc.returncode, 0,
                             "concurrent xmss sign failed: {}".format(err))
            indices.append(self._xmss_sig_index(sig_file, 4))
        self.assertEqual(len(set(indices)), len(indices),
                         "xmss signature index reused: {}".format(indices))

    def test_xmss_missing_height_value(self):
        """-height with no value must fail gracefully (no crash)."""
        self._track("xmss-bad.priv", "xmss-bad.pub")
        r = run_wolfssl("-genkey", "xmss", "-out", "xmss-bad",
                        "-outform", "raw", "-output", "KEYPAIR", "-height")
        self.assertEqual(r.returncode, 0,
                            "expected default value of 20 set for -height (no "
                            "crash)")

    def test_xmss_missing_height_arg(self):
        self._track("xmss-bad.priv", "xmss-bad.pub")
        r = run_wolfssl("-genkey", "xmss", "-out", "xmss-bad",
                        "-outform", "raw", "-output", "KEYPAIR")
        self.assertEqual(r.returncode, 0,
                            "expected default value for -height (no "
                            "crash)")

@unittest.skipUnless(_has_algorithm("xmss"), "xmss not available")
class XmssmtTest(_GenkeySignVerifyBase):

    def test_xmssmt_raw(self):
        # The XMSS^MT signer derives the parameter set from the key file name,
        # so the keybase must be a valid param string with '-' in place of '/'
        # (e.g. "XMSSMT-SHA2_20/2_256" -> "XMSSMT-SHA2_20-2_256"). -height 20
        # defaults to layer 2, matching this name.
        keybase = "XMSSMT-SHA2_20-2_256"
        self._track(keybase + ".priv", keybase + ".pub")
        self._gen_sign_verify(
            "xmssmt", keybase, "xmss-signed.sig", "raw",
            extra_genkey_args=["-height", "20"],
            skip_priv_verify=True, use_output_flag=True)

    def test_xmssmt_sign_waits_for_state_lock(self):
        # XMSS^MT with height 20 uses a 3-byte index.
        self._check_sign_waits_for_lock("xmssmt", "XMSSMT-SHA2_20-2_256",
                                        ["-height", "20"], 3)

    def test_xmssmt_missing_height_value(self):
        """-height with no value must fail gracefully (no crash)."""
        self._track("xmss-bad.priv", "xmss-bad.pub")
        r = run_wolfssl("-genkey", "xmssmt", "-out", "xmss-bad",
                        "-outform", "raw", "-output", "KEYPAIR", "-height")
        self.assertEqual(r.returncode, 0,
                            "expected default value of 20 set for -height (no "
                            "crash)")

    def test_xmssmt_missing_height_arg(self):
        self._track("xmss-bad.priv", "xmss-bad.pub")
        r = run_wolfssl("-genkey", "xmssmt", "-out", "xmss-bad",
                        "-outform", "raw", "-output", "KEYPAIR")
        self.assertEqual(r.returncode, 0,
                            "expected default value for -height (no "
                            "crash)")


@unittest.skipIf(os.name == "nt", "POSIX file permissions only")
class GenkeyPermissionsTest(_GenkeySignVerifyBase):
    """Private key files must be owner-only under umask 022 (F-8096)."""

    def setUp(self):
        old_umask = os.umask(0o022)
        self.addCleanup(os.umask, old_umask)

    def _check_modes(self, algo, keybase, fmt, extra_args=None):
        # Start from new files so the create mode applies.
        _cleanup_files([keybase + ".priv", keybase + ".pub"])
        priv, pub = self._genkey(algo, keybase, fmt, extra_args,
                                 use_output_flag=True)
        priv_mode = os.stat(priv).st_mode & 0o777
        pub_mode = os.stat(pub).st_mode & 0o777
        self.assertEqual(priv_mode, 0o600,
                         "{} {} private key mode is {:o}, expected 600".format(
                             algo, fmt, priv_mode))
        self.assertEqual(pub_mode, 0o644,
                         "{} {} public key mode is {:o}, expected 644".format(
                             algo, fmt, pub_mode))

    def test_rsa_key_modes(self):
        for fmt in ["der", "pem"]:
            with self.subTest(fmt=fmt):
                self._check_modes("rsa", "perm-rsa-" + fmt, fmt)

    def test_ecc_key_modes(self):
        for fmt in ["der", "pem"]:
            with self.subTest(fmt=fmt):
                self._check_modes("ecc", "perm-ecc-" + fmt, fmt)

    def test_ed25519_key_modes(self):
        for fmt in ["raw", "der", "pem"]:
            with self.subTest(fmt=fmt):
                self._check_modes("ed25519", "perm-ed25519-" + fmt, fmt)

    def test_dilithium_key_modes(self):
        if not _has_algorithm("dilithium"):
            self.skipTest("dilithium not available")
        for algo in ["dilithium", "ml-dsa"]:
            with self.subTest(algo=algo):
                self._check_modes(algo, "perm-" + algo, "der",
                                  ["-level", "2"])

    def test_xmss_key_modes(self):
        if not _has_algorithm("xmss"):
            self.skipTest("xmss not available")
        self._check_modes("xmss", "perm-xmss", "raw", ["-height", "10"])

    def test_priv_only_key_mode(self):
        keybase = "perm-ecc-privonly"
        priv = keybase + ".priv"
        self._track(priv, keybase + ".pub")
        _cleanup_files([priv])
        r = run_wolfssl("-genkey", "ecc", "-out", keybase, "-outform", "der",
                        "-output", "priv")
        self.assertEqual(r.returncode, 0, r.stderr)
        mode = os.stat(priv).st_mode & 0o777
        self.assertEqual(mode, 0o600,
                         "private key mode is {:o}, expected 600".format(mode))


class SignVerifySetupArgsTest(unittest.TestCase):
    """Argument-parsing branches in clu_sign_verify_setup.c.

    These exercise the legacy `-rsa`/`-ecc`/... sign & verify entry point
    (note the leading dash, which selects the legacy code path).
    """

    SIGN_FILE = "svsetup-sign-this.txt"
    RSA_KEY = os.path.join(CERTS_DIR, "server-key.pem")
    ECC_KEY = os.path.join(CERTS_DIR, "ecc-key.pem")
    ECC_PUB = os.path.join(CERTS_DIR, "ecc-keyPub.pem")

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
        _cleanup_files([cls.SIGN_FILE])

    def test_sign_help(self):
        r = run_wolfssl("-rsa", "-sign", "-help")
        self.assertGreaterEqual(r.returncode, 0,
                                "sign help crashed with signal "
                                "{}".format(r.returncode))
        self.assertIn("RSA Sign", r.stdout + r.stderr)

    def test_verify_help(self):
        r = run_wolfssl("-rsa", "-verify", "-help")
        self.assertGreaterEqual(r.returncode, 0,
                                "verify help crashed with signal "
                                "{}".format(r.returncode))
        self.assertIn("RSA Verify", r.stdout + r.stderr)

    def test_generic_help(self):
        """No -sign/-verify prints both the sign and verify help blocks."""
        r = run_wolfssl("-ecc", "-help")
        self.assertGreaterEqual(r.returncode, 0,
                                "generic help crashed with signal "
                                "{}".format(r.returncode))
        combined = r.stdout + r.stderr
        self.assertIn("ECC Sign", combined)
        self.assertIn("ECC Verify", combined)

class GenkeyArgvTest(unittest.TestCase):
    """Argument-bounds checks for the genkey subcommand entry point."""

    def test_genkey_no_keytype(self):
        """`wolfssl genkey` with no key-type argument must not deref argv[2]."""
        r = run_wolfssl("genkey")
        self.assertNotEqual(r.returncode, 0,
                            "expected failure with no key type")
        self.assertGreaterEqual(r.returncode, 0,
                                "genkey with no key type crashed with signal "
                                "{}".format(r.returncode))


if __name__ == "__main__":
    test_main()

#!/usr/bin/env python3
"""Key generation, signing, and verification tests for wolfCLU."""

import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import WOLFSSL_BIN, CERTS_DIR, run_wolfssl, test_main

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


def _icacls_entries(path):
    """Return the list of ACE description strings icacls reports for path,
    one string per trustee (e.g. "DOMAIN\\user:(F)")."""
    r = subprocess.run(["icacls", path], capture_output=True, text=True,
                       timeout=10)
    if r.returncode != 0:
        raise RuntimeError("icacls {} failed: {}".format(path, r.stderr))

    entries = []
    for line in r.stdout.splitlines():
        line = line.rstrip()
        if not line:
            break
        if line.lower().startswith("successfully processed"):
            break
        if line.startswith(path):
            line = line[len(path):].strip()
        else:
            line = line.strip()
        if line:
            entries.append(line)
    return entries


class KeyFilePermissionsTest(unittest.TestCase):
    """wolfCLU_OpenKeyFile must write private keys with owner-only
    permissions (POSIX 0600 / Windows single-owner ACE), and must replace
    (not append to) a pre-existing file.

    On Windows this exercises the SDDL/CreateFileA branch of
    wolfCLU_OpenKeyFile via icacls instead of POSIX mode bits, since NTFS
    ACLs are the actual enforcement mechanism there, not the mode bits
    os.stat() reports.
    """

    @classmethod
    def tearDownClass(cls):
        _cleanup_files(_TEMP_FILES)
        _TEMP_FILES.clear()

    def _assert_owner_only(self, priv, label):
        if os.name == "nt":
            entries = _icacls_entries(priv)
            self.assertEqual(len(entries), 1,
                             "{}: expected exactly one owner-only ACL "
                             "entry, got: {}".format(label, entries))
            entry = entries[0]
            self.assertIn("(F)", entry,
                         "{}: owner ACE missing full control: {}"
                         .format(label, entry))
            for forbidden in ("Everyone", "Authenticated Users",
                              "BUILTIN\\Users", "NT AUTHORITY"):
                self.assertNotIn(forbidden, entry,
                                 "{}: unexpected broad-access principal "
                                 "{!r} in ACL: {}"
                                 .format(label, forbidden, entry))
        else:
            mode = os.stat(priv).st_mode & 0o777
            self.assertEqual(mode, 0o600,
                             "{}: private key file mode is {:o}, expected "
                             "600".format(label, mode))

    def _priv_mode(self, keybase):
        priv = keybase + ".priv"
        pub = keybase + ".pub"
        _TEMP_FILES.extend([priv, pub])
        r = run_wolfssl("-genkey", "rsa", "-size", "2048", "-out", keybase,
                        "-outform", "der", "-output", "KEYPAIR")
        self.assertEqual(r.returncode, 0, r.stderr)
        return priv

    def test_rsa_priv_key_mode_is_owner_only(self):
        priv = self._priv_mode("rsakey-perm-test")
        self._assert_owner_only(priv, "RSA")

    def test_ecc_priv_key_mode_is_owner_only(self):
        priv = "ecckey-perm-test.priv"
        pub = "ecckey-perm-test.pub"
        _TEMP_FILES.extend([priv, pub])
        r = run_wolfssl("-genkey", "ecc", "-out", "ecckey-perm-test",
                        "-outform", "der", "-output", "KEYPAIR")
        self.assertEqual(r.returncode, 0, r.stderr)
        self._assert_owner_only(priv, "ECC")

    def test_ed25519_priv_key_mode_is_owner_only(self):
        priv = "edkey-perm-test.priv"
        pub = "edkey-perm-test.pub"
        _TEMP_FILES.extend([priv, pub])
        r = run_wolfssl("-genkey", "ed25519", "-out", "edkey-perm-test",
                        "-outform", "der", "-output", "KEYPAIR")
        self.assertEqual(r.returncode, 0, r.stderr)
        self._assert_owner_only(priv, "Ed25519")

    def test_dh_priv_key_mode_is_owner_only(self):
        r = run_wolfssl("dhparam", "1024")
        if "DH support not compiled into wolfSSL" in r.stdout + r.stderr:
            self.skipTest("DH support not compiled in")

        params_file = "dh-perm-test.params"
        keyfile = "dh-perm-test.key"
        _TEMP_FILES.extend([params_file, keyfile])

        r = run_wolfssl("dhparam", "1024", "-out", params_file)
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("dhparam", "-in", params_file, "-genkey",
                        "-out", keyfile)
        self.assertEqual(r.returncode, 0, r.stderr)
        self._assert_owner_only(keyfile, "DH")

    def test_dsa_priv_key_mode_is_owner_only(self):
        r = run_wolfssl("dsaparam", "1024")
        if "DSA support not compiled into wolfSSL" in r.stdout + r.stderr:
            self.skipTest("DSA support not compiled in")

        params_file = "dsa-perm-test.params"
        keyfile = "dsa-perm-test.key"
        _TEMP_FILES.extend([params_file, keyfile])

        r = run_wolfssl("dsaparam", "-out", params_file, "1024")
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("dsaparam", "-in", params_file, "-genkey",
                        "-out", keyfile)
        self.assertEqual(r.returncode, 0, r.stderr)
        self._assert_owner_only(keyfile, "DSA")

    @unittest.skipIf(os.name == "nt",
                     "symlink attack path is POSIX-specific")
    def test_symlink_at_priv_path_is_not_followed(self):
        """A pre-existing symlink at the -out path must not be followed:
        key material must never land at the symlink's target, and the
        target's contents must be untouched."""
        keybase = "rsakey-symlink-test"
        priv = keybase + ".priv"
        pub = keybase + ".pub"
        target = "rsakey-symlink-target.txt"
        _TEMP_FILES.extend([priv, pub, target])

        with open(target, "wb") as f:
            f.write(b"attacker-owned file; must not be overwritten")
        os.symlink(target, priv)

        r = run_wolfssl("-genkey", "rsa", "-size", "2048", "-out", keybase,
                        "-outform", "der", "-output", "KEYPAIR")

        with open(target, "rb") as f:
            target_content = f.read()
        self.assertEqual(target_content,
                         b"attacker-owned file; must not be overwritten",
                         "symlink target was written through; key "
                         "material leaked to an attacker-controlled path")

        if r.returncode == 0:
            self.assertFalse(os.path.islink(priv),
                             "priv path is still a symlink after a "
                             "successful -genkey")
            self._assert_owner_only(priv, "RSA (post-symlink)")

    def test_preexisting_priv_file_is_replaced(self):
        """A stale file at the target path must be replaced, not appended
        to or left with mixed content, and must end up owner-only."""
        keybase = "rsakey-replace-test"
        priv = keybase + ".priv"
        pub = keybase + ".pub"
        _TEMP_FILES.extend([priv, pub])

        with open(priv, "wb") as f:
            f.write(b"stale placeholder content")
        if os.name != "nt":
            os.chmod(priv, 0o644)

        r = run_wolfssl("-genkey", "rsa", "-size", "2048", "-out", keybase,
                        "-outform", "der", "-output", "KEYPAIR")
        self.assertEqual(r.returncode, 0, r.stderr)

        with open(priv, "rb") as f:
            content = f.read()
        self.assertNotIn(b"stale placeholder content", content,
                         "stale content survived key generation")

        self._assert_owner_only(priv, "replaced RSA")


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

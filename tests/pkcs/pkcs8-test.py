#!/usr/bin/env python3
"""PKCS8 tests for wolfCLU."""

import base64
import filecmp
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import (WOLFSSL_BIN, CERTS_DIR, HAVE_PTY, is_fips,
                          run_wolfssl, run_wolfssl_pty, test_main)

RSA_OID = bytes.fromhex("2a864886f70d010101")   # rsaEncryption
EC_OID = bytes.fromhex("2a8648ce3d0201")        # id-ecPublicKey
P256_OID = bytes.fromhex("2a8648ce3d030107")    # prime256v1


def der_tlv(data, pos=0):
    """Return (tag, value, end) of the DER element at pos."""
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    return tag, data[pos:pos + length], pos + length


def der_enc(tag, value):
    """Return the DER element tag, length, value."""
    n = len(value)
    if n < 0x80:
        return bytes([tag, n]) + value
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(raw)]) + raw + value


def pkcs8_der(key, oid, params):
    """Wrap a traditional private key in a PKCS#8 PrivateKeyInfo."""
    alg = der_enc(0x30, der_enc(0x06, oid) + params)
    return der_enc(0x30, der_enc(0x02, b"\x00") + alg + der_enc(0x04, key))


class Pkcs8Test(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

        config_log = os.path.join(".", "config.log")
        if os.path.isfile(config_log):
            with open(config_log, "r") as f:
                if "disable-filesystem" in f.read():
                    raise unittest.SkipTest("filesystem support disabled")

        r = run_wolfssl("pkcs8", "-in",
                        os.path.join(CERTS_DIR, "server-keyEnc.pem"),
                        "-passin", "pass:yassl123")
        combined = r.stdout + r.stderr
        if "Recompile wolfSSL with PKCS8 support" in combined:
            raise unittest.SkipTest("PKCS8 support not compiled in")

        cls.is_fips = is_fips()

    def _cleanup(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: os.remove(p)
                            if os.path.exists(p) else None)

    def test_decrypt_and_convert(self):
        key_pem = "key.pem"
        pkcs1_pem = "pkcs1.pem"
        key_enc_der = "keyEnc.der"
        self._cleanup(key_pem, pkcs1_pem, key_enc_der)

        if not self.is_fips:
            r = run_wolfssl("pkcs8", "-in",
                            os.path.join(CERTS_DIR, "server-keyEnc.pem"),
                            "-passin", "pass:yassl123",
                            "-outform", "DER", "-out", key_enc_der)
            self.assertEqual(r.returncode, 0, r.stderr)

            r = run_wolfssl("pkcs8", "-in", key_enc_der, "-inform", "DER",
                            "-outform", "PEM", "-out", key_pem)
            self.assertEqual(r.returncode, 0, r.stderr)
        else:
            r = run_wolfssl("pkcs8", "-in",
                            os.path.join(CERTS_DIR, "server-key.pem"),
                            "-outform", "PEM", "-out", key_pem)
            self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("pkcs8", "-in", key_pem, "-topk8", "-nocrypt")
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("pkcs8", "-in", key_pem, "-traditional",
                        "-out", pkcs1_pem)
        self.assertEqual(r.returncode, 0, r.stderr)

        self.assertTrue(
            filecmp.cmp(os.path.join(CERTS_DIR, "server-key.pem"),
                        pkcs1_pem, shallow=False),
            "server-key.pem -traditional check failed")

    def _read(self, path):
        with open(path, "rb") as f:
            return f.read()

    def _assert_pkcs8_der(self, der, oid, params):
        """Check der is a PKCS#8 PrivateKeyInfo and return its privateKey."""
        tag, body, end = der_tlv(der)
        self.assertEqual((tag, end), (0x30, len(der)))
        tag, version, pos = der_tlv(body)
        self.assertEqual((tag, version), (0x02, b"\x00"))
        tag, alg, pos = der_tlv(body, pos)
        self.assertEqual(tag, 0x30, "no AlgorithmIdentifier, not PKCS#8")
        tag, alg_oid, alg_end = der_tlv(alg)
        self.assertEqual((tag, alg_oid), (0x06, oid))
        self.assertEqual(alg[alg_end:], params)
        tag, key, pos = der_tlv(body, pos)
        self.assertEqual(tag, 0x04)
        return key

    def test_topk8_nocrypt_der_is_pkcs8(self):
        """-topk8 -nocrypt -outform DER writes PKCS#8 (F-9841)."""
        rsa_pem = os.path.join(CERTS_DIR, "server-key.pem")
        rsa_der = os.path.join(CERTS_DIR, "server-key.der")
        enc_pem = os.path.join(CERTS_DIR, "server-keyEnc.pem")
        ecc_pem = os.path.join(CERTS_DIR, "ecc-key.pem")
        rsa_alg = (RSA_OID, b"\x05\x00")
        ecc_alg = (EC_OID, b"\x06\x08" + P256_OID)

        p8_pem = "topk8-in-pkcs8.pem"
        self._cleanup(p8_pem)
        r = run_wolfssl("pkcs8", "-in", rsa_pem, "-out", p8_pem)
        self.assertEqual(r.returncode, 0, r.stderr)

        # PKCS#8 DER inputs: server-key.der wrapped here, and the body of the
        # PKCS#8 PEM file ca-ecc-key.pem.
        rsa_p8 = pkcs8_der(self._read(rsa_der), *rsa_alg)
        with open(os.path.join(CERTS_DIR, "ca-ecc-key.pem"), "r") as f:
            ecc_p8 = base64.b64decode("".join(
                l for l in f.read().splitlines() if not l.startswith("-")))
        rsa_p8_der = "topk8-in-rsa-p8.der"
        ecc_p8_der = "topk8-in-ecc-p8.der"
        self._cleanup(rsa_p8_der, ecc_p8_der)
        for path, data in ((rsa_p8_der, rsa_p8), (ecc_p8_der, ecc_p8)):
            with open(path, "wb") as f:
                f.write(data)

        cases = [
            ("topk8-rsa-pem.der", ["-in", rsa_pem], rsa_alg),
            ("topk8-rsa-der.der", ["-in", rsa_der, "-inform", "DER"], rsa_alg),
            ("topk8-rsa-p8.der", ["-in", p8_pem], rsa_alg),
            ("topk8-rsa-p8der.der", ["-in", rsa_p8_der, "-inform", "DER"],
             rsa_alg),
            ("topk8-ecc-pem.der", ["-in", ecc_pem], ecc_alg),
            ("topk8-ecc-p8der.der", ["-in", ecc_p8_der, "-inform", "DER"],
             ecc_alg),
        ]
        if not self.is_fips:
            cases.append(("topk8-rsa-enc.der",
                          ["-in", enc_pem, "-passin", "pass:yassl123"],
                          rsa_alg))
        for out, args, (oid, params) in cases:
            with self.subTest(out=out):
                trad = "trad-" + out
                self._cleanup(out, trad)
                r = run_wolfssl("pkcs8", *(args + [
                    "-topk8", "-nocrypt", "-outform", "DER", "-out", out]))
                self.assertEqual(r.returncode, 0, r.stderr)
                r = run_wolfssl("pkcs8", *(args + [
                    "-traditional", "-outform", "DER", "-out", trad]))
                self.assertEqual(r.returncode, 0, r.stderr)

                key = self._assert_pkcs8_der(self._read(out), oid, params)
                self.assertEqual(key, self._read(trad))
                # Every RSA case is server-key, so the output is the same
                # PKCS#8 DER that openssl writes.
                if oid == RSA_OID:
                    self.assertEqual(self._read(out), rsa_p8)

        # The PKCS#8 DER output reads back as the original key.
        outs = ["topk8-rsa-pem.der"]
        if not self.is_fips:
            outs.append("topk8-rsa-enc.der")
        for out in outs:
            with self.subTest(read_back=out):
                pkcs1_pem = "back-" + out + ".pem"
                self._cleanup(pkcs1_pem)
                r = run_wolfssl("pkcs8", "-in", out, "-inform", "DER",
                                "-traditional", "-out", pkcs1_pem)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(self._read(pkcs1_pem), self._read(rsa_pem))

    def test_der_without_topk8_is_traditional(self):
        """Without -topk8, DER output stays traditional, as in openssl."""
        rsa_pem = os.path.join(CERTS_DIR, "server-key.pem")
        expected = self._read(os.path.join(CERTS_DIR, "server-key.der"))
        cases = [
            ("notopk8-trad.der", ["-traditional"]),
            ("notopk8-plain.der", []),
        ]
        for out, args in cases:
            with self.subTest(out=out):
                self._cleanup(out)
                r = run_wolfssl("pkcs8", "-in", rsa_pem, *(args + [
                    "-outform", "DER", "-out", out]))
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(self._read(out), expected)

    @unittest.skipIf(os.name == "nt", "POSIX file permissions only")
    def test_out_file_owner_only(self):
        """-out holds a private key, so it must be created 0600 (F-9854)."""
        old_umask = os.umask(0o022)
        self.addCleanup(os.umask, old_umask)

        key = os.path.join(CERTS_DIR, "server-key.pem")
        cases = [
            ("perm-pkcs8.pem", ["-in", key, "-outform", "PEM"]),
            ("perm-pkcs8.der", ["-in", key, "-outform", "DER"]),
            ("perm-pkcs1.pem", ["-in", key, "-traditional"]),
        ]
        if not self.is_fips:
            cases.append(("perm-pkcs8-dec.pem",
                          ["-in", os.path.join(CERTS_DIR, "server-keyEnc.pem"),
                           "-passin", "pass:yassl123"]))

        for out, args in cases:
            with self.subTest(out=out):
                self._cleanup(out)
                # Start from a new file so the create mode applies.
                if os.path.exists(out):
                    os.remove(out)
                r = run_wolfssl("pkcs8", *(args + ["-out", out]))
                self.assertEqual(r.returncode, 0, r.stderr)
                mode = os.stat(out).st_mode & 0o777
                self.assertEqual(mode, 0o600,
                                 "{} mode is {:o}, expected 600".format(
                                     out, mode))

    def test_help(self):
        for flag in ("-help", "-h"):
            r = run_wolfssl("pkcs8", flag)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("wolfssl pkcs8", r.stdout + r.stderr)

    def test_bad_argument_fails(self):
        r = run_wolfssl("pkcs8", "-not-a-real-option")
        self.assertNotEqual(r.returncode, 0)

    @unittest.skipIf(is_fips(), "skipped in FIPS builds")
    def test_stdin_input(self):
        pem_path = os.path.join(CERTS_DIR, "server-keyEnc.pem")
        with open(pem_path, "rb") as f:
            data = f.read()

        r = subprocess.run(
            [WOLFSSL_BIN, "pkcs8", "-passin", "pass:yassl123"],
            input=data, capture_output=True, text=False,
            timeout=60,
        )
        self.assertIn(b"BEGIN PRIVATE", r.stdout + r.stderr)

    @unittest.skipIf(is_fips(), "skipped in FIPS builds")
    def test_fail_wrong_input(self):
        r = run_wolfssl("pkcs8", "-in",
                        os.path.join(CERTS_DIR, "server-cert.pem"),
                        "-passin", "pass:yassl123")
        self.assertNotEqual(r.returncode, 0)

    @unittest.skipIf(is_fips(), "skipped in FIPS builds")
    def test_fail_wrong_password(self):
        r = run_wolfssl("pkcs8", "-in",
                        os.path.join(CERTS_DIR, "server-keyEnc.pem"),
                        "-passin", "pass:wrongPass")
        self.assertNotEqual(r.returncode, 0)

    @unittest.skipIf(is_fips(), "skipped in FIPS builds")
    def test_fail_wrong_format(self):
        r = run_wolfssl("pkcs8", "-in",
                        os.path.join(CERTS_DIR, "server-keyEnc.pem"),
                        "-inform", "DER", "-passin", "pass:yassl123")
        self.assertNotEqual(r.returncode, 0)

    @unittest.skipUnless(HAVE_PTY, "pty not available")
    def test_password_prompt_eof_fails(self):
        """EOF at the password prompt for an encrypted key must fail cleanly.

        The password buffer was measured with strlen after the failed read,
        although nothing had been written to it."""
        code, out = run_wolfssl_pty(
            "pkcs8", "-in", os.path.join(CERTS_DIR, "server-keyEnc.pem"),
            reply=b"\x04")
        self.assertIn(b"Input Password", out)
        self.assertIn(b"Unable to get password from stdin", out)
        self.assertGreater(code, 0, out)
        self.assertNotIn(b"PRIVATE KEY", out)
        self.assertNotIn(b"AddressSanitizer", out)


if __name__ == "__main__":
    test_main()

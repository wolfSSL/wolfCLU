#!/usr/bin/env python3
"""Encrypt/decrypt round-trip tests for various cipher algorithms."""

import filecmp
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import run_wolfssl, test_main

# Small test input — created once, used by all tests
INPUT_FILE = "encdec_input.txt"
INPUT_DATA = "The quick brown fox jumps over the lazy dog.\n" * 100


def _available_algos():
    """Parse available algorithms from -encrypt -help output."""
    r = run_wolfssl("-encrypt", "-help")
    combined = r.stdout + r.stderr
    algos = set()
    for line in combined.splitlines():
        for token in line.split():
            if "-" in token and any(c.isdigit() for c in token):
                algos.add(token)
    return algos


_ALGOS = _available_algos()


class EncDecRoundtripTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open(INPUT_FILE, "w") as f:
            f.write(INPUT_DATA)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(INPUT_FILE):
            os.remove(INPUT_FILE)

    def _cleanup(self, *files):
        for f in files:
            self.addCleanup(lambda p=f: os.remove(p)
                            if os.path.exists(p) else None)

    def _roundtrip(self, algo, password):
        enc_file = f"enc_{algo.replace('-', '_')}.bin"
        dec_file = f"dec_{algo.replace('-', '_')}.bin"
        self._cleanup(enc_file, dec_file)

        r = run_wolfssl("-encrypt", algo, "-pwd", password,
                        "-in", INPUT_FILE, "-out", enc_file)
        self.assertEqual(r.returncode, 0,
                         f"encrypt {algo} failed: {r.stderr}")
        self.assertFalse(filecmp.cmp(INPUT_FILE, enc_file, shallow=False),
                         f"{algo} encrypted file is identical to input")

        r = run_wolfssl("-decrypt", algo, "-in", enc_file,
                        "-out", dec_file, "-pwd", password)
        self.assertEqual(r.returncode, 0,
                         f"decrypt {algo} failed: {r.stderr}")
        self.assertTrue(filecmp.cmp(INPUT_FILE, dec_file, shallow=False),
                        f"{algo} decrypted file does not match original")


@unittest.skipUnless("aes-cbc-128" in _ALGOS, "AES-CBC not available")
class AesCbcTest(EncDecRoundtripTest):

    def test_aes_cbc_128(self):
        self._roundtrip("aes-cbc-128", "hello128")

    def test_aes_cbc_192(self):
        self._roundtrip("aes-cbc-192", "hello192")

    def test_aes_cbc_256(self):
        self._roundtrip("aes-cbc-256", "hello256")


@unittest.skipUnless("aes-ctr-128" in _ALGOS, "AES-CTR not available")
class AesCtrTest(EncDecRoundtripTest):

    def test_aes_ctr_128(self):
        self._roundtrip("aes-ctr-128", "hello128")

    def test_aes_ctr_192(self):
        self._roundtrip("aes-ctr-192", "hello192")

    def test_aes_ctr_256(self):
        self._roundtrip("aes-ctr-256", "hello256")


@unittest.skipUnless("3des-cbc-56" in _ALGOS, "3DES-CBC not available")
class Des3CbcTest(EncDecRoundtripTest):

    def test_3des_cbc_56(self):
        self._roundtrip("3des-cbc-56", "hello056")

    def test_3des_cbc_112(self):
        self._roundtrip("3des-cbc-112", "hello112")

    def test_3des_cbc_168(self):
        self._roundtrip("3des-cbc-168", "hello168")


@unittest.skipUnless("camellia-cbc-128" in _ALGOS,
                     "Camellia-CBC not available")
class CamelliaCbcTest(EncDecRoundtripTest):

    def test_camellia_cbc_128(self):
        self._roundtrip("camellia-cbc-128", "hello128")

    def test_camellia_cbc_192(self):
        self._roundtrip("camellia-cbc-192", "hello192")

    def test_camellia_cbc_256(self):
        self._roundtrip("camellia-cbc-256", "hello256")


if __name__ == "__main__":
    test_main()

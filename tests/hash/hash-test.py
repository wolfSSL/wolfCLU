#!/usr/bin/env python3
"""Hash tests for wolfCLU."""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import (CERTS_DIR, run_wolfssl, test_main, truncate_sparse)

HASH_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(CERTS_DIR, "ca-cert.pem")


def _read_expected(name):
    path = os.path.join(HASH_DIR, name)
    with open(path, "r") as f:
        return f.read().strip()


class HashCommandTest(unittest.TestCase):
    """Tests using the -hash subcommand."""

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

        config_log = os.path.join(".", "config.log")
        if os.path.isfile(config_log):
            with open(config_log, "r") as f:
                if "disable-filesystem" in f.read():
                    raise unittest.SkipTest("filesystem support disabled")

    def test_sha(self):
        r = run_wolfssl("-hash", "-sha", "-in", CERT_FILE)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), _read_expected("sha-expect.hex"))

    def test_sha256(self):
        r = run_wolfssl("-hash", "-sha256", "-in", CERT_FILE)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), _read_expected("sha256-expect.hex"))

    def test_sha384(self):
        r = run_wolfssl("-hash", "-sha384", "-in", CERT_FILE)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), _read_expected("sha384-expect.hex"))

    def test_sha512(self):
        r = run_wolfssl("-hash", "-sha512", "-in", CERT_FILE)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), _read_expected("sha512-expect.hex"))

    def test_base64enc(self):
        r = run_wolfssl("-hash", "-base64enc", "-in", CERT_FILE)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), _read_expected("base64enc-expect.b64"))

    def test_base64dec(self):
        r = run_wolfssl("-hash", "-base64dec", "-in", os.path.join(HASH_DIR,
                                                        "base64enc-expect.b64"))
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(CERT_FILE) as f:
            self.assertEqual(r.stdout.strip(), f.read().strip())

    def test_blake2b(self):
        r = run_wolfssl("-hash", "-blake2b", "64", "-in", CERT_FILE)
        if r.returncode != 0 and "BLAKE2 not avalible" in (r.stdout + r.stderr):
            self.skipTest("BLAKE2 not compiled into wolfSSL")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), _read_expected("blake2b-expect.hex"))


class HashShortcutTest(unittest.TestCase):
    """Tests using the shortcut subcommands (md5, sha256, etc.)."""

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

        config_log = os.path.join(".", "config.log")
        if os.path.isfile(config_log):
            with open(config_log, "r") as f:
                if "disable-filesystem" in f.read():
                    raise unittest.SkipTest("filesystem support disabled")

    def test_md5(self):
        r = run_wolfssl("md5", CERT_FILE)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), _read_expected("md5-expect.hex"))

    def test_sha256(self):
        r = run_wolfssl("sha256", CERT_FILE)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), _read_expected("sha256-expect.hex"))

    def test_sha384(self):
        r = run_wolfssl("sha384", CERT_FILE)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), _read_expected("sha384-expect.hex"))

    def test_sha512(self):
        r = run_wolfssl("sha512", CERT_FILE)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), _read_expected("sha512-expect.hex"))


class LargeFileHashTest(unittest.TestCase):
    """Two >4 GiB files differing only in the last byte must hash differently.

    Guards against truncating the file size to word32 in clu_hash.c, which
    caused files past the 4 GiB boundary to collide.

    Defaults to sha256. Set WOLFCLU_LARGE_HASH_ALG=<alg> to test a single
    different algorithm, or WOLFCLU_LARGE_HASH_ALG=all to test every
    supported algorithm.
    """

    LARGE_FILE_SIZE = 4_831_838_208  # 4.5 GiB, well above UINT32_MAX
    CANDIDATE_ALGS = ["md5", "sha", "sha256", "sha384", "sha512"]
    DEFAULT_ALG = "sha256"

    @classmethod
    def _probe_supported(cls, algs):
        supported = []
        for alg in algs:
            r = run_wolfssl(alg, CERT_FILE)
            if r.returncode == 0:
                supported.append(alg)
        return supported

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

        requested = os.environ.get("WOLFCLU_LARGE_HASH_ALG", cls.DEFAULT_ALG)
        if requested == "all":
            cls.algs = cls._probe_supported(cls.CANDIDATE_ALGS)
        else:
            cls.algs = cls._probe_supported([requested])
        if not cls.algs:
            raise unittest.SkipTest(
                "no supported hash algorithm for "
                "WOLFCLU_LARGE_HASH_ALG={}".format(requested))

        cls._tmpdir = tempfile.mkdtemp(prefix="wolfclu-large-hash-")
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

    def test_tampered_last_byte_changes_hash(self):
        for alg in self.algs:
            with self.subTest(alg=alg):
                r1 = run_wolfssl(alg, self.original, timeout=1800)
                r2 = run_wolfssl(alg, self.tampered, timeout=1800)
                self.assertEqual(r1.returncode, 0, r1.stderr)
                self.assertEqual(r2.returncode, 0, r2.stderr)
                self.assertNotEqual(r1.stdout.strip(), r2.stdout.strip())


class HashArgErrorTest(unittest.TestCase):
    """Argument-handling regression tests."""

    def test_missing_in_value(self):
        """-in with no value must fail gracefully (no segfault)."""
        r = run_wolfssl("-hash", "sha256", "-in")
        self.assertNotEqual(r.returncode, 0,
                            "expected failure for missing -in value")
        self.assertGreaterEqual(r.returncode, 0,
                                "-in without value crashed with signal "
                                "{}".format(r.returncode))


if __name__ == "__main__":
    test_main()

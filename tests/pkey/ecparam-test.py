#!/usr/bin/env python3
"""EC parameter tests for wolfCLU."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import CERTS_DIR, run_wolfssl


def _get_curve_names():
    """Parse available curve names from ecparam -help output."""
    r = run_wolfssl("ecparam", "-help")
    combined = r.stdout + r.stderr
    in_names = False
    names = []
    for line in combined.splitlines():
        if "name options" in line:
            in_names = True
            continue
        if in_names:
            name = line.strip()
            if name and "SAKKE" not in name:
                names.append(name)
    return names


class EcparamTest(unittest.TestCase):

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

    def test_genkey_and_text(self):
        self._cleanup("ecparam.key")

        r = run_wolfssl("ecparam", "-genkey", "-name", "secp384r1",
                        "-out", "ecparam.key")
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("ecparam", "-text", "-in", "ecparam.key")
        self.assertEqual(r.returncode, 0, r.stderr)
        expected = ("Curve Name : SECP384R1\n"
                    "-----BEGIN EC PARAMETERS-----\n"
                    "BgUrgQQAIg==\n"
                    "-----END EC PARAMETERS-----")
        self.assertEqual(r.stdout.strip(), expected)

    def test_text_existing_key(self):
        r = run_wolfssl("ecparam", "-text", "-in",
                        os.path.join(CERTS_DIR, "ecc-key.pem"))
        self.assertEqual(r.returncode, 0, r.stderr)
        expected = ("Curve Name : SECP256R1\n"
                    "-----BEGIN EC PARAMETERS-----\n"
                    "BggqhkjOPQMBBw==\n"
                    "-----END EC PARAMETERS-----")
        self.assertEqual(r.stdout.strip(), expected)

    def test_pem_to_der(self):
        self._cleanup("ecc-key.der")

        r = run_wolfssl("ecparam", "-in",
                        os.path.join(CERTS_DIR, "ecc-key.pem"),
                        "-out", "ecc-key.der", "-outform", "der")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_fail_der_params_only(self):
        """Reading DER with parameters only (no key) is not yet supported."""
        self._cleanup("ecc-key.der", "ecc-key.pem")

        r = run_wolfssl("ecparam", "-in",
                        os.path.join(CERTS_DIR, "ecc-key.pem"),
                        "-out", "ecc-key.der", "-outform", "der")
        self.assertEqual(r.returncode, 0, r.stderr)

        r = run_wolfssl("ecparam", "-in", "ecc-key.der", "-inform", "der",
                        "-out", "ecc-key.pem", "-outform", "pem")
        self.assertNotEqual(r.returncode, 0)

    def test_genkey_der(self):
        self._cleanup("ecc-key.der")

        r = run_wolfssl("ecparam", "-genkey", "-out", "ecc-key.der",
                        "-outform", "der")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_fail_non_ecc_key(self):
        r = run_wolfssl("ecparam", "-in",
                        os.path.join(CERTS_DIR, "ca-key.pem"), "-text")
        self.assertNotEqual(r.returncode, 0)

    def test_all_curves_ecparam(self):
        """Generate key for each supported curve and verify text output."""
        names = _get_curve_names()
        self.assertTrue(len(names) > 0, "no curve names found")

        for name in names:
            with self.subTest(curve=name):
                self._cleanup("tmp_ecparam.key", "tmp_ecparam_text")

                r = run_wolfssl("ecparam", "-genkey", "-name", name,
                                "-out", "tmp_ecparam.key")
                self.assertEqual(r.returncode, 0,
                                 f"genkey {name}: {r.stderr}")

                r = run_wolfssl("ecparam", "-text", "-in", "tmp_ecparam.key",
                                "-out", "tmp_ecparam_text")
                self.assertEqual(r.returncode, 0,
                                 f"text {name}: {r.stderr}")

                with open("tmp_ecparam_text", "r") as f:
                    text = f.read()
                self.assertIn(name, text,
                              f"curve name {name} not in text output")

    def test_fail_bad_curve_name(self):
        self._cleanup("tmp_ecparam.key")

        r = run_wolfssl("ecparam", "-genkey", "-name", "bad_curve_name",
                        "-out", "tmp_ecparam.key")
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(os.path.exists("tmp_ecparam.key"),
                         "key file should not be created for bad curve")

    def test_all_curves_genkey(self):
        """Re-run curve test using the genkey command."""
        names = _get_curve_names()
        self.assertTrue(len(names) > 0, "no curve names found")

        for name in names:
            with self.subTest(curve=name):
                self._cleanup("tmp_ecparam.priv", "tmp_ecparam.pub",
                              "tmp_ecparam_text")

                r = run_wolfssl("genkey", "ecc", "-name", name,
                                "-outform", "PEM", "-out", "tmp_ecparam")
                self.assertEqual(r.returncode, 0,
                                 f"genkey ecc {name}: {r.stderr}")

                r = run_wolfssl("ecparam", "-text", "-in", "tmp_ecparam.priv",
                                "-out", "tmp_ecparam_text")
                self.assertEqual(r.returncode, 0,
                                 f"text {name}: {r.stderr}")

                with open("tmp_ecparam_text", "r") as f:
                    text = f.read()
                self.assertIn(name, text,
                              f"curve name {name} not in text output")


if __name__ == "__main__":
    unittest.main()

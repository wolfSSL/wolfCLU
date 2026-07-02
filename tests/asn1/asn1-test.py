#!/usr/bin/env python3
"""asn1parse tests for wolfCLU."""

import base64
import functools
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wolfclu_test import CERTS_DIR, config_defines, run_wolfssl, test_main

# Two top-level DER INTEGERs (42, then 43): 02 01 2a 02 01 2b.
# Used to confirm -length truncates parsing and -offset skips ahead: the
# items are independent and minimally sized, so the count of "INTEGER" lines
# in the output is a direct measure of how much of the buffer was parsed.
TWO_INTEGERS = bytes([0x02, 0x01, 0x2a, 0x02, 0x01, 0x2b])

# Error fragment emitted when -oid is used in a build that compiled out OID
# encoding (see clu_asn1_setup.c).
_NO_OID_ENCODE_MSG = "not configured to handle encoding oids"


@functools.lru_cache(maxsize=None)
def oid_encoding_supported():
    """True when the build can DER-encode the OIDs from an -oid file.

    -oid relies on wc_EncodeObjectId, which is compiled out via
    NO_WC_ENCODE_OBJECT_ID for libwolfssl <= 5.9.1 (set in configure.ac).
    In that build -oid reports a fatal error instead of encoding anything.
    The flag is a -D in AM_CFLAGS rather than a config.h define, so it cannot
    be read via config_defines(); probe the binary directly instead.  A
    nonexistent file is enough: the disabled path errors during argument
    handling before the file is ever opened.
    """
    result = run_wolfssl("asn1parse", "-oid", "asn1-oid-probe.nonexistent")
    return _NO_OID_ENCODE_MSG not in (result.stdout + result.stderr)


class TestBasicFunctions(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not os.path.isdir(CERTS_DIR):
            raise unittest.SkipTest("certs directory not found")

        cls.der = os.path.join(CERTS_DIR, "ca-cert.der")
        cls.pem = os.path.join(CERTS_DIR, "ca-cert.pem")

        # Skip when asn1parse is not compiled in (needs WOLFSSL_ASN_PRINT).
        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", cls.der)
        if "Cannot Parse Asn1" in (result.stdout + result.stderr):
            raise unittest.SkipTest("asn1parse support not compiled in")

        # Reference output produced from the DER form of the cert.
        cls.der_output = result.stdout

    def test_DER(self):
        """Parse a DER input and confirm the ASN.1 structure is printed."""
        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", self.der)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SEQUENCE", result.stdout)

    def test_PEM(self):
        """PEM input of the same cert yields the same parse as DER."""
        result = run_wolfssl("asn1parse", "-inform", "PEM", "-in", self.pem)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, self.der_output)

    def test_base64(self):
        """Base64 (non-PEM) input yields the same parse as DER."""
        b64_file = "test-asn1.b64"
        self.addCleanup(lambda: os.remove(b64_file)
                        if os.path.exists(b64_file) else None)
        with open(self.der, "rb") as f:
            with open(b64_file, "w") as out:
                out.write(base64.encodebytes(f.read()).decode())

        result = run_wolfssl("asn1parse", "-inform", "B64", "-in", b64_file)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, self.der_output)

    def test_out_arg_is_DER(self):
        """The -out file is the processed DER that was input"""
        out_file = "test-asn1.out"
        open(out_file, "w").close()
        self.addCleanup(lambda: os.remove(out_file)
                        if os.path.exists(out_file) else None)
        result = run_wolfssl("asn1parse", "-inform", "DER", "-noout", "-in", self.der,
                             "-out", out_file)
        self.assertEqual(result.returncode, 0, result.stderr)
        with open(out_file, "rb") as out:
            with open(self.der, "rb") as infile:
                self.assertEqual(str(out.read()), str(infile.read()))

    def test_out_arg(self):
        """The -out flag (output file must exist) runs without error."""
        out_file = "test-asn1.out"
        open(out_file, "w").close()
        self.addCleanup(lambda: os.remove(out_file)
                        if os.path.exists(out_file) else None)

        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", self.der,
                             "-out", out_file)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_noout_suppresses_stdout(self):
        """-noout suppresses stdout but the -out file still gets the DER."""
        out_file = "test-asn1-noout.out"
        self.addCleanup(lambda: os.remove(out_file)
                        if os.path.exists(out_file) else None)

        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", self.der,
                             "-out", out_file, "-noout")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

        with open(out_file, "rb") as out:
            with open(self.der, "rb") as infile:
                self.assertEqual(out.read(), infile.read())

    def test_noout_without_out_errors(self):
        """-noout with no -out leaves no targets and is rejected."""
        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", self.der,
                             "-noout")
        self.assertNotEqual(result.returncode, 0)

    def test_offset(self):
        """An offset changes where parsing begins."""
        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", self.der,
                             "-offset", "4")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SEQUENCE", result.stdout)
        self.assertNotEqual(result.stdout, self.der_output)

    def test_strparse_octet_string(self):
        """-strparse onto an OCTET/BIT STRING node succeeds.

        Build OCTET STRING { INTEGER 42 }:
            04 03 02 01 2a
        -strparse 0 descends into the OCTET STRING at offset 0 and prints the
        wrapped INTEGER, with no dependence on the bytes of any shipped cert.
        """
        der_file = "test-asn1-strparse-octet.der"
        with open(der_file, "wb") as f:
            f.write(bytes([0x04, 0x03, 0x02, 0x01, 0x2a]))
        self.addCleanup(lambda: os.remove(der_file)
                        if os.path.exists(der_file) else None)

        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", der_file,
                             "-strparse", "0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("INTEGER", result.stdout)

    def test_strparse_nested_octet_strings(self):
        """A comma-separated -strparse list drills through nested OCTET STRINGs.

        Build OCTET STRING { OCTET STRING { INTEGER 42 } }:
            04 05 04 03 02 01 2a
        Each list entry is an offset (relative to the current substructure) of
        an OCTET/BIT STRING to descend into, so "0,0" peels both wrappers and
        leaves the INTEGER to be printed.
        """
        der_file = "test-asn1-nested.der"
        with open(der_file, "wb") as f:
            f.write(bytes([0x04, 0x05, 0x04, 0x03, 0x02, 0x01, 0x2a]))
        self.addCleanup(lambda: os.remove(der_file)
                        if os.path.exists(der_file) else None)
        # Two levels: descend through both wrappers to the INTEGER.
        r = run_wolfssl("asn1parse", "-inform", "DER", "-in", der_file,
                          "-strparse", "0,0")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("INTEGER", r.stdout)
        self.assertNotIn("OCTET STRING", r.stdout)

    def test_strparse_bit_string(self):
        """-strparse into a BIT STRING skips its leading unused-bits octet.

        Build BIT STRING { INTEGER 42 }:
            03 04 00 02 01 2a
        The 0x00 unused-bits octet is not part of the nested DER, so -strparse
        must step over it to reach and print the wrapped INTEGER.
        """
        der_file = "test-asn1-strparse-bit.der"
        with open(der_file, "wb") as f:
            f.write(bytes([0x03, 0x04, 0x00, 0x02, 0x01, 0x2a]))
        self.addCleanup(lambda: os.remove(der_file)
                        if os.path.exists(der_file) else None)

        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", der_file,
                             "-strparse", "0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("INTEGER", result.stdout)

    @unittest.skipUnless(oid_encoding_supported(),
                         "built without wc_EncodeObjectId (-oid disabled)")
    def test_oid(self):
        """A custom OID definition file maps an unknown OID to its name.

        The callback is only consulted for OIDs wolfSSL does not already
        know, so use an arbitrary unknown OID (1.3.111111.5) encoded as a bare
        OBJECT IDENTIFIER and confirm the supplied long name is printed.
        """
        # DER: 06 05 2b 86 e4 07 05  == OBJECT IDENTIFIER 1.3.111111.5
        # 111111 base-128 = 6, 100, 7 -> 0x86 0xe4 0x07.
        der_file = "test-asn1-unknown-oid.der"
        with open(der_file, "wb") as f:
            f.write(bytes([0x06, 0x05, 0x2b, 0x86, 0xe4, 0x07, 0x05]))
        self.addCleanup(lambda: os.remove(der_file)
                        if os.path.exists(der_file) else None)

        oid_file = "test-asn1-oid.conf"
        with open(oid_file, "w") as f:
            f.write("1.3.111111.5 myShort MyUnknownOid")
        self.addCleanup(lambda: os.remove(oid_file)
                        if os.path.exists(oid_file) else None)

        # Without the mapping the OID prints in dotted-decimal form.
        baseline = run_wolfssl("asn1parse", "-inform", "DER", "-in", der_file)
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        self.assertIn("1.3.111111.5", baseline.stdout)
        self.assertNotIn("MyUnknownOid", baseline.stdout)

        # With the mapping the custom long name is resolved.
        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", der_file,
                             "-oid", oid_file)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("MyUnknownOid", result.stdout)

    @unittest.skipUnless(oid_encoding_supported(),
                         "built without wc_EncodeObjectId (-oid disabled)")
    def test_oid_multibyte_first_subidentifier(self):
        """A custom OID whose first subidentifier needs base-128 encoding maps.

        For OID 2.100.3 the first subidentifier is 40*2 + 100 = 180, which
        exceeds 127 and must be encoded over two base-128 bytes (0x81 0x34).
        Regression test: a single-byte encoding truncates and the -oid
        mapping silently fails to match.
        """
        # DER: 06 03 81 34 03  == OBJECT IDENTIFIER 2.100.3
        der_file = "test-asn1-arc2-oid.der"
        with open(der_file, "wb") as f:
            f.write(bytes([0x06, 0x03, 0x81, 0x34, 0x03]))
        self.addCleanup(lambda: os.remove(der_file)
                        if os.path.exists(der_file) else None)

        oid_file = "test-asn1-arc2-oid.conf"
        with open(oid_file, "w") as f:
            f.write("2.100.3 myShort MyArc2Oid\n")
        self.addCleanup(lambda: os.remove(oid_file)
                        if os.path.exists(oid_file) else None)

        # Without the mapping the OID prints in dotted-decimal form.
        baseline = run_wolfssl("asn1parse", "-inform", "DER", "-in", der_file)
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        self.assertIn("2.100.3", baseline.stdout)
        self.assertNotIn("MyArc2Oid", baseline.stdout)

        # With the mapping the custom long name is resolved, which only
        # happens if the conf OID was DER-encoded to the same bytes.
        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", der_file,
                             "-oid", oid_file)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("MyArc2Oid", result.stdout)

    @unittest.skipUnless("HAVE_OID_TABLE" in config_defines(),
                         "built with --enable-oid-table")
    def test_builtin_oid_table(self):
        """The built-in OID table resolves an OID with no -oid file supplied.

        Exercises the second loop in OidToNameCallback (the static
        oid_name_table), which is only compiled with --enable-oid-table.
        2.16.840.1.114171.500.9 ("Wells Fargo EV policy") is in the table but
        not otherwise known to wolfSSL, so the callback is consulted and the
        table name must be printed without any -oid mapping.
        """
        # DER: 06 0a 60 86 48 01 86 fb 7b 83 74 09
        #   == OBJECT IDENTIFIER 2.16.840.1.114171.500.9
        der_file = "test-asn1-builtin-oid.der"
        with open(der_file, "wb") as f:
            f.write(bytes([0x06, 0x0a, 0x60, 0x86, 0x48, 0x01, 0x86, 0xfb,
                           0x7b, 0x83, 0x74, 0x09]))
        self.addCleanup(lambda: os.remove(der_file)
                        if os.path.exists(der_file) else None)

        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", der_file)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Wells Fargo EV policy", result.stdout)

    def test_length_truncates(self):
        """A valid -length stops parsing at the byte limit.

        TWO_INTEGERS holds two independent top-level INTEGERs.  Parsed whole,
        both appear; with -length 3 (exactly the first INTEGER's TLV) only the
        first is parsed, confirming the limit is honoured rather than ignored.
        """
        der_file = "test-asn1-twoint.der"
        with open(der_file, "wb") as f:
            f.write(TWO_INTEGERS)
        self.addCleanup(lambda: os.remove(der_file)
                        if os.path.exists(der_file) else None)

        full = run_wolfssl("asn1parse", "-inform", "DER", "-in", der_file)
        self.assertEqual(full.returncode, 0, full.stderr)
        self.assertEqual(full.stdout.count("INTEGER"), 2)

        truncated = run_wolfssl("asn1parse", "-inform", "DER", "-in", der_file,
                                "-length", "3")
        self.assertEqual(truncated.returncode, 0, truncated.stderr)
        self.assertEqual(truncated.stdout.count("INTEGER"), 1)

    def test_offset_skips_leading_bytes(self):
        """A valid -offset begins parsing past the skipped bytes.

        With -offset 3 the first INTEGER's TLV in TWO_INTEGERS is skipped, so
        only the second INTEGER remains to be parsed.
        """
        der_file = "test-asn1-twoint-off.der"
        with open(der_file, "wb") as f:
            f.write(TWO_INTEGERS)
        self.addCleanup(lambda: os.remove(der_file)
                        if os.path.exists(der_file) else None)

        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", der_file,
                             "-offset", "3")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("INTEGER"), 1)

    def test_offset_past_end(self):
        """An -offset past the end of the input is rejected, not read OOB."""
        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", self.der,
                             "-offset", "9999999")
        self.assertNotEqual(result.returncode, 0)

    def test_length_too_large(self):
        """A -length larger than the remaining input is rejected."""
        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", self.der,
                             "-length", "9999999")
        self.assertNotEqual(result.returncode, 0)

    def test_negative_integer_arg(self):
        """A non-integer / negative argument to -offset is rejected."""
        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", self.der,
                             "-offset", "-5")
        self.assertNotEqual(result.returncode, 0)

    def test_strparse_non_octet_string(self):
        """-strparse onto a non-OCTET/BIT STRING node errors out."""
        # The top-level node of the cert is a SEQUENCE, not an OCTET STRING.
        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", self.der,
                             "-strparse", "0")
        self.assertNotEqual(result.returncode, 0)

    def test_malformed_oid_file(self):
        """A malformed -oid definition file is rejected."""
        oid_file = "test-asn1-bad-oid.conf"
        with open(oid_file, "w") as f:
            # Missing the short and long name tokens.
            f.write("1.2.3.4\n")
        self.addCleanup(lambda: os.remove(oid_file)
                        if os.path.exists(oid_file) else None)

        result = run_wolfssl("asn1parse", "-inform", "DER", "-in", self.der,
                             "-oid", oid_file)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    test_main()

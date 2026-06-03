# includes append to these:
SUFFIXES =
TESTS =
CLEANFILES =
DISTCLEANFILES =
#bin_PROGRAMS =
noinst_HEADERS =
lib_LTLIBRARIES =
man_MANS =
noinst_LTLIBRARIES =
noinst_PROGRAMS =
include_HEADERS =
nobase_include_HEADERS =
check_PROGRAMS =
EXTRA_HEADERS =
BUILT_SOURCES=
EXTRA_DIST=
dist_doc_DATA=
check_SCRIPTS=
dist_noinst_SCRIPTS=

TEST_EXTENSIONS = .sh .py
PY_LOG_COMPILER = $(PYTHON)
AM_TESTS_ENVIRONMENT = \
    WOLFCLU_BUILDDIR='$(abs_top_builddir)'; export WOLFCLU_BUILDDIR; \
    WOLFCLU_SRCDIR='$(abs_top_srcdir)'; export WOLFCLU_SRCDIR;

#includes additional rules from aminclude.am
@INC_AMINCLUDE@
DISTCLEANFILES+= aminclude.am

#exampledir = $(docdir)/example
#dist_example_DATA=

ACLOCAL_AMFLAGS= -I m4

EXTRA_DIST+= tests
EXTRA_DIST+= certs
EXTRA_DIST+= manpages
EXTRA_DIST+= README.md
EXTRA_DIST+= LICENSE
EXTRA_DIST+= ChangeLog.md
EXTRA_DIST+= wolfclu.sln
EXTRA_DIST+= wolfCLU.vcxproj
EXTRA_DIST+= wolfCLU.vcxproj.filters

if ENABLE_MANPAGES
man_MANS+= manpages/wolfssl.1
man_MANS+= manpages/wolfssl-bench.1
man_MANS+= manpages/wolfssl-decrypt.1
man_MANS+= manpages/wolfssl-encrypt.1
man_MANS+= manpages/wolfssl-hash.1
man_MANS+= manpages/wolfssl-enc.1
man_MANS+= manpages/wolfssl-ca.1
man_MANS+= manpages/wolfssl-x509.1
man_MANS+= manpages/wolfssl-asn1parse.1
man_MANS+= manpages/wolfssl-req.1
man_MANS+= manpages/wolfssl-verify.1
man_MANS+= manpages/wolfssl-crl.1
man_MANS+= manpages/wolfssl-genkey.1
man_MANS+= manpages/wolfssl-pkey.1
man_MANS+= manpages/wolfssl-rsa.1
man_MANS+= manpages/wolfssl-ecparam.1
man_MANS+= manpages/wolfssl-dsaparam.1
man_MANS+= manpages/wolfssl-dhparam.1
man_MANS+= manpages/wolfssl-pkcs7.1
man_MANS+= manpages/wolfssl-pkcs8.1
man_MANS+= manpages/wolfssl-pkcs12.1
man_MANS+= manpages/wolfssl-dgst.1
man_MANS+= manpages/wolfssl-sign_verify.1
# The keytype and hash-shortcut pages below are .so aliases for
# wolfssl-sign_verify.1 and wolfssl-hash.1 respectively. .so pages only
# render once installed under man1/.
man_MANS+= manpages/wolfssl-ecc.1
man_MANS+= manpages/wolfssl-ed25519.1
man_MANS+= manpages/wolfssl-dilithium.1
man_MANS+= manpages/wolfssl-xmss.1
man_MANS+= manpages/wolfssl-xmssmt.1
man_MANS+= manpages/wolfssl-rand.1
man_MANS+= manpages/wolfssl-base64.1
man_MANS+= manpages/wolfssl-s_client.1
man_MANS+= manpages/wolfssl-s_server.1
man_MANS+= manpages/wolfssl-ocsp.1
man_MANS+= manpages/wolfssl-md5.1
man_MANS+= manpages/wolfssl-sha256.1
man_MANS+= manpages/wolfssl-sha384.1
man_MANS+= manpages/wolfssl-sha512.1
man_MANS+= manpages/wolfssl-version.1
endif

include src/include.am
include wolfclu/include.am
if HAVE_PYTHON
include tests/dh/include.am
include tests/dsa/include.am
include tests/pkey/include.am
include tests/dgst/include.am
include tests/rand/include.am
include tests/asn1/include.am
include tests/base64/include.am
include tests/ocsp/include.am
include tests/ocsp-scgi/include.am
include tests/pkcs/include.am
include tests/x509/include.am
include tests/encrypt/include.am
include tests/genkey_sign_ver/include.am
include tests/hash/include.am
include tests/bench/include.am
include tests/client/include.am
include tests/server/include.am
include tests/testEncDec/include.am
endif
include ide/include.am
#####include data/include.am


TESTS += $(check_PROGRAMS)

check_SCRIPTS+= $(dist_noinst_SCRIPTS)
TESTS += $(check_SCRIPTS)

# Automake's test driver writes .log/.trs files next to each test script.
# When tests live in the source tree (no VPATH), those files land in tests/,
# where EXTRA_DIST+=tests would otherwise sweep them into the tarball and
# break `make distcheck` via stale VPATH lookups.
# Generate the compressed manpages into the tarball from their .1 sources,
# so the .gz copies are never hand-maintained in git. These ship in the release
# tarball for downstream packaging; they are intentionally not installed
# (man_MANS installs the .1 files, and distros compress man pages themselves).
# -n keeps the output byte-reproducible across dist runs (no embedded
# filename/mtime). Only done if manpages are enabled.
dist-hook:
	find $(distdir)/tests -name '*.log' -delete
	find $(distdir)/tests -name '*.trs' -delete
# Always strip stale .1.gz from the tarball (local manpages-gz output or a
# prior dist may have left them in manpages/). Regenerate only when enabled.
	chmod u+w $(distdir)/manpages 2>/dev/null || true
	rm -f $(distdir)/manpages/*.1.gz
if ENABLE_MANPAGES
	for f in $(distdir)/manpages/*.1; do gzip -nc "$$f" > "$$f.gz"; done
endif

if ENABLE_MANPAGES
# On-demand regeneration of the compressed manpages from their .1 sources.
# Run `make manpages-gz` after editing any .1; thanks to the prerequisite
# only the pages whose source actually changed are rebuilt. These .gz are
# gitignored and NOT installed (man_MANS installs the .1 files) -- the
# release tarball gets its own fresh copies via the dist-hook above, so this
# target is purely a local convenience (preview/packaging). It is not wired
# into `all` on purpose: writing into the source tree during a normal build
# would break `make distcheck`, which builds against a read-only srcdir.
# -n keeps the output byte-reproducible (no embedded filename/mtime).
MAN_GZ = $(man_MANS:.1=.1.gz)

.PHONY: manpages-gz
manpages-gz: $(MAN_GZ)

manpages/%.1.gz: $(srcdir)/manpages/%.1
	@$(MKDIR_P) manpages
	gzip -nc "$<" > "$@"

CLEANFILES += $(MAN_GZ)
endif

test: check
#DISTCLEANFILES+= wolfssl-config


maintainer-clean-local:
	-rm Makefile.in
	-rm aclocal.m4
	-rm build-aux/compile
	-rm build-aux/config.guess
	-rm build-aux/config.sub
	-rm build-aux/depcomp
	-rm build-aux/install-sh
	-rm build-aux/ltmain.sh
	-rm build-aux/missing
	-rm wolfssl-config
	-rmdir build-aux
	-rm configure
	-rm config.log
	-rm config.status
	-rm config.in
	-rm m4/libtool.m4
	-rm m4/ltoptions.m4
	-rm m4/ltsugar.m4
	-rm m4/ltversion.m4
	-rm m4/lt~obsolete.m4
	find . -type f -name '*~' -exec rm -f '{}' \;
	-rm -f @PACKAGE@-*.tar.gz
	-rm -f @PACKAGE@-*.rpm

#install-exec-local:	install-generic-config

#install-generic-config:
#	$(mkinstalldirs) $(DESTDIR)$(bindir)
#	$(INSTALL_SCRIPT) @GENERIC_CONFIG@ $(DESTDIR)$(bindir)

#uninstall-local:
#	-rm -f $(DESTDIR)$(bindir)/@GENERIC_CONFIG@

merge-clean:
	@find ./ | $(GREP) \.gcda | xargs rm -f
	@find ./ | $(GREP) \.gcno | xargs rm -f
	@find ./ | $(GREP) \.gz | xargs rm -f
	@find ./ | $(GREP) \.orig | xargs rm -f
	@find ./ | $(GREP) \.rej | xargs rm -f
	@find ./ | $(GREP) \.rpm | xargs rm -f
	@find ./ | $(GREP) \.THIS | xargs rm -f
	@find ./ | $(GREP) \.OTHER | xargs rm -f
	@find ./ | $(GREP) \.BASE | xargs rm -f
	@find ./ | $(GREP) \~$$ | xargs rm -f

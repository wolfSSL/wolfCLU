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

#includes additional rules from aminclude.am
@INC_AMINCLUDE@
DISTCLEANFILES+= aminclude.am

#exampledir = $(docdir)/example
#dist_example_DATA=

ACLOCAL_AMFLAGS= -I m4

EXTRA_DIST+= tests
EXTRA_DIST+= manpages
EXTRA_DIST+= README.md
EXTRA_DIST+= LICENSE
EXTRA_DIST+= ChangeLog.md
EXTRA_DIST+= wolfclu.sln
EXTRA_DIST+= wolfCLU.vcxproj
EXTRA_DIST+= wolfCLU.vcxproj.filters

man_MANS+= manpages/wolfCLU_benchmark.1
man_MANS+= manpages/wolfCLU_decrypt.1
man_MANS+= manpages/wolfCLU_encrypt.1
man_MANS+= manpages/wolfCLU_hash.1
man_MANS+= manpages/wolfssl.1

include src/include.am
include wolfclu/include.am
include tests/dh/include.am
include tests/dsa/include.am
include tests/pkey/include.am
include tests/dgst/include.am
include tests/rand/include.am
include tests/base64/include.am
include tests/pkcs/include.am
include tests/x509/include.am
include tests/encrypt/include.am
include tests/genkey_sign_ver/include.am
include tests/hash/include.am
include tests/bench/include.am
include tests/client/include.am
include tests/server/include.am
include ide/include.am
#####include data/include.am


TESTS += $(check_PROGRAMS)

check_SCRIPTS+= $(dist_noinst_SCRIPTS)
TESTS += $(check_SCRIPTS)

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

bin_PROGRAMS =
check_PROGRAMS =
TESTS =
EXTRA_DIST =
CLEANFILES =
DISTCLEANFILES =
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_TESTS_ENVIRONMENT = top_builddir='$(top_builddir)'; \
		       top_srcdir='$(top_srcdir)'; \
		       export top_builddir top_srcdir;
TESTS_ENVIRONMENT = $(AM_TESTS_ENVIRONMENT)

AM_CPPFLAGS = \
        -include $(top_builddir)/config.h \
        -I${top_srcdir}/axa
AM_CFLAGS = \
	${my_CFLAGS}
AM_LDFLAGS = \
	${my_LDFLAGS}

configdir = ${CONFDIR}
dist_config_DATA = etc/fields

EXTRA_DIST += \
	autogen.sh \
	axalib/README \
	axa/README \
	COPYRIGHT \
	debian/axa-tools.install \
	debian/changelog \
	debian/control \
	debian/copyright \
	debian/gbp.conf \
	debian/libaxa3.install \
	debian/libaxa-dev.install \
	debian/rules \
	DoxygenLayout.xml \
	fwd.man \
	json-schema.yaml \
	LICENSE \
	radwatch.man \
	README.md \
	sratool/cmds.man \
	sratool/README \
	sratunnel/README \
	srawatch.man \
	watch.man

#
##
### documentation
##
#

MAN_PROCESS = $(AM_V_GEN) soelim -I. -I`dirname $<` -r $< | sed -e "s/^\.Dd.*/.Dd `date '+%B %d, %Y'`/" >$@
.man.1:
	    $(MAN_PROCESS)
.man.8:
	    $(MAN_PROCESS)

sratool/sratool.1: sratool/sratool.man \
	fwd.man watch.man srawatch.man sratool/options.man sratool/cmds.man
sratool/radtool.1: sratool/radtool.man \
	fwd.man watch.man radwatch.man sratool/options.man sratool/cmds.man
sratunnel/sratunnel.1: sratunnel/sratunnel.man fwd.man srawatch.man watch.man
sratunnel/radtunnel.1: sratunnel/radtunnel.man fwd.man srawatch.man watch.man

man_MANS =  \
	sratool/sratool.1 \
	sratool/radtool.1 \
	sratunnel/sratunnel.1 \
	sratunnel/radtunnel.1 \
	tools/axa_link_certs.8 \
	tools/axa_make_cert.8 \
	tools/axa_server_cert.8
DISTCLEANFILES += $(man_MANS)

#
##
### library
##
#

LIBAXA_CURRENT=3
LIBAXA_REVISION=1
LIBAXA_AGE=0

nobase_include_HEADERS = \
	axa/axa.h \
	axa/bits.h \
	axa/client.h \
	axa/client_config.h \
	axa/dns_walk.h \
	axa/axa_endian.h \
	axa/fields.h \
	axa/json.h \
	axa/kickfile.h \
	axa/open_nmsg_out.h \
	axa/protocol.h \
	axa/socket.h \
	axa/strbuf.h \
	axa/trie.h \
	axa/version.h \
	axa/wire.h \
	axa/yajl_shortcuts.h \
	libmy/b64_encode.h
lib_LTLIBRARIES = axa/libaxa.la

axa_libaxa_la_SOURCES = \
	axa/axa.h \
	axa/bits.h \
	axa/client.h \
	axa/client_config.h \
	axa/dns_walk.h \
	axa/axa_endian.h \
	axa/fields.h \
	axa/json.h \
	axa/kickfile.h \
	axa/open_nmsg_out.h \
	axa/protocol.h \
	axa/socket.h \
	axa/strbuf.h \
	axa/trie.h \
	axa/version.h \
	axa/wire.h \
	axalib/apikey.c \
	axalib/bit_funcs.c \
	axalib/client.c \
	axalib/client_config.c \
	axalib/dns_walk.c \
	axalib/domain_to_str.c \
	axalib/emsg.c \
	axalib/fields.c \
	axalib/get_field_name.c \
	axalib/hash_divisor.c \
	axalib/json.c \
	axalib/kickfile.c \
	axalib/open_nmsg_out.c \
	axalib/parse_ch.c \
	axalib/socket.c \
	axalib/strbuf.c \
	axalib/time.c \
	axalib/tls.c \
	axalib/trie.c \
	axalib/version.c \
	axalib/wdns_res.c \
	axalib/wdns_rtype.c \
	axalib/whit2nmsg.c \
	axalib/wire.c \
	libmy/b64_encode.c libmy/b64_encode.h

axa_libaxa_la_LDFLAGS = $(AM_LDFLAGS) \
	-version-info $(LIBAXA_CURRENT):$(LIBAXA_REVISION):$(LIBAXA_AGE) \
	-export-symbols-regex "^(axa_[a-z].*)" \
	${libssl_LIBS} \
	${libcrypto_LIBS} \
	${libpcap_LIBS} \
	${libwdns_LIBS} \
	${libnmsg_LIBS} \
	${strlcpy_LIBS} \
	${yajl_LIBS}

axa_libaxa_la_CFLAGS = \
	${AM_CFLAGS} \
	${libssl_CFLAGS} \
	${libcrypto_CFLAGS} \
	${libpcap_CFLAGS} \
	${libwdns_CFLAGS} \
	${libnmsg_CFLAGS} \
	${strlcpy_CFLAGS} \
	${yajl_CFLAGS}

pkgconfig_DATA = axa/libaxa.pc


#
##
### programs
##
#

bin_PROGRAMS += sratool/sratool
sratool_sratool_SOURCES = \
	sratool/cmd.c \
	sratool/error.c \
	sratool/infile.c \
	sratool/io.c \
	sratool/main.c \
	sratool/output.c \
	sratool/server.c \
	sratool/signal.c \
	sratool/print.c \
	sratool/time.c \
	sratool/sratool.h

sratool_sratool_LDADD = \
	axa/libaxa.la \
	${libssl_LIBS} \
	${libcrypto_LIBS} \
	${libpcap_LIBS} \
	${libnmsg_LIBS} \
	${libz_LIBS} \
	${libwdns_LIBS} \
	${libedit_LIBS} \
	${strlcpy_LIBS} \
	${LIBM}

sratool_sratool_CFLAGS = \
	${AM_CFLAGS} \
	${libssl_CFLAGS} \
	${libcrypto_CFLAGS} \
	${libpcap_CFLAGS} \
	${libnmsg_CFLAGS} \
	${libz_CFLAGS} \
	${libwdns_CFLAGS} \
	${libedit_CFLAGS}

bin_PROGRAMS += sratool/radtool
sratool_radtool_SOURCES = ${sratool_sratool_SOURCES}
sratool_radtool_LDADD = ${sratool_sratool_LDADD}
sratool_radtool_CFLAGS = ${sratool_sratool_CFLAGS}

bin_PROGRAMS += sratunnel/sratunnel
sratunnel_sratunnel_SOURCES = \
	sratunnel/forward.c \
	sratunnel/main.c \
	sratunnel/output.c \
	sratunnel/pidfile.c \
	sratunnel/print.c \
	sratunnel/server.c \
	sratunnel/signal.c \
	sratunnel/sratunnel.h

sratunnel_sratunnel_LDADD = \
	axa/libaxa.la \
	${libnmsg_LIBS} \
	${libssl_LIBS} \
	${libcrypto_LIBS} \
	${libpcap_LIBS} \
	${strlcpy_LIBS} \
	${LIBM}

sratunnel_sratunnel_CFLAGS = \
	${AM_CFLAGS} \
	${libnmsg_CFLAGS} \
	${libssl_CFLAGS} \
	${libcrypto_CFLAGS} \
	${libpcap_CFLAGS}

bin_PROGRAMS += sratunnel/radtunnel
sratunnel_radtunnel_SOURCES = ${sratunnel_sratunnel_SOURCES}
sratunnel_radtunnel_LDADD = ${sratunnel_sratunnel_LDADD}
sratunnel_radtunnel_CFLAGS = ${sratunnel_sratunnel_CFLAGS}

#
##
### scripts
##
#

bin_SCRIPTS = \
	tools/axa_link_certs \
	tools/axa_make_cert \
	tools/axa_server_cert

#
##
### documentation
##
#

if HAVE_DOXYGEN
stamp-html: $(DOXYGEN_INPUT) $(top_builddir)/Doxyfile $(top_srcdir)/DoxygenLayout.xml $(include_HEADERS) $(nobase_include_HEADERS)
	$(AM_V_GEN) $(DOXYGEN)
	@touch $@
html-local: stamp-html
doc: html-local
clean-local:
	rm -rf $(top_builddir)/html $(top_builddir)/stamp-html
endif

spotless: distclean
	rm -fr ar-lib aclocal.m4 autom4te.cache configure config.* Makefile.in  \
	autoscan.log config.h compile depcomp configure.scan       	   			\
	missing install-sh ltmain.sh $(top_builddir)/html						\
	$(top_builddir)/stamp-html

#
##
### tests
##
#

EXTRA_DIST += tests/test-config tests/test-config-badperms

if HAVE_YAJL
TESTS += tests/test-json
check_PROGRAMS += tests/test-json
tests_test_json_SOURCES = tests/test-json.c
tests_test_json_LDADD = axa/libaxa.la ${libnmsg_LIBS} ${check_LIBS}
tests_test_json_CFLAGS = ${AM_CFLAGS} ${libnmsg_CFLAGS} ${check_CFLAGS} ${libssl_CFLAGS}
endif

TESTS += tests/test-apikey
check_PROGRAMS += tests/test-apikey
tests_test_apikey_SOURCES = tests/test-apikey.c
tests_test_apikey_LDADD = axa/libaxa.la ${libnmsg_LIBS} ${check_LIBS}
tests_test_apikey_CFLAGS = ${AM_CFLAGS} ${libnmsg_CFLAGS} ${check_CFLAGS} ${libssl_CFLAGS}

TESTS += tests/test-client_config
check_PROGRAMS += tests/test-client_config
tests_test_client_config_SOURCES = tests/test-client_config.c
tests_test_client_config_LDADD = axa/libaxa.la ${libnmsg_LIBS} ${check_LIBS} ${strlcpy_LIBS}
tests_test_client_config_CFLAGS = ${AM_CFLAGS} ${libnmsg_CFLAGS} ${check_CFLAGS} ${libssl_CFLAGS} ${strlcpy_CFLAGS}

TESTS += tests/test-stats
check_PROGRAMS += tests/test-stats
tests_test_stats_SOURCES = tests/test-stats.c
tests_test_stats_LDADD = axa/libaxa.la ${libnmsg_LIBS} ${check_LIBS} ${strlcpy_LIBS}
tests_test_stats_CFLAGS = ${AM_CFLAGS} ${libnmsg_CFLAGS} ${check_CFLAGS} ${libssl_CFLAGS} ${strlcpy_CFLAGS}

TESTS += tests/test-kill
check_PROGRAMS += tests/test-kill
tests_test_kill_SOURCES = tests/test-kill.c
tests_test_kill_LDADD = axa/libaxa.la ${libnmsg_LIBS} ${check_LIBS} ${strlcpy_LIBS}
tests_test_kill_CFLAGS = ${AM_CFLAGS} ${libnmsg_CFLAGS} ${check_CFLAGS} ${libssl_CFLAGS} ${strlcpy_CFLAGS}

TESTS += tests/test-kickfile
check_PROGRAMS += tests/test-kickfile
tests_test_kickfile_SOURCES = tests/test-kickfile.c
tests_test_kickfile_LDADD = axa/libaxa.la ${libnmsg_LIBS} ${check_LIBS} ${strlcpy_LIBS}
tests_test_kickfile_CFLAGS = ${AM_CFLAGS} ${libnmsg_CFLAGS} ${check_CFLAGS} ${libssl_CFLAGS} ${strlcpy_CFLAGS}

EXTRA_DIST += tests/tool-tests-data/001000-single-command \
tests/tool-tests-data/002210-valid-before-and-after-unrecognized-command \
tests/tool-tests-data/002000-multiple-commands \
tests/tool-tests-data/002200-valid-then-unrecognized-command \
tests/tool-tests-data/002100-unrecognized-command \
tests/tool-tests-data/001010-multiple-commands-on-single-line \
tests/tool-tests-data/with-server/001000-connect \
tests/tool-tests-data/with-server/001010-invalid-username

TESTS += tests/test-tools-without-server.sh \
	 tests/test-tools-with-server.sh

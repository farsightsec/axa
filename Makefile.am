bin_PROGRAMS =
check_PROGRAMS =
TESTS =
EXTRA_DIST =
CLEANFILES =
DISTCLEANFILES =
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

AM_CPPFLAGS = \
        -include $(top_builddir)/config.h \
        -I${top_srcdir}/axa
AM_CFLAGS = \
	${my_CFLAGS}
AM_LDFLAGS = \
	${my_LDFLAGS}

configdir = ${CONFDIR}
dist_config_DATA = etc/fields

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

EXTRA_DIST += \
	fwd.man \
	watch.man \
	srawatch.man \
	radwatch.man \
	sratool/cmds.man \
	README.md \
	DoxygenLayout.xml

man_MANS =  \
	sratool/sratool.1 \
	sratool/radtool.1 \
	sratunnel/sratunnel.1 \
	sratunnel/radtunnel.1 \
	cert_tools/axa_link_certs.8 \
	cert_tools/axa_make_cert.8 \
	cert_tools/axa_server_cert.8
DISTCLEANFILES += $(man_MANS)

#
##
### library
##
#

LIBAXA_CURRENT=0
LIBAXA_REVISION=0
LIBAXA_AGE=0

nobase_include_HEADERS = \
	axa/axa.h \
	axa/bits.h \
	axa/client.h \
	axa/dns_walk.h \
	axa/axa_endian.h \
	axa/fields.h \
	axa/json.h \
	axa/open_nmsg_out.h \
	axa/protocol.h \
	axa/socket.h \
	axa/strbuf.h \
	axa/trie.h \
	axa/wire.h \
	libmy/b64_encode.h
lib_LTLIBRARIES = axa/libaxa.la

axa_libaxa_la_SOURCES = \
	axa/axa.h \
	axa/bits.h \
	axa/client.h \
	axa/dns_walk.h \
	axa/axa_endian.h \
	axa/fields.h \
	axa/json.h \
	axa/open_nmsg_out.h \
	axa/protocol.h \
	axa/socket.h \
	axa/strbuf.h \
	axa/trie.h \
	axa/wire.h \
	axalib/client.c \
	axalib/dns_walk.c \
	axalib/domain_to_str.c \
	axalib/emsg.c \
	axalib/fields.c \
	axalib/get_field_name.c \
	axalib/hash_divisor.c \
	axalib/json.c \
	axalib/open_nmsg_out.c \
	axalib/parse_ch.c \
	axalib/socket.c \
	axalib/strbuf.c \
	axalib/time.c \
	axalib/tls.c \
	axalib/trie.c \
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
	${libprotobuf_c_CFLAGS} \
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
	${libprotobuf_c_LIBS} \
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
	${libprotobuf_c_CFLAGS} \
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
	${libprotobuf_c_CFLAGS} \
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
	cert_tools/axa_link_certs \
	cert_tools/axa_make_cert \
	cert_tools/axa_server_cert

#
##
### documentation 
##
#

exampledir = ${docdir}/examples
nobase_example_DATA = \
	sratool/main.c \
	sratool/print.c \
	sratool/sratool.h \
	sratool/README \
	sratunnel/main.c \
	sratunnel/README

EXTRA_DIST += \
	autogen.sh \
	copyright \
	axalib/README \
	axa/README \
	sratool/README \
	sratunnel/README

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

EXTRA_DIST += tests/test-json.c

TESTS += tests/test-json
check_PROGRAMS += tests/test-json
tests_test_json_SOURCES = tests/test-json.c
tests_test_json_LDADD = axa/libaxa.la ${libnmsg_LIBS} ${check_LIBS}
tests_test_json_CFLAGS = ${AM_CFLAGS} ${libnmsg_CFLAGS} ${check_CFLAGS} ${libssl_CFLAGS}

AC_PREREQ(2.60)
AC_INIT([axa], [0.2.4])
AC_CONFIG_SRCDIR([axa/axa.h])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign 1.11 -Wall -Wno-portability silent-rules subdir-objects])
AC_PROG_CC_STDC
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])
LT_INIT

my_CFLAGS=" \
-Wextra -Wall -Wbad-function-cast -Wcast-align -Wmissing-noreturn \
-Wnested-externs -Wpointer-arith -Wshadow -Wwrite-strings \
-Wdeclaration-after-statement -Wswitch-enum \
-Wunused \
-Wunreachable-code \
-Wuninitialized \
-Wno-unknown-pragmas \
-Wmissing-declarations -Wmissing-prototypes \
-Wsign-compare -Wchar-subscripts \
-Wstrict-prototypes -Wshadow \
-Wformat-security"
AC_SUBST([my_CFLAGS])

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES([Makefile axa/libaxa.pc])

PKG_PROG_PKG_CONFIG
if test -n "$PKG_CONFIG"; then
    if $PKG_CONFIG --variable=pc_path pkg-config 2>/dev/null | grep -q /libdata/; then
        PKG_INSTALLDIR(['${prefix}/libdata/pkgconfig'])
    else
        PKG_INSTALLDIR
    fi
fi

AC_C_BIGENDIAN

MY_CHECK_LIBPCAP

MY_CHECK_LIBPROTOBUF_C

save_LIBS="$LIBS"
AC_SEARCH_LIBS([strlcpy],
               [bsd],
               [strlcpy_LIBS="$LIBS"],
               [AC_MSG_ERROR([could not find library containing strlcpy])]
              )
LIBS="$save_LIBS"
AC_SUBST(strlcpy_LIBS)

PKG_CHECK_MODULES([libedit], [libedit], [], [MY_CHECK_LIBEDIT])

PKG_CHECK_MODULES([libnmsg], [libnmsg >= 0.8.0])

PKG_CHECK_MODULES([libwdns], [libwdns])

AC_CHECK_HEADER([zlib.h], [], [ AC_MSG_ERROR([required header file not found]) ])
AC_CHECK_LIB([z], [deflate], [], [ AC_MSG_ERROR([required library not found]) ])

save_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$libnmsg_CFLAGS"
AC_CHECK_HEADERS([nmsg/base/dnsqr.pb-c.h nmsg/base/encode.pb-c.h nmsg/base/packet.pb-c.h nmsg/sie/newdomain.pb-c.h],
                 [],
                 [AC_MSG_ERROR([required header file not found])])
CPPFLAGS="$save_CPPFLAGS"

AX_DEFINE_DIR([CONFDIR], [sysconfdir/axa], [config dir for axa])
AC_DEFINE_UNQUOTED(FIELDS_FILE,"$CONFDIR/fields",[Fields file])

AC_DEFINE_UNQUOTED(AXA_PVERS_STR,"version $PACKAGE_VERSION", [Version])

AC_OUTPUT
AC_MSG_RESULT([
    $PACKAGE $VERSION

        compiler:               ${CC}
        cflags:                 ${CFLAGS}
        ldflags:                ${LDFLAGS}
        libs:                   ${LIBS}

        prefix:                 ${prefix}
        sysconfdir:             ${sysconfdir}
        libdir:                 ${libdir}
        includedir:             ${includedir}
        pkgconfigdir:           ${pkgconfigdir}

        bigendian:              ${ac_cv_c_bigendian}
])

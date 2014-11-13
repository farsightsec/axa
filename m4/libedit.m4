AC_DEFUN([MY_CHECK_LIBEDIT], [
    libedit_CFLAGS=""
    libedit_LIBS="-ledit"

    AC_ARG_WITH(
        [libedit],
        AC_HELP_STRING([--with-libedit=DIR], [libedit installation path]),
        [],
        [withval="yes"]
    )
    if test "$withval" = "yes"; then
        withval="/usr /usr/local"
    fi

    libedit_dir=""

    AC_MSG_CHECKING([for libedit headers])
    for dir in $withval; do
        if test -f "$dir/include/histedit.h"; then
            libedit_dir="$dir"
            if test "$dir" != "/usr"; then
                libedit_CFLAGS="-I$dir/include"
            fi
            break
        fi
    done
    if test -n "$libedit_dir"; then
        AC_MSG_RESULT([$libedit_dir])
    else
        AC_MSG_ERROR([cannot find histedit.h in $withval])
    fi

    save_LDFLAGS="$LDFLAGS"
    save_LIBS="$LIBS"
    if test "$libedit_dir" != "/usr"; then
        libedit_LIBS="$libedit_LIBS -L$libedit_dir/lib"
        LDFLAGS="-L$libedit_dir/lib"
    fi
    AC_CHECK_LIB(
        [edit],
        [history],
        [],
        [AC_MSG_ERROR([required library not found])]
    )
    LDFLAGS="$save_LDFLAGS"
    LIBS="$save_LIBS"

    AC_SUBST([libedit_CFLAGS])
    AC_SUBST([libedit_LIBS])
])

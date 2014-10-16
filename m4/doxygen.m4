AC_DEFUN([MY_CHECK_DOXYGEN], [

    PROG=`doxygen --version`
    OIFS="$IFS"
    IFS='.'
    read -a version <<< "${PROG}"
    IFS="$OIFS"
    if test ${version[[0]]} -ge 1 &&
       test ${version[[1]]} -ge 8 &&
       test ${version[[2]]} -ge 3; then
        DOXYGEN_version="newish"
    else
        DOXYGEN_version="oldish"
    fi
    AC_SUBST([DOXYGEN_version])
])

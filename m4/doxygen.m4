AC_DEFUN([MY_CHECK_DOXYGEN], [

    OIFS=$IFS
    IFS=.
    DOXYGEN_version="oldish"
    doxy_ver1=`doxygen --version`
    min_ver1="1.8.3"
    doxy_ver=($doxy_ver1)
    min_ver=($min_ver1)
    for ((i = 0; i < ${#doxy_ver[@]}; i++))
        do
            if ((10#${doxy_ver[i]} > 10#${min_ver[i]}))
            then
                DOXYGEN_version="newish"
                break
            fi
            if ((10#${doxy_ver[i]} > 10#${min_ver[i]}))
            then
                DOXYGEN_version="oldish"
                break
            fi
    done

    AC_SUBST([DOXYGEN_version])
    IFS=$OIFS
])

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(NuFW, 2.2.0, nufw-devel@nongnu.org)
AM_CONFIG_HEADER(src/include/config.h)
AC_CONFIG_SRCDIR([src/nufw/main.c])

# Checks for programs.
AC_PROG_CC

AM_PROG_LIBTOOL
AC_PROG_INSTALL

# Checks for endianess
AC_C_BIGENDIAN()

case $host in
*-*-linux*) AC_DEFINE([LINUX],[1],[Target is Linux]) ;;
*-*-darwin*) AC_DEFINE([FREEBSD],[1],[Target is darwin (freebsd like)]) ;;
*-*-freebsd*) AC_DEFINE([FREEBSD],[1],[Target is freebsd]) ;;
*) AC_MSG_ERROR([Linux, FreeBSD, Darwin only, dude!]);;
esac

# check to see if struct dirent has the d_type member
AC_CHECK_MEMBER([struct dirent.d_type],
        [AC_DEFINE([HAVE_STRUCT_DIRENT_D_TYPE],
        [1],
        [Define if struct dirent has member d_type])],
        ,
        [#include <dirent.h>])

# Checks for libraries.

AC_CHECK_LIB([pthread], [pthread_mutex_init],, check_pthread=no)

AC_CHECK_TOOL(DOCBOOK2MAN, docbook2man, true)
AC_CHECK_TOOL(DOCBOOK2PDF, docbook2pdf, true)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_STAT
AC_CHECK_FUNCS([gethostbyname memset socket strcasecmp strspn])

AC_CHECK_LIB([gcrypt], [gcry_md_open],AC_DEFINE([HAVE_LIBRARY_GCRYPT],[1],[Gcrypt lib flag]), check_gcrypt=no,[-L/usr/local/lib])
AC_CHECK_LIB([gnutls], [gnutls_init],AC_DEFINE([HAVE_LIBRARY_GNUTLS],[1],[Gnutls lib flag]), check_gnutls=no)
AC_CHECK_LIB([sasl2],[sasl_server_init],AC_DEFINE([HAVE_LIBRARY_SASL2],[1],[SASL lib flag]), check_sasl=no)

#Configure database support, depending on user input
AC_ARG_WITH(prelude-log,
        [AC_HELP_STRING(--with-prelude-log,
        Support user activity logging in Prelude)],
        enable_prelude_log=$withval,
        enable_prelude_log="")

AC_ARG_WITH(mysql-log, [AC_HELP_STRING(--with-mysql-log,  Support user activity logging in Mysql database)], enable_mysql_log=$withval, enable_mysql_log="")
AC_ARG_WITH(pgsql-log, [AC_HELP_STRING(--with-pgsql-log,  Support user activity logging in PostgreSQL database)], enable_pgsql_log=$withval, enable_pgsql_log="")
AC_ARG_WITH(syslog-log, [AC_HELP_STRING(--with-syslog-log,  Support user activity logging in syslog)], enable_syslog_log=$withval, enable_syslog_log="yes")

AC_ARG_WITH(plaintext-auth, [AC_HELP_STRING(--with-plaintext-auth,  Support for authentification with plaintext file)], enable_plaintext_auth=$withval, enable_plaintext_auth="yes")
AC_ARG_WITH(mark-group, [AC_HELP_STRING(--with-mark-group,  Support mark packet by group)], enable_mark_group=$withval, enable_mark_group="yes")
AC_ARG_WITH(mark-field, [AC_HELP_STRING(--with-mark-field,  Support mark packet by packet field)], enable_mark_field=$withval, enable_mark_field="yes")
AC_ARG_WITH(mark-flag, [AC_HELP_STRING(--with-mark-flag,  Support mark packet following acl indication)], enable_mark_flag=$withval, enable_mark_flag="yes")
AC_ARG_WITH(system-auth, [AC_HELP_STRING(--with-system-auth,  Support PAM+NSS authentication)], enable_system_auth=$withval, enable_system_auth="yes")

AC_ARG_WITH(ldap,   [AC_HELP_STRING(--with-ldap,  Support LDAP directory for users and acl lookup)],ldap=$withval, ldap="")


AC_ARG_WITH(nfqueue,   [AC_HELP_STRING(--with-nfqueue, Compile for NFQUEUE instead of QUEUE)],use_nfqueue=$withval, use_nfqueue="yes")
AC_ARG_WITH(nfconntrack,   [AC_HELP_STRING(--with-nfconntrack, Compile with netfilter_conntrack)],use_nfconntrack=$withval, use_nfconntrack="")


AC_ARG_WITH(utf8,   [AC_HELP_STRING(--with-utf8, Use UTF8 exchange between client and server)], AC_DEFINE_UNQUOTED([USE_UTF8],[1],[Will use UTF8 exchange]))
AC_ARG_WITH(fixedtimeout,   [AC_HELP_STRING(--with-fixedtimeout, Assume libconntrack has fixed timeout extension )],have_conntrack_fixedtimeout=$withval )


AC_ARG_ENABLE(nufw,   [AC_HELP_STRING(--disable-nufw, Don't build nufw (default is to build))],build_nufw=$enableval, build_nufw="yes")
AC_ARG_ENABLE(nuauth, [AC_HELP_STRING(--disable-nuauth, Don't build nuauth (default is to build))],build_nuauth=$enableval, build_nuauth="yes")
AC_ARG_ENABLE(libnuclient,   [AC_HELP_STRING(--disable-libnuclient, Don't build libnuclient (default is to build))],build_libnuclient=$enableval, build_libnuclient="yes")
AC_ARG_ENABLE(nutcpc,   [AC_HELP_STRING(--disable-nutcpc, Don't build nutcpc (default is to build))],build_nutcpc=$enableval, build_nutcpc="yes" )
AC_ARG_ENABLE(pam-nufw,   [AC_HELP_STRING(--enable-pam-nufw, Build pam_nufw (default is not to build))],build_pam_nufw=$enableval, build_pam_nufw="no" )
AC_ARG_ENABLE(nuauth-command,   [AC_HELP_STRING(--disable-nuauth-command, Don't build nuauth_command (default is to build))],build_nuauth_command=$enableval, build_nuauth_command="yes" )

AC_ARG_ENABLE(debug,   [AC_HELP_STRING(--enable-debug, Add development debug messages (default no))],debug=$enableval, debug="")
AC_ARG_WITH(perf-display,
    [AC_HELP_STRING(--with-perf-display, Enable performance display (default yes))],
    use_perf_display=$withval, use_perf_display="yes")

if test "${use_perf_display}" = "yes"; then
	AC_DEFINE_UNQUOTED([PERF_DISPLAY_ENABLE],[1],[Performance display])
fi

if test "${build_nuauth}" = "yes"; then
        # glib stuff
        AM_PATH_GLIB_2_0(2.4.0, , check_glib=no,[gthread gmodule])
        if test "$enable_system_auth" = "yes"; then
                AC_CHECK_LIB([pam],[pam_start],AC_DEFINE([HAVE_LIBRARY_PAM],[1],[pam lib flag]), check_pam=no)
        fi

        if test "${ldap}" = "yes"; then
                 AC_CHECK_LIB([ldap],[ldap_simple_bind_s],AC_DEFINE([HAVE_LIBRARY_LDAP],[1],[ldap lib flag]), check_ldap=no)
        fi

        if test "$enable_mysql_log" = "yes"; then
			if which mysql_config 1>/dev/null; then
				AC_CHECK_LIB([mysqlclient],[mysql_real_connect],AC_DEFINE([HAVE_LIBRARY_MYSQLCLIENT],[1],[mysql lib flag] )  , check_mysql=no,[$(mysql_config --libs)])
                		AC_CHECK_LIB([mysqlclient],[mysql_ssl_set],AC_DEFINE_UNQUOTED([HAVE_MYSQL_SSL],[1],[Will compile mysql log module with ssl support]),AC_MSG_NOTICE([mysqlclient has no ssl support]),[$(mysql_config --libs)])
				have_mysql_config="yes"
			else
                		AC_CHECK_LIB([mysqlclient],[mysql_real_connect],AC_DEFINE([HAVE_LIBRARY_MYSQLCLIENT],[1],[mysql lib flag] ), check_mysql=no)
                		AC_CHECK_LIB([mysqlclient],[mysql_ssl_set],AC_DEFINE_UNQUOTED([HAVE_MYSQL_SSL],[1],[Will compile mysql log module with ssl support]),AC_MSG_NOTICE([mysqlclient has no ssl support]))
		    fi
        fi

        if test "$enable_prelude_log" = "yes"; then
                # Evil hack to check if /usr/include/libprelude/prelude.h does exist.
                # TODO: Be able to change this directory and send this directory
                #       to Prelude module of NuAuth
                OLDCFLAGS="$CFLAGS"
                OLDCPPFLAGS="$CPPFLAGS"
                CFLAGS="$CFLAGS -I/usr/include/libprelude/"
                CPPFLAGS="$CFLAGS -I/usr/include/libprelude/"
                AC_CHECK_HEADER(prelude.h,, check_prelude=no)

                # Check for prelude_init() function libprelude.so
                AC_CHECK_LIB([prelude],[prelude_init],
                        AC_DEFINE([HAVE_LIBRARY_PRELUDE],[1],[prelude library flag]),
                        check_prelude=no)
                CFLAGS="$OLDCFLAGS"
                CPPFLAGS="$OLDCPPFLAGS"
        fi

        if test "$enable_pgsql_log" = "yes"; then
                AC_CHECK_LIB([pq],[PQconnectdb],AC_DEFINE([HAVE_LIBRARY_PQ],[1],[pgsql lib flag]), check_pgsql=no)
        fi
fi

AM_CONDITIONAL(USE_SYSTEM_AUTH, test x$enable_system_auth = xyes)
AM_CONDITIONAL(USE_LDAP, test x$ldap = xyes)
AM_CONDITIONAL(USE_PRELUDE_LOG, test x$enable_prelude_log = xyes)
AM_CONDITIONAL(USE_MYSQL_LOG, test x$enable_mysql_log = xyes)
AM_CONDITIONAL(HAVE_MYSQL_CONFIG, test x$have_mysql_config = xyes)

AM_CONDITIONAL(USE_PGSQL_LOG, test x$enable_pgsql_log = xyes)
AM_CONDITIONAL(USE_PLAINTEXT_AUTH, test x$enable_plaintext_auth = xyes)
AM_CONDITIONAL(USE_MARK_GROUP, test x$enable_mark_group = xyes)
AM_CONDITIONAL(USE_MARK_FIELD, test x$enable_mark_field = xyes)
AM_CONDITIONAL(USE_MARK_FLAG, test x$enable_mark_flag = xyes)
AM_CONDITIONAL(USE_SYSLOG_LOG, test x$enable_syslog_log = xyes)

if test "${build_nufw}" = "yes"; then
    if test "${use_nfqueue}" = "yes"; then
        # if we don't have we can't build nufw
        AC_CHECK_LIB([nfnetlink], [nfnl_open], have_nfqueue="yes", build_nufw="")
        AC_CHECK_LIB([netfilter_queue], [nfq_open], have_nfqueue="yes", have_nfqueue="",[-lnfnetlink])
        AC_CHECK_LIB([netfilter_queue], [nfq_set_queue_maxlen],AC_DEFINE_UNQUOTED([HAVE_NFQ_SET_QUEUE_MAXLEN],[1],[Found queue max length support in netfilter_queue]) ,,[-lnfnetlink])
        AC_CHECK_LIB([nfnetlink], [nlif_catch],have_nlif_catch="yes")
        if test "${have_nlif_catch}" = "yes"; then
            AC_CHECK_LIB([netfilter_queue], [nfq_get_indev_name],have_nfq_indev_name="yes",, [-lnfnetlink])
            if test "${have_nfq_indev_name}" = "yes"; then
                AC_DEFINE_UNQUOTED([HAVE_NLIF_CATCH],[1],[Found iface resolution in nfnetlink and libnetfilter_queue])
            else
                AC_ERROR("Support of interface resolution in nfnetlink but not in netfilter_queue")
            fi
        fi
        AC_DEFINE_UNQUOTED([USE_NFQUEUE],[1],[Will use netlink queue support instead of libipq])
    else
        AC_CHECK_HEADERS([libipq/libipq.h libipq.h])
        # if we don't have we can't build nufw
        AC_CHECK_LIB([ipq], [ipq_message_type], have_ipq="yes", build_nufw="")

        if test "$have_ipq" = "yes"; then
        # check if we have a version of libipq supporting mark
                AC_ARG_WITH(user-mark, [AC_HELP_STRING(--with-user-mark,  Support user mark on NuFW firewall (useless if using nfqueue))], enable_user_mark="yes", enable_user_mark="")

                if test "$enable_user_mark" = "yes"; then
                        AC_CHECK_LIB([ipq], [ipq_set_vwmark],AC_DEFINE_UNQUOTED([HAVE_LIBIPQ_MARK],[1],[libipq has support for mark]),AC_MSG_RESULT([libipq has no support for mark]))
                fi
        fi
    fi
fi

if test "${use_nfconntrack}" = "yes"; then
	AC_CHECK_LIB([netfilter_conntrack], [nfct_dump_conntrack_table], have_conntrack="yes", have_conntrack="",[-ldl -lnfnetlink])
else
	have_conntrack=""
fi

if test "${have_conntrack}" = "yes"; then
        AC_DEFINE_UNQUOTED([HAVE_LIBCONNTRACK],[1],[libconntrack has been found])
	AC_CHECK_LIB([netfilter_conntrack], [nfct_callback_register], have_new_conntrack_api="yes", have_new_conntrack_api="", [-ldl -lnfnetlink])
	if test "${have_conntrack_fixedtimeout}" = "yes"; then
        	AC_DEFINE_UNQUOTED([HAVE_LIBCONNTRACK_FIXEDTIMEOUT],[1],[libconntrack with fixed timeout extension has been choosen])
	fi
        if test "${have_new_conntrack_api}" = "yes"; then
                AC_DEFINE_UNQUOTED([HAVE_NEW_NFCT_API],[1],[libconntrack new API has been found])
        fi
fi

if test "${build_pam_nufw}" = "yes"; then
    #AC_CHECK_LIB([pam], [pam_sm_authenticate],AC_DEFINE([HAVE_LIBRARY_PAM],[1],[Pam lib flag]), check_pam=no)
    AC_CHECK_LIB([pam],[pam_start],AC_DEFINE([HAVE_LIBRARY_PAM],[1],[pam lib flag]), check_pam=no)
fi

AM_CONDITIONAL(BUILD_NUFW, test x${build_nufw} = xyes)
AM_CONDITIONAL(BUILD_NUAUTH, test x${build_nuauth} = xyes)
AM_CONDITIONAL(BUILD_NUTCPC, test x${build_nutcpc} = xyes)
AM_CONDITIONAL(BUILD_LIBNUCLIENT, test x${build_libnuclient} = xyes)
AM_CONDITIONAL(BUILD_PAM_NUFW, test x${build_pam_nufw} = xyes)
AM_CONDITIONAL(BUILD_NUAUTH_COMMAND, test x${build_nuauth_command} = xyes)

AM_CONDITIONAL(HAVE_IPQ,test x$have_ipq = xyes && test x$have_conntrack = x )
AM_CONDITIONAL(USE_USER_MARK, test x$enable_user_mark = xyes)
AM_CONDITIONAL(HAVE_NFQUEUE_ONLY, test x$have_nfqueue = xyes && test x$have_conntrack = x  )
AM_CONDITIONAL(HAVE_NFQUEUE_CONNTRACK,test x$have_conntrack = xyes && test x$have_nfqueue = xyes )
AM_CONDITIONAL(HAVE_CONNTRACK_ONLY, test x$have_nfqueue = x && test x$have_conntrack = xyes  )

if test "x$GCC" = "xyes"; then

	dnl get gcc version
	AC_MSG_CHECKING([gcc version])
		gccver=$($CC -dumpversion)
		gccvermajor=$(echo $gccver | cut -d . -f1)
		gccverminor=$(echo $gccver | cut -d . -f2)
		gccvernum=$(expr $gccvermajor "*" 100 + $gccverminor)
	AC_MSG_RESULT($gccver)

    CFLAGS="$CFLAGS -ansi -Wall"

	if test "$gccvernum" -ge "400"; then
		dnl gcc 4.0 or later
        CFLAGS="$CFLAGS -Wextra"
	else
        CFLAGS="$CFLAGS -W"
	fi
    CFLAGS="$CFLAGS -Wno-unused-parameter"
fi

if test "${debug}" = "yes"; then
	AC_DEFINE_UNQUOTED([DEBUG_ENABLE],[1],[Will compile development debug message])
	CFLAGS="$CFLAGS -O0 -g"
else
	CFLAGS="$CFLAGS -O2"
fi

AC_CONFIG_FILES([Makefile
        doc/Makefile
        src/Makefile
        src/nuauth/Makefile
        src/nuauth/modules/Makefile
        src/nuauth/modules/ldap/Makefile
        src/nuauth/modules/plaintext/Makefile
        src/nuauth/modules/mark_group/Makefile
        src/nuauth/modules/mark_field/Makefile
        src/nuauth/modules/mark_flag/Makefile
        src/nuauth/modules/system/Makefile
        src/nuauth/modules/log_pgsql/Makefile
        src/nuauth/modules/log_mysql/Makefile
        src/nuauth/modules/log_nuprelude/Makefile
        src/nuauth/modules/log_syslog/Makefile
        src/nuauth/modules/log_script/Makefile
        src/nuauth/modules/xml_defs/Makefile
        src/nuauth/modules/x509_std/Makefile
        src/nuauth/modules/mark_uid/Makefile
        src/nuauth/modules/session_expire/Makefile
        src/nuauth/modules/ipauth_guest/Makefile
        src/clients/Makefile
        src/clients/lib/Makefile
        src/clients/nutcpc/Makefile
        src/clients/pam_nufw/Makefile
        src/nufw/Makefile
	scripts/Makefile
	scripts/nuauth_command/Makefile
	scripts/nuauth_command/scripts/Makefile
	tests/Makefile
])

# Display errors if any library is missing
if test \
       x${check_sasl} = xno \
    -o x${check_pthread} = xno \
    -o x${check_glib} = xno \
    -o x${check_mysql} = xno \
    -o x${check_pgsql} = xno \
    -o x${check_prelude} = xno \
    -o x${check_ldap} = xno \
    -o x${check_gcrypt} = xno \
    -o x${check_gnutls} = xno \
    -o x${check_pam} = xno \
; then
    AC_MSG_RESULT([])
    if test x${check_pthread} = xno; then
        AC_MSG_RESULT([ERROR: pthread library needed])
    fi
    if test x${check_sasl} = xno; then
        AC_MSG_RESULT([ERROR: sasl library needed for authentication])
    fi
    if test x${check_gcrypt} = xno; then
        AC_MSG_RESULT([ERROR: gcrypt library needed for encryption])
    fi
    if test x${check_pam} = xno; then
        AC_MSG_RESULT([ERROR: PAM library needed for system authentication])
    fi
    if test x${check_gnutls} = xno; then
        AC_MSG_RESULT([ERROR: gnutls library needed for encryption])
    fi
    if test x${check_ldap} = xno; then
        AC_MSG_RESULT([ERROR: ldap library needed for authentication])
    fi
    if test x${check_glib} = xno; then
        AC_MSG_RESULT([ERROR: glib is required in order to compile nuauth])
    fi
    if test x${check_mysql} = xno; then
        AC_MSG_RESULT([ERROR: mysqlclient library needed if selected])
    fi
    if test x${check_prelude} = xno; then
        AC_MSG_RESULT([ERROR: libprelude library needed if Prelude logging selected])
    fi
    if test x${check_pgsql} = xno; then
        AC_MSG_ERROR([libpq library needed if PostgreSQL support selected])
    fi
    exit 1
fi

AM_INIT_AUTOMAKE(1.9)

AC_OUTPUT
AC_MSG_RESULT([

Configuration complete
])

if test "$debug"; then
	AC_MSG_RESULT([* Compiling with developement DEBUG support])
fi

if test "${build_nuauth}" = "yes"; then
		AC_MSG_RESULT([* Compiling NuAuth])
        if test "$enable_system_auth" = "yes"; then
        	AC_MSG_RESULT([  - NuAuth: compile auth module system])
        fi

        if test "${ldap}" = "yes"; then
        	AC_MSG_RESULT([  - NuAuth: compile module ldap])
        fi

        if test "${enable_prelude_log}" = "yes"; then
        	AC_MSG_RESULT([  - NuAuth: compile log module prelude])
        fi

        if test "${enable_mysql_log}" = "yes"; then
        	AC_MSG_RESULT([  - NuAuth: compile log module mysql])
        fi

        if test "${enable_pgsql_log}" = "yes"; then
        	AC_MSG_RESULT([  - NuAuth: compile log module pgsql])
        fi

        if test "${enable_syslog_log}" = "yes"; then
        	AC_MSG_RESULT([  - NuAuth: compile syslog log module])
        fi

        if test "${enable_plaintext_auth}" = "yes"; then
        	AC_MSG_RESULT([  - NuAuth: compile plaintext auth module])
        fi

        if test "${enable_mark_group}" = "yes"; then
        	AC_MSG_RESULT([  - NuAuth: compile mark group module])
        fi

        if test "${enable_mark_field}" = "yes"; then
        	AC_MSG_RESULT([  - NuAuth: compile mark field module])
        fi

        if test "${enable_mark_flag}" = "yes"; then
        	AC_MSG_RESULT([  - NuAuth: compile mark flag module])
        fi
fi

if test "${build_nufw}" = "yes"; then
        AC_MSG_RESULT([* Compiling NuFW])
        if test "${have_conntrack}" = "yes"; then
        	AC_MSG_RESULT([  - NuFW: libnetfilter_conntrack support])
        fi
        if test "${have_nfqueue}" = "yes"; then
        	AC_MSG_RESULT([  - NuFW: libnetfilter_queue support])
        else
                if test "${have_ipq}" = "yes"; then
                        AC_MSG_RESULT([  - NuFW: libipq support])
        	        if test "$enable_user_mark" = "yes"; then
                                AC_MSG_RESULT([  - NuFW: User mark support])
	                fi
                fi
        fi
else
    if test "${use_nfconntrack}" = "yes"; then
        AC_MSG_RESULT([!!! WARNING !!! NuFW daemon WON'T be compiled: libnetfilter_queue not present])
    else
        AC_MSG_RESULT([!!! WARNING !!! NuFW daemon WON'T be compiled: libipq not present])
    fi
fi

if test "${build_libnuclient}" = "yes"; then
	AC_MSG_RESULT([* Compiling libnuclient])
fi

if test "${build_nutcpc}" = "yes"; then
	AC_MSG_RESULT([* Compiling nutcpc])
fi

if test "${build_pam_nufw}" = "yes"; then
	AC_MSG_RESULT([* Compiling pam_nufw])
fi

AC_MSG_RESULT([
Now type 'make' and then 'sudo make install'])

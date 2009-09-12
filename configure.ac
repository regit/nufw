#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(NuFW, 2.4.0-beta1, nufw-devel@nongnu.org)
AM_CONFIG_HEADER(src/include/config.h)
AC_CONFIG_SRCDIR([src/nufw/main.c])

# Checks for programs.
AC_PROG_CC

# check for a ISO C99 compiler
AC_DEFUN([AC_CPP_FUNC], [AC_REQUIRE([AC_PROG_CC_STDC])dnl
AC_CACHE_CHECK([for an ANSI C99-conforming __func__], ac_cv_cpp_func,
[AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],
[[char *foo = __func__;]])],
  [ac_cv_cpp_func=yes],
  [AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],
[[char *foo = __FUNCTION__;]])],
  [ac_cv_cpp_func=__FUNCTION__],
  [ac_cv_cpp_func=no])])])

if test $ac_cv_cpp_func = yes; then
   AC_DEFINE(__PRELUDE_FUNC__, __func__, [Define to __FUNCTION__ or "" if '__func__' does not conform to ANSI C.])
elif test $ac_cv_cpp_func = __FUNCTION__; then
   AC_DEFINE(__PRELUDE_FUNC__, __FUNCTION__, [Define to __FUNCTION__ or "" if '__func__' does not conform to ANSI C.])
elif test $ac_cv_cpp_func = no; then
   AC_DEFINE(__PRELUDE_FUNC__, "", [Define to __FUNCTION__ or "" if '__func__' does not conform to ANSI C.])
fi
])

AC_CPP_FUNC

AM_PROG_LEX
# macro AM_PROG_LEX is really stupid, so we insist on flex
AC_CHECK_PROG(FLEX, flex, "$LEX", false)
if test "$FLEX" = "false"; then
  AC_MSG_ERROR([This package requires flex to build])
fi
AC_PROG_YACC
# the macro is stupid and set $YACC to "yacc" if nothing was found ..
AC_CHECK_PROG(YACC, yacc, "$YACC", false)
if test "$YACC" = "yacc"; then
  AC_MSG_ERROR([This package requires bison to build])
fi
AM_PROG_LIBTOOL
AC_PROG_INSTALL


# Checks for endianess
AC_C_BIGENDIAN()

case $host in
*-*-linux*)
	AC_DEFINE([LINUX],[1],[Target is Linux])
	CFLAGS="$CFLAGS -D_POSIX_C_SOURCE=199506L" ;;
*-*-darwin*) AC_DEFINE([FREEBSD],[1],[Target is darwin (freebsd like)]) ;;
*-*-freebsd*) AC_DEFINE([FREEBSD],[1],[Target is freebsd]) ;;
*) AC_MSG_ERROR([Linux, FreeBSD, Darwin only, dude!]);;
esac

# Global definitions
# _ISOC99_SOURCE	Use ISO C99 standard, needed by snprintf for example
# _GNU_SOURCE		Use GNU extensions like getline() in stdio.h
# _SVID_SOURCE		Needed to get 'strdup' from <string.h>
# _BSD_SOURCE		Use 4.3BSD

CFLAGS="$CFLAGS -D_ISOC99_SOURCE -D_GNU_SOURCE -D_BSD_SOURCE -D_SVID_SOURCE"

# check to see if struct dirent has the d_type member
AC_CHECK_MEMBER([struct dirent.d_type],
        [AC_DEFINE([HAVE_STRUCT_DIRENT_D_TYPE],
        [1],
        [Define if struct dirent has member d_type])],
        ,
        [#include <dirent.h>])

# Checks for libraries.

AC_CHECK_LIB([pthread], [pthread_mutex_init], check_pthread="yes", check_pthread="no")

AC_CHECK_TOOL(DOCBOOK2MAN, docbook2man, true)
AC_CHECK_TOOL(DOCBOOK2PDF, docbook2pdf, true)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h errno.h fcntl.h getopt.h limits.h netdb.h netinet/in.h netinet/tcp.h pthread.h stdarg.h stdlib.h string.h sys/select.h sys/socket.h unistd.h inexistent.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_STAT
AC_CHECK_FUNCS([getopt_long gethostbyname memset setsockopt socket strcasecmp strspn])

#AC_CHECK_LIB([gcrypt], [gcry_md_open],AC_DEFINE([HAVE_LIBRARY_GCRYPT],[1],[Gcrypt lib flag]), check_gcrypt=no,[-L/usr/local/lib])
#AC_CHECK_LIB([gnutls], [gnutls_init],AC_DEFINE([HAVE_LIBRARY_GNUTLS],[1],[Gnutls lib flag]), check_gnutls=no)
#AM_CHECK_PATH([libgcrypt], [gcry_md_open],AC_DEFINE([HAVE_LIBRARY_GCRYPT],[1],[Gcrypt lib flag]), check_gcrypt=no,[-L/usr/local/lib])
#AM_CHECK_PATH(libgnutls], [gnutls_init],AC_DEFINE([HAVE_LIBRARY_GNUTLS],[1],[Gnutls lib flag]), check_gnutls=no)

PKG_PROG_PKG_CONFIG

dnl
dnl <SSL>
dnl

dnl We can force the use of OpenSSL
AC_ARG_WITH(openssl,   [AC_HELP_STRING(--with-openssl, Build with openssl support *EXPERIMENTAL*.)],build_openssl=$enableval, build_openssl="no" )

if test "${build_openssl}" != "no"; then
   PKG_CHECK_MODULES(OPENSSL, openssl)
   AC_DEFINE_UNQUOTED([HAVE_OPENSSL],[1],[Will use openssl support instead of gnutls])
fi

if test "x${build_openssl}" = "xno"; then
   NEED_LIBGCRYPT_VERSION=1.2.0
   AM_PATH_LIBGCRYPT("$NEED_LIBGCRYPT_VERSION")
   if test "x$LIBGCRYPT_LIBS" = "x"; then
     AC_MSG_ERROR([libgcrypt is needed.
                     See ftp://ftp.gnupg.org/gcrypt/ .])
   else
     CFLAGS="$CFLAGS $LIBGCRYPT_CFLAGS"
     LDFLAGS="$LDFLAGS $LIBGCRYPT_LIBS"
   fi

   NEED_LIBGNUTLS_VERSION=1.0.16
   PKG_CHECK_MODULES(GNUTLS, gnutls >= $NEED_LIBGNUTLS_VERSION,,exit)
   AC_DEFINE_UNQUOTED([HAVE_GNUTLS],[1],[Will use gnutls support instead of openssl])
   AC_CHECK_LIB(gnutls, gnutls_priority_set, AC_DEFINE_UNQUOTED(HAVE_GNUTLS_STRING_PRIORITY, , Define whether GnuTLS provide priority parsing),)
fi
dnl
dnl </SSL>
dnl

#Configure database support, depending on user input
AC_ARG_WITH(prelude-log,
        [AC_HELP_STRING(--with-prelude-log,
        Support user activity logging in Prelude)],
        enable_prelude_log=$withval,
        enable_prelude_log="")

AC_ARG_WITH(mysql-log, [AC_HELP_STRING(--with-mysql-log,  Support user activity logging in Mysql database)], enable_mysql_log=$withval, enable_mysql_log="")
AC_ARG_WITH(mysql-auth, [AC_HELP_STRING(--with-mysql-auth,  Support user authentication in Mysql database)], enable_mysql_auth=$withval, enable_mysql_auth="")
AC_ARG_WITH(pgsql-log, [AC_HELP_STRING(--with-pgsql-log,  Support user activity logging in PostgreSQL database)], enable_pgsql_log=$withval, enable_pgsql_log="")
AC_ARG_WITH(syslog-log, [AC_HELP_STRING(--without-syslog-log,  Disable user activity logging in syslog)], enable_syslog_log=$withval, enable_syslog_log="yes")
AC_ARG_WITH(ulogd2-log, [AC_HELP_STRING(--without-ulogd2-log,  Disable user activity logging in ulogd2)], enable_ulogd2_log=$withval, enable_ulogd2_log="yes")

AC_ARG_WITH(plaintext-auth, [AC_HELP_STRING(--without-plaintext-auth,  Disable authentication with plaintext file)], enable_plaintext_auth=$withval, enable_plaintext_auth="yes")
AC_ARG_WITH(mark-group, [AC_HELP_STRING(--without-mark-group,  Disable mark packet by group)], enable_mark_group=$withval, enable_mark_group="yes")
AC_ARG_WITH(mark-field, [AC_HELP_STRING(--without-mark-field,  Disable mark packet by packet field)], enable_mark_field=$withval, enable_mark_field="yes")
AC_ARG_WITH(mark-flag, [AC_HELP_STRING(--without-mark-flag,  Disable mark packet following acl indication)], enable_mark_flag=$withval, enable_mark_flag="yes")
AC_ARG_WITH(system-auth, [AC_HELP_STRING(--without-system-auth,  Disable PAM+NSS authentication)], enable_system_auth=$withval, enable_system_auth="yes")

AC_ARG_WITH(ldap,   [AC_HELP_STRING(--with-ldap,  Support LDAP directory for acl lookup)],ldap=$withval, ldap="")


AC_ARG_WITH(nfqueue,   [AC_HELP_STRING(--without-nfqueue, Compile for QUEUE instead of NFQUEUE)],use_nfqueue=$withval, use_nfqueue="yes")

AC_ARG_WITH(utf8,   [AC_HELP_STRING(--with-utf8, Use UTF8 exchange between client and server)], AC_DEFINE_UNQUOTED([USE_UTF8],[1],[Will use UTF8 exchange]))
AC_ARG_WITH(fixedtimeout,   [AC_HELP_STRING(--with-fixedtimeout, Assume libconntrack has fixed timeout extension )],have_conntrack_fixedtimeout=$withval )


AC_ARG_ENABLE(nufw,   [AC_HELP_STRING(--disable-nufw, Don't build nufw (default is to build))],build_nufw=$enableval, build_nufw="yes")
AC_ARG_ENABLE(nuauth, [AC_HELP_STRING(--disable-nuauth, Don't build nuauth (default is to build))],build_nuauth=$enableval, build_nuauth="yes")
AC_ARG_ENABLE(libnuclient,   [AC_HELP_STRING(--disable-libnuclient, Don't build libnuclient (default is to build))],build_libnuclient=$enableval, build_libnuclient="yes")
AC_ARG_ENABLE(nutcpc,   [AC_HELP_STRING(--disable-nutcpc, Don't build nutcpc (default is to build))],build_nutcpc=$enableval, build_nutcpc="yes" )
AC_ARG_ENABLE(pam-nufw,   [AC_HELP_STRING(--enable-pam-nufw, Build pam_nufw (default is not to build))],build_pam_nufw=$enableval, build_pam_nufw="no" )
AC_ARG_ENABLE(nuauth-command,   [AC_HELP_STRING(--disable-nuauth-command, Don't build nuauth_command (default is to build))],build_nuauth_command=$enableval, build_nuauth_command="yes" )
AC_ARG_ENABLE(emc,   [AC_HELP_STRING(--disable-emc, Don't build emc (default is to build))],build_emc=$enableval, build_emc="yes")

define([EXPAND_VARIABLE],
[$2=[$]$1
while true; do
  case "[$]$2" in
    *\[$]* ) eval "$2=[$]$2" ;;
    *) break ;;
  esac
done])dnl EXPAND_VARIABLE



if test "${build_nuauth_command}" = "yes"; then
    AC_CHECK_TOOL(PYTHON, python)
    AC_DEFINE_UNQUOTED([BUILD_NUAUTH_COMMAND],[1],[Build nuauth_command])

    EXPAND_VARIABLE(localstatedir,e_localstatedir)
    AC_SUBST(e_localstatedir)
fi

AC_ARG_ENABLE(debug,   [AC_HELP_STRING(--enable-debug, Add development debug messages (default no))],debug=$enableval, debug="")
AC_ARG_WITH(perf-display,
    [AC_HELP_STRING(--without-perf-display, Disable performance display)],
    use_perf_display=$withval, use_perf_display="yes")

if test "${use_perf_display}" = "yes"; then
	AC_DEFINE_UNQUOTED([PERF_DISPLAY_ENABLE],[1],[Performance display])
fi

if test \
	   "${build_nuauth}" = "yes"  \
	-o "${build_libnuclient}" = "yes" \
	-o "${build_nutcpc}" = "yes" \
	-o "${build_pam_nufw}" = "yes" \
; then
	AC_CHECK_LIB([sasl2],[sasl_server_init],AC_DEFINE([HAVE_LIBRARY_SASL2],[1],[SASL lib flag]), check_sasl=no)
fi

if test "${build_nuauth}" = "yes"; then
	AC_CHECK_LIB([sasl2],[sasl_server_init],AC_DEFINE([HAVE_LIBRARY_SASL2],[1],[SASL lib flag]), check_sasl=no)
        # glib stuff
        AM_PATH_GLIB_2_0(2.4.0, , check_glib=no,[gthread gmodule])
        if test "$enable_system_auth" = "yes"; then
                AC_CHECK_LIB([pam],[pam_start],AC_DEFINE([HAVE_LIBRARY_PAM],[1],[pam lib flag]), check_pam=no)
        fi

        if test "${ldap}" = "yes"; then
                 AC_CHECK_LIB([ldap],[ldap_simple_bind_s],AC_DEFINE([HAVE_LIBRARY_LDAP],[1],[ldap lib flag]), check_ldap=no)
        fi

        if test "$enable_mysql_log" = "yes" \
		-o "$enable_mysql_auth" = "yes" ; then
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
AM_CONDITIONAL(USE_MYSQL_AUTH, test x$enable_mysql_auth = xyes)
AM_CONDITIONAL(HAVE_MYSQL_CONFIG, test x$have_mysql_config = xyes)

AM_CONDITIONAL(USE_PGSQL_LOG, test x$enable_pgsql_log = xyes)
AM_CONDITIONAL(USE_PLAINTEXT_AUTH, test x$enable_plaintext_auth = xyes)
AM_CONDITIONAL(USE_MARK_GROUP, test x$enable_mark_group = xyes)
AM_CONDITIONAL(USE_MARK_FIELD, test x$enable_mark_field = xyes)
AM_CONDITIONAL(USE_MARK_FLAG, test x$enable_mark_flag = xyes)
AM_CONDITIONAL(USE_SYSLOG_LOG, test x$enable_syslog_log = xyes)
AM_CONDITIONAL(USE_ULOGD2_LOG, test x$enable_ulogd2_log = xyes)

if test "${build_libnuclient}" = "yes"; then
	AC_CHECK_LIB([sasl2],[sasl_server_init],AC_DEFINE([HAVE_LIBRARY_SASL2],[1],[SASL lib flag]), check_sasl=no)
fi

if test "${build_nufw}" = "yes"; then
    if test "${check_pthread}" = "no"; then
        AC_MSG_ERROR([No pthread library, nufw daemon WON'T be able to compile]);	
    fi
    if test "${use_nfqueue}" = "yes"; then
        # if we don't have we can't build nufw
        AC_CHECK_LIB([nfnetlink], [nfnl_open], have_nfqueue="yes", build_nufw="")
        AC_CHECK_LIB([netfilter_queue], [nfq_open], have_nfqueue="yes",[AC_MSG_ERROR([libnetfilter_queue not present])],[-lnfnetlink])
        AC_CHECK_LIB([netfilter_queue], [nfq_set_queue_maxlen],AC_DEFINE_UNQUOTED([HAVE_NFQ_SET_QUEUE_MAXLEN],[1],[Found queue max length support in netfilter_queue]) ,,[-lnfnetlink])
        AC_CHECK_LIB([netfilter_queue], [nfq_set_verdict_mark_exptime],AC_DEFINE_UNQUOTED([HAVE_NFQ_MARK_EXPTIME],[1],[Found verdict with mark and exptime support in netfilter_queue]) ,,[-lnfnetlink])
	AC_CHECK_LIB([nfnetlink], [nlif_catch],
			AC_CHECK_LIB([netfilter_queue], [nfq_get_indev_name],
				AC_DEFINE_UNQUOTED([HAVE_NFQ_INDEV_NAME],
					[1],
					[Found iface resolution in nfnetlink and libnetfilter_queue]),
				AC_MSG_WARN("Support of interface resolution in nfnetlink but not in netfilter_queue"),
				[-lnfnetlink])
		    )
        AC_DEFINE_UNQUOTED([USE_NFQUEUE],[1],[Will use netlink queue])
    fi
fi

if test "${build_pam_nufw}" = "yes"; then
    #AC_CHECK_LIB([pam], [pam_sm_authenticate],AC_DEFINE([HAVE_LIBRARY_PAM],[1],[Pam lib flag]), check_pam=no)
    AC_CHECK_LIB([pam],[pam_start],AC_DEFINE([HAVE_LIBRARY_PAM],[1],[pam lib flag]), check_pam=no)
fi

if test "${build_emc}" = "yes"; then
	AC_CHECK_HEADERS([ev.h])
	AC_CHECK_LIB([ev], [ev_loop], have_libev="yes",AC_MSG_ERROR([libev is required to build emc]))
fi

if test "${build_nuauth}" = "yes"; then
	AC_CHECK_HEADERS([ev.h])
	AC_CHECK_LIB([ev], [ev_loop],have_libev="yes", AC_MSG_ERROR([libev is required to build nuauth]))
fi

if test "${have_libev}" = "yes"; then
	AC_DEFINE_UNQUOTED([HAVE_LIBEV],[1],[libev flag])
fi

AM_CONDITIONAL(BUILD_EMC, test x${build_emc} = xyes)
AM_CONDITIONAL(BUILD_NUFW, test x${build_nufw} = xyes)
AM_CONDITIONAL(BUILD_NUAUTH, test x${build_nuauth} = xyes)
AM_CONDITIONAL(BUILD_NUTCPC, test x${build_nutcpc} = xyes)
AM_CONDITIONAL(BUILD_LIBNUCLIENT, test x${build_libnuclient} = xyes)
AM_CONDITIONAL(BUILD_PAM_NUFW, test x${build_pam_nufw} = xyes)
AM_CONDITIONAL(BUILD_NUAUTH_COMMAND, test x${build_nuauth_command} = xyes)

AM_CONDITIONAL(USE_USER_MARK, test x$enable_user_mark = xyes)
AM_CONDITIONAL(HAVE_NFQUEUE_ONLY, test x$have_nfqueue = xyes && test x$have_conntrack = x  )

AM_CONDITIONAL(USE_OPENSSL, test x$build_openssl != xno)
AM_CONDITIONAL(USE_GNUTLS, test x$build_openssl = xno)

if test "x$GCC" = "xyes"; then

	dnl get gcc version
	AC_MSG_CHECKING([gcc version])
		gccver=$($CC -dumpversion)
		gccvermajor=$(echo $gccver | cut -d . -f1)
		gccverminor=$(echo $gccver | cut -d . -f2)
		gccvernum=$(expr $gccvermajor "*" 100 + $gccverminor)
	AC_MSG_RESULT($gccver)


	if test "$gccvernum" -ge "400"; then
		dnl gcc 4.0 or later
		CFLAGS="$CFLAGS -Wextra"
	else
		CFLAGS="$CFLAGS -W"
	fi
fi

CFLAGS="$CFLAGS -Wall"
CFLAGS="$CFLAGS -Wno-unused-parameter"

if test "${debug}" = "yes"; then
	AC_DEFINE_UNQUOTED([DEBUG_ENABLE],[1],[Will compile development debug message])
	CFLAGS="$CFLAGS -O0 -g"
else
	CFLAGS="$CFLAGS -O2"
fi

AC_CONFIG_FILES([Makefile
        doc/Makefile
        conf/Makefile
        python/Makefile
        selinux/Makefile
        src/Makefile
        src/include/Makefile
        src/libs/Makefile
        src/libs/nubase/Makefile
        src/libs/nuconfparser/Makefile
        src/libs/nussl/Makefile
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
        src/nuauth/modules/log_ulogd2/Makefile
	src/nuauth/modules/multi_mode/Makefile
        src/nuauth/modules/xml_defs/Makefile
        src/nuauth/modules/x509_ocsp/Makefile
        src/nuauth/modules/x509_std/Makefile
        src/nuauth/modules/mark_uid/Makefile
        src/nuauth/modules/session_expire/Makefile
        src/nuauth/modules/session_authtype/Makefile
        src/nuauth/modules/ipauth_guest/Makefile
        src/nuauth/modules/auth_mysql/Makefile
        src/nuauth/modules/postauth_localuser/Makefile
        src/clients/Makefile
        src/clients/lib/Makefile
        src/clients/lib/tests/Makefile
        src/clients/lib/plugins/Makefile
        src/clients/lib/plugins/luser/Makefile
        src/clients/lib/plugins/multi/Makefile
        src/clients/nutcpc/Makefile
        src/clients/pam_nufw/Makefile
        src/nufw/Makefile
        src/emc/Makefile
        scripts/Makefile
        scripts/nuauth_command/Makefile
        scripts/nuauth_command/scripts/Makefile
        scripts/nuauth_command/scripts/nuauth_command
        scripts/nuauth_command/nuauth_command/Makefile
        scripts/auth_mysql/Makefile
        tests/Makefile
        tests/inl_tests/Makefile
        tests/pki/Makefile
])

# Display errors if any library is missing
if test \
    x${check_glib} = xno \
    -o x${check_mysql} = xno \
    -o x${check_pgsql} = xno \
    -o x${check_prelude} = xno \
    -o x${check_ldap} = xno \
    -o x${check_gcrypt} = xno \
    -o x${check_gnutls} = xno \
    -o x${check_pam} = xno \
; then
    AC_MSG_RESULT([])
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

if test \
	   "${build_nuauth}" = "yes"  \
	-o "${build_libnuclient}" = "yes" \
	-o "${build_nutcpc}" = "yes" \
	-o "${build_pam_nufw}" = "yes" \
; then
    if test x${check_sasl} = xno; then
        AC_MSG_RESULT([ERROR: sasl library needed for authentication])
    	exit 1
    fi
fi

AM_INIT_AUTOMAKE(1.8)

AC_OUTPUT
AC_MSG_RESULT([

Configuration complete
])

if test "$debug"; then
	AC_MSG_RESULT([* Compiling with developement DEBUG support])
fi

if test "${build_openssl}" != "no"; then
	AC_MSG_RESULT([* Compiling with OpenSSL])
else
	AC_MSG_RESULT([* Compiling with GnuTLS])
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

        if test "${enable_mysql_auth}" = "yes"; then
        	AC_MSG_RESULT([  - NuAuth: compile authentication module mysql])
        fi

        if test "${enable_pgsql_log}" = "yes"; then
        	AC_MSG_RESULT([  - NuAuth: compile log module pgsql])
        fi

        if test "${enable_syslog_log}" = "yes"; then
        	AC_MSG_RESULT([  - NuAuth: compile syslog log module])
        fi

        if test "${enable_ulogd2_log}" = "yes"; then
        	AC_MSG_RESULT([  - NuAuth: compile ulogd2 log module])
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
        if test "${have_nfqueue}" = "yes"; then
        	AC_MSG_RESULT([  - NuFW: libnetfilter_queue support])
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

if test "${build_emc}" = "yes"; then
	AC_MSG_RESULT([* Compiling emc])
fi

AC_MSG_RESULT([
Now type 'make' and then 'sudo make install'])


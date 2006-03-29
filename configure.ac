#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(NuFW, 1.1.4, nufw-devel@nongnu.org)
AM_CONFIG_HEADER(src/include/config.h)
AC_CONFIG_SRCDIR([src/nufw/main.c])

# Checks for programs.
AC_PROG_CC

AC_PROG_LIBTOOL
AC_PROG_INSTALL

# Checks for endianess
AC_C_BIGENDIAN()

case $host in
*-*-linux*) AC_DEFINE([LINUX],[1],[Target is Linux]) ;;
*-*-freebsd*) AC_DEFINE([FREEBSD],[1],[Target is freebsd]) ;;
*) AC_MSG_ERROR([Linux or FreeBSD only, dude!]);;
esac


# Checks for libraries.

AC_CHECK_LIB([pthread], [pthread_mutex_init])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_STAT
AC_CHECK_FUNCS([gethostbyname memset socket strcasecmp strspn])

AC_CHECK_LIB([gcrypt], [gcry_md_open],AC_DEFINE([HAVE_LIBRARY_GCRYPT],[1],[Gcrypt lib flag]),AC_MSG_ERROR([gcrypt library needed for encryption]),[-L/usr/local/lib])
AC_CHECK_LIB([gnutls], [gnutls_init],AC_DEFINE([HAVE_LIBRARY_GNUTLS],[1],[Gnutls lib flag]),AC_MSG_ERROR([gnutls library needed for encryption]))
AC_CHECK_LIB([sasl2],[sasl_server_init],AC_DEFINE([HAVE_LIBRARY_SASL2],[1],[SASL lib flag]),AC_MSG_ERROR([sasl library needed for authentication]))

#Configure database support, depending on user input
AC_ARG_WITH(mysql-log, [AC_HELP_STRING(--with-mysql-log,  Support user activity logging in Mysql database)], enable_mysql_log="yes", enable_mysql_log="")
AC_ARG_WITH(pgsql-log, [AC_HELP_STRING(--with-pgsql-log,  Support user activity logging in PostgreSQL database)], enable_pgsql_log="yes", enable_pgsql_log="")

AC_ARG_WITH(system-auth, [AC_HELP_STRING(--with-system-auth,  Support PAM+NSS authentication)], enable_system_auth="yes", enable_system_auth="")

AC_ARG_WITH(ldap,   [AC_HELP_STRING(--with-ldap,  Support LDAP directory for users and acl lookup)],ldap="yes", ldap="")
AC_ARG_WITH(gdbm,   [AC_HELP_STRING(--with-gdbm, Support gdbm users lookup)],gdbm="yes", gdbm="")
AC_ARG_WITH(ident,   [AC_HELP_STRING(--with-ident,  Support ident users authentication)],ident="yes", ident="")


AC_ARG_WITH(nfqueue,   [AC_HELP_STRING(--with-nfqueue, Compile for NFQUEUE instead of QUEUE)],use_nfqueue="yes", use_nfqueue="")


AC_ARG_WITH(utf8,   [AC_HELP_STRING(--with-utf8, Use UTF8 exchange between client and server)], AC_DEFINE_UNQUOTED([USE_UTF8],[1],[Will use UTF8 exchange]))
AC_ARG_WITH(fixedtimeout,   [AC_HELP_STRING(--with-fixedtimeout, Assume libconntrack has fixed timeout extension )],have_conntrack_fixedtimeout="yes" )


AC_ARG_ENABLE(debug,   [AC_HELP_STRING(--enable-debug, Add development debug messages (default no))],debug=$enableval, debug="")
AC_ARG_ENABLE(nufw,   [AC_HELP_STRING(--disable-nufw, Don't build nufw (default is to build))],build_nufw=$enableval, build_nufw="yes")
AC_ARG_ENABLE(nuauth, [AC_HELP_STRING(--disable-nuauth, Don't build nuauth (default is to build))],build_nuauth=$enableval, build_nuauth="yes")
AC_ARG_ENABLE(libnuclient,   [AC_HELP_STRING(--disable-libnuclient, Don't build libnuclient (default is to build))],build_libnuclient=$enableval, build_libnuclient="yes")
AC_ARG_ENABLE(nutcpc,   [AC_HELP_STRING(--disable-nutcpc, Don't build nutcpc (default is to build))],build_nutcpc=$enableval, build_nutcpc="yes" )
AC_ARG_ENABLE(nutrackd,   [AC_HELP_STRING(--disable-nutrackd, Don't build nutrackd (default is to build))],build_nutrackd=$enableval, build_nutrackd="yes")

AC_ARG_WITH(perf-display, 
    [AC_HELP_STRING(--with-perf-display, Enable benchmark of user authentification)],
    AC_DEFINE_UNQUOTED([PERF_DISPLAY_ENABLE],[1],[Benchmark of user authentification]))

AC_ARG_WITH(gryzor-hacks, 
    [AC_HELP_STRING(--with-gryzor-hacks, Enable gryzor hacks (send icmp answer))],
    AC_DEFINE_UNQUOTED([GRYZOR_HACKS],[1],[Enable gryzor hacks (send icmp answer)]))

if test "${build_nuauth}" = "yes"; then
        # glib stuff
        AM_PATH_GLIB_2_0(2.4.0, , AC_MSG_ERROR([glib is required in order to compile nuauth]),[gthread gmodule])
        if test "$enable_system_auth" = "yes"; then
                AC_CHECK_LIB([pam],[pam_start],AC_DEFINE([HAVE_LIBRARY_PAM],[1],[pam lib flag]),AC_MSG_ERROR([PAM library needed for system authentication]))
        fi

        if test "${ldap}" = "yes"; then
                 AC_CHECK_LIB([ldap],[ldap_simple_bind_s],AC_DEFINE([HAVE_LIBRARY_LDAP],[1],[ldap lib flag]),AC_MSG_ERROR([ldap library needed for authentication]))
        fi

        if test "${gdbm}" = "yes"; then
                AC_CHECK_LIB([gdbm],[gdbm_fetch], AC_DEFINE([HAVE_LIBRARY_GDBM],[1],[ldap lib flag] ) ,AC_MSG_ERROR([dbm library needed for authentication]))
        fi

        if test "${ident}" = "yes"; then
                AC_CHECK_LIB([ident],[id_open], AC_DEFINE([HAVE_LIBRARY_IDENT],[1],[ident lib flag] )    ,AC_MSG_ERROR([ident library needed for ident user authentication]))
        fi

        if test "$enable_mysql_log" = "yes"; then
                AC_CHECK_LIB([mysqlclient],[mysql_real_connect],AC_DEFINE([HAVE_LIBRARY_MYSQLCLIENT],[1],[mysql lib flag] )  ,AC_MSG_ERROR([mysqlclient library needed if selected]))
                AC_CHECK_LIB([mysqlclient],[mysql_ssl_set],AC_DEFINE_UNQUOTED([HAVE_MYSQL_SSL],[1],[Will compile mysql log module with ssl support]),AC_MSG_NOTICE([mysqlclient has no ssl support]))
        fi
  
        if test "$enable_pgsql_log" = "yes"; then
                AC_CHECK_LIB([pq],[PQconnectdb],AC_DEFINE([HAVE_LIBRARY_PQ],[1],[pgsql lib flag] )   ,AC_MSG_ERROR([libpq library needed if PostgreSQL support selected]))
        fi
fi

AM_CONDITIONAL(USE_SYSTEM_AUTH, test x$enable_system_auth = xyes)
AM_CONDITIONAL(USE_LDAP, test x$ldap = xyes)
AM_CONDITIONAL(USE_GDBM, test x$gdbm = xyes)
AM_CONDITIONAL(USE_IDENT, test x$ident = xyes)
AM_CONDITIONAL(USE_MYSQL_LOG, test x$enable_mysql_log = xyes)
AM_CONDITIONAL(USE_PGSQL_LOG, test x$enable_pgsql_log = xyes)

AM_CONDITIONAL(HAVE_NFQUEUE,test x$have_nfqueue = xyes)
if test "${build_nufw}" = "yes"; then
if test "${use_nfqueue}" = "yes"; then
        # if we don't have we can't build nufw
	AC_CHECK_LIB([nfnetlink], [nfnl_open], have_nfqueue="yes", build_nufw="")
	AC_CHECK_LIB([netfilter_queue], [nfq_open], have_nfqueue="yes", have_nfqueue="",[-lnfnetlink])
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

AC_CHECK_LIB([netfilter_conntrack], [nfct_dump_conntrack_table], have_conntrack="yes", have_conntrack="",[-ldl -lnfnetlink])

if test "${have_conntrack}" = "yes"; then
        AC_DEFINE_UNQUOTED([HAVE_LIBCONNTRACK],[1],[libconntrack has been found])
	if test "${have_conntrack_fixedtimeout}" = "yes"; then
        	AC_DEFINE_UNQUOTED([HAVE_LIBCONNTRACK_FIXEDTIMEOUT],[1],[libconntrack with fixed timeout extension has been choosen])
	fi
else
        build_nutrackd=""
fi

AM_CONDITIONAL(BUILD_NUFW, test x${build_nufw} = xyes)
AM_CONDITIONAL(BUILD_NUAUTH, test x${build_nuauth} = xyes)
AM_CONDITIONAL(BUILD_NUTRACKD, test x${build_nutrackd} = xyes)
AM_CONDITIONAL(BUILD_NUTCPC, test x${build_nutcpc} = xyes)
AM_CONDITIONAL(BUILD_LIBNUCLIENT, test x${build_libnuclient} = xyes)

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
  		 src/nuauth/modules/dbm/Makefile
  		 src/nuauth/modules/plaintext/Makefile
  		 src/nuauth/modules/system/Makefile
  		 src/nuauth/modules/log_pgsql/Makefile
  		 src/nuauth/modules/log_mysql/Makefile
  		 src/nuauth/modules/log_syslog/Makefile
  		 src/nuauth/modules/log_script/Makefile
		 src/nuauth/modules/ipauth_ident/Makefile
		 src/nuauth/modules/xml_defs/Makefile
		 src/clients/Makefile
		 src/clients/lib/Makefile
		 src/clients/nutcpc/Makefile
		 src/nufw/Makefile
                 src/support/Makefile
                 src/support/dbm/Makefile
                 src/nutrackd/Makefile
		 ])

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

        if test "${gdbm}" = "yes"; then
        	AC_MSG_RESULT([  - NuAuth: compile module dbm])
        fi

        if test "${ident}" = "yes"; then
        	AC_MSG_RESULT([  - NuAuth: compile (fallback) module ident])
        fi

        if test "${enable_mysql_log}" = "yes"; then
        	AC_MSG_RESULT([  - NuAuth: compile log module mysql])
        fi

        if test "${enable_pgsql_log}" = "yes"; then
        	AC_MSG_RESULT([  - NuAuth: compile log module pgsql])
        fi
fi

if test "${build_nufw}" = "yes"; then
		AC_MSG_RESULT([* Compiling NuFW])
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
	AC_MSG_RESULT([!!! WARNING !!! NuFW daemon WON'T be compiled: libipq or libnetfilter_queue not present])
fi

if test "${build_nutrackd}" = "yes"; then
	AC_MSG_RESULT([* Compiling nutrackd])
fi
if test "${build_libnuclient}" = "yes"; then
	AC_MSG_RESULT([* Compiling libnuclient])
fi

if test "${build_nutpcc}" = "yes"; then
	AC_MSG_RESULT([* Compiling nutcpc])
fi

AC_MSG_RESULT([
Now type 'make' and then 'sudo make install'])

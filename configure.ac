#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(NuFW, 1.0.3, nufw-devel@nongnu.org)
AM_CONFIG_HEADER(src/include/config.h)
AC_CONFIG_SRCDIR([src/nufw/main.c])

# Checks for programs.
AC_PROG_CC

AC_PROG_LIBTOOL
AC_PROG_INSTALL

# Checks for libraries.


AC_CHECK_HEADERS([libipq/libipq.h libipq.h])
AC_CHECK_LIB([ipq], [ipq_message_type], have_ipq="yes", have_ipq="")

if test "$have_ipq" = "yes"; then
# check if we have a version of libipq supporting mark
AC_ARG_WITH(user-mark, [--with-user-mark  Support user mark on NuFW firewall], enable_user_mark="yes", enable_user_mark="")
if test "$enable_user_mark" = "yes"; then
        AC_CHECK_LIB([ipq], [ipq_set_vwmark],AC_DEFINE_UNQUOTED([HAVE_LIBIPQ_MARK],[1],[libipq has support for mark]),AC_MSG_RESULT([libipq has no support for mark]))
fi


fi

AM_CONDITIONAL(HAVE_LIBIPQ,test x$have_ipq = xyes)


#AC_CHECK_LIB([pthread], [pthread_mutex_init])

# glib stuff
AM_PATH_GLIB_2_0(2.0.0, , AC_MSG_ERROR([glib is required in order to compile nuauth]),[gthread gmodule])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_STAT
AC_CHECK_FUNCS([gethostbyname memset socket strcasecmp strspn])

AC_CHECK_LIB([gcrypt], [gcry_md_open],AC_DEFINE([HAVE_LIBRARY_GCRYPT],[1],[Gcrypt lib flag]),AC_MSG_ERROR([gcrypt library needed for encryption]))
AC_CHECK_LIB([gnutls], [gnutls_init],AC_DEFINE([HAVE_LIBRARY_GNUTLS],[1],[Gnutls lib flag]),AC_MSG_ERROR([gnutls library needed for encryption]))
AC_CHECK_LIB([sasl2],[sasl_server_init],AC_DEFINE([HAVE_LIBRARY_SASL2],[1],[SASLlib flag]),AC_MSG_ERROR([sasl library needed for authentication]))
        
AM_CONDITIONAL(USE_USER_MARK, test x$enable_user_mark = xyes)


#Configure database support, depending on user input
AC_ARG_WITH(mysql-log, [--with-mysql-log  Support user activity logging in Mysql database], enable_mysql_log="yes", enable_mysql_log="")
AC_ARG_WITH(pgsql-log, [--with-pgsql-log  Support user activity logging in PostgreSQL database], enable_pgsql_log="yes", enable_pgsql_log="")

AC_ARG_WITH(system-auth, [--with-system-auth  Support PAM+NSS authentication], enable_system_auth="yes", enable_system_auth="")

AC_ARG_WITH(ldap,   [--with-ldap  Support LDAP directory for users and acl lookup],ldap="yes", ldap="")
AC_ARG_WITH(gdbm,   [--with-gdbm  Support gdbm users lookup],gdbm="yes", gdbm="")
AC_ARG_WITH(ident,   [--with-ident  Support ident users authentication],ident="yes", ident="")

AC_ARG_WITH(debug,   [--with-debug Add development debug message],debug="yes", debug="")

if test "$enable_system_auth" = "yes"; then
  AC_CHECK_LIB([pam],[pam_start],,AC_MSG_ERROR([PAM library needed for system authentication]))
fi
AM_CONDITIONAL(USE_SYSTEM_AUTH, test x$enable_system_auth = xyes)

if test "${ldap}" = "yes"; then
  AC_CHECK_LIB([ldap],[ldap_simple_bind_s],,AC_MSG_ERROR([ldap library needed for authentication]))
fi
AM_CONDITIONAL(USE_LDAP, test x$ldap = xyes)

if test "${gdbm}" = "yes"; then
  AC_CHECK_LIB([gdbm],[gdbm_fetch],,AC_MSG_ERROR([dbm library needed for authentication]))
fi
AM_CONDITIONAL(USE_GDBM, test x$gdbm = xyes)

if test "${ident}" = "yes"; then
  AC_CHECK_LIB([ident],[id_open],,AC_MSG_ERROR([ident library needed for ident user authentication]))
fi
AM_CONDITIONAL(USE_IDENT, test x$ident = xyes)

if test "$enable_mysql_log" = "yes"; then
  AC_CHECK_LIB([mysqlclient],[mysql_real_connect],,AC_MSG_ERROR([mysqlclient library needed if selected]))
  AC_CHECK_LIB([mysqlclient],[mysql_ssl_set],AC_DEFINE_UNQUOTED([HAVE_MYSQL_SSL],[1],[Will compile mysql log module with ssl support]),AC_MSG_NOTICE([mysqlclient has no ssl support]))
fi
AM_CONDITIONAL(USE_MYSQL_LOG, test x$enable_mysql_log = xyes)
  
if test "$enable_pgsql_log" = "yes"; then
  AC_CHECK_LIB([pq],[PQconnectdb],,AC_MSG_ERROR([libpq library needed if PostgreSQL support selected]))
fi
AM_CONDITIONAL(USE_PGSQL_LOG, test x$enable_pgsql_log = xyes)

if test "${debug}" = "yes"; then
	AC_DEFINE_UNQUOTED([DEBUG_ENABLE],[1],[Will compile development debug message])
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
		 src/nuauth/modules/ipauth_ident/Makefile
		 src/clients/Makefile
		 src/clients/lib/Makefile
		 src/clients/nutcpc/Makefile
		 src/nufw/Makefile
                 src/support/Makefile
                 src/support/dbm/Makefile
		 ])

AM_INIT_AUTOMAKE(1.9)

AC_OUTPUT

if test "$debug"; then
	AC_MSG_NOTICE([Compiling with developement debug support])
fi

if test "$have_ipq" = ""; then
	AC_MSG_NOTICE([nufw daemon WON'T be compiled: libipq not present])
else
	if test "$enable_user_mark" = "yes"; then
		AC_MSG_NOTICE([nufw will be compiled with user mark support])
	fi
fi

if test "$enable_system_auth" = "yes"; then
	AC_MSG_NOTICE([Compiling module system auth])
fi

if test "${ldap}" = "yes"; then
	AC_MSG_NOTICE([Compiling module ldap])
fi

if test "${gdbm}" = "yes"; then
	AC_MSG_NOTICE([Compiling module dbm])
fi

if test "${ident}" = "yes"; then
	AC_MSG_NOTICE([Compiling fallback module ident])
fi

if test "${enable_mysql_log}" = "yes"; then
	AC_MSG_NOTICE([Compiling mysql log module])
fi

if test "${enable_pgsql_log}" = "yes"; then
	AC_MSG_NOTICE([Compiling pgsql log module])
fi





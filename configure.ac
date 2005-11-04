#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(NuFW, 1.1.0, nufw-devel@nongnu.org)
AM_CONFIG_HEADER(src/include/config.h)
AC_CONFIG_SRCDIR([src/nufw/main.c])

# Checks for programs.
AC_PROG_CC

AC_PROG_LIBTOOL
AC_PROG_INSTALL

# Checks for endianess
AC_C_BIGENDIAN()

# Checks for libraries.


#AC_CHECK_LIB([pthread], [pthread_mutex_init])

# glib stuff
AM_PATH_GLIB_2_0(2.4.0, , AC_MSG_ERROR([glib is required in order to compile nuauth]),[gthread gmodule])

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
AC_CHECK_LIB([sasl2],[sasl_server_init],AC_DEFINE([HAVE_LIBRARY_SASL2],[1],[SASL lib flag]),AC_MSG_ERROR([sasl library needed for authentication]))
        


#Configure database support, depending on user input
AC_ARG_WITH(mysql-log, [--with-mysql-log  Support user activity logging in Mysql database], enable_mysql_log="yes", enable_mysql_log="")
AC_ARG_WITH(pgsql-log, [--with-pgsql-log  Support user activity logging in PostgreSQL database], enable_pgsql_log="yes", enable_pgsql_log="")

AC_ARG_WITH(system-auth, [--with-system-auth  Support PAM+NSS authentication], enable_system_auth="yes", enable_system_auth="")

AC_ARG_WITH(ldap,   [--with-ldap  Support LDAP directory for users and acl lookup],ldap="yes", ldap="")
AC_ARG_WITH(gdbm,   [--with-gdbm  Support gdbm users lookup],gdbm="yes", gdbm="")
AC_ARG_WITH(ident,   [--with-ident  Support ident users authentication],ident="yes", ident="")

AC_ARG_WITH(debug,   [--with-debug Add development debug message],debug="yes", debug="")

AC_ARG_WITH(nfqueue,   [--with-nfqueue Compile for NFQUEUE instead of QUEUE],use_nfqueue="yes", use_nfqueue="")

AC_ARG_WITH(conntrack,   [--with-conntrack Compile with libnetfilter_conntrack support],use_conntrack="yes", use_conntrack="")

AC_ARG_WITH(utf8,   [--with-utf8 Use UTF8 exchange between client and server], AC_DEFINE_UNQUOTED([USE_UTF8],[1],[Will use UTF8 exchange])
)


if test "${use_nfqueue}" = "yes"; then
	AC_CHECK_LIB([nfnetlink], [nfnl_open], have_nfqueue="yes", have_nfqueue="")
#	AC_CHECK_LIB([nfnetlink], [nfnl_open], have_nfnetlink="yes", have_nfnetlink="")
#	AC_CHECK_LIB([netfilter_queue], [nfqnl_open], have_nfqueue="yes", have_nfqueue="")
	AC_DEFINE_UNQUOTED([USE_NFQUEUE],[1],[Will use netlink queue support instead of libipq])
else

AM_CONDITIONAL(HAVE_NFQUEUE,test x$have_nfqueue = xyes)

AC_CHECK_HEADERS([libipq/libipq.h libipq.h])
AC_CHECK_LIB([ipq], [ipq_message_type], have_ipq="yes", have_ipq="")

if test "$have_ipq" = "yes"; then
# check if we have a version of libipq supporting mark
AC_ARG_WITH(user-mark, [--with-user-mark  Support user mark on NuFW firewall (useless if using nfqueue)], enable_user_mark="yes", enable_user_mark="")

if test "$enable_user_mark" = "yes"; then
        AC_CHECK_LIB([ipq], [ipq_set_vwmark],AC_DEFINE_UNQUOTED([HAVE_LIBIPQ_MARK],[1],[libipq has support for mark]),AC_MSG_RESULT([libipq has no support for mark]))
fi
fi
fi

if test "${use_conntrack}" = "yes"; then
#	AC_CHECK_LIB([nfnetlink], [nfnl_open], have_nfqueue="yes", have_nfqueue="")
#	AC_CHECK_LIB([nfnetlink], [nfnl_open], have_nfnetlink="yes", have_nfnetlink="")
	AC_CHECK_LIB([netfilter_conntrack], [nfct_event_conntrack], have_conntrack="yes", have_conntrack="")
	AC_DEFINE_UNQUOTED([USE_CONNTRACK],[1],[Will build nutrackd daemon])
fi

AM_CONDITIONAL(HAVE_IPQ,test x$have_ipq = xyes)
AM_CONDITIONAL(USE_USER_MARK, test x$enable_user_mark = xyes)
AM_CONDITIONAL(HAVE_NFQUEUE,test x$have_nfqueue = xyes)
AM_CONDITIONAL(HAVE_CONNTRACK,test x$have_conntrack = xyes)
AM_CONDITIONAL(HAVE_NETFILTER,(test x$have_nfqueue = xyes) || (test x$have_ipq = xyes)  )

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
                 src/nutrackd/Makefile
		 ])

AM_INIT_AUTOMAKE(1.9)

AC_OUTPUT

if test "$debug"; then
	AC_MSG_NOTICE([Compiling with developement debug support])
fi

if (test "$have_ipq" = "" && test "$have_nfqueue" = "")  ;  then
	AC_MSG_NOTICE([nufw daemon WON'T be compiled: libipq or libnetfilter_queue not present])
else

if test "${have_ipq}" = "yes"; then
	if test "$enable_user_mark" = "yes"; then
AC_MSG_NOTICE([nufw will be compiled with user mark support])
	fi
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

if test "${have_nfqueue}" = "yes"; then
	AC_MSG_NOTICE([Compiling with libnetfilter_queue support instead of libipq])
fi

if test "${have_conntrack}" = "yes"; then
	AC_MSG_NOTICE([Compiling nutrackd])
fi




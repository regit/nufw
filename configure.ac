#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(NuFW, 0.8.2, nufw-devel@nongnu.org)
AC_CONFIG_SRCDIR([src/nufw/main.c])
AM_CONFIG_HEADER(src/include/config.h)

# Checks for programs.
AC_PROG_CC

AC_PROG_LIBTOOL
AC_PROG_INSTALL

# Checks for libraries.


AC_CHECK_LIB([ipq], [ipq_message_type],AC_DEFUN([HAVE_LIBRARY_IPQ],[1]))

AC_CHECK_LIB([pthread], [pthread_mutex_init])
# TODO : ldap check
AC_CHECK_LIB([ldap],[ldap_simple_bind_s],AC_DEFUN([HAVE_LIBRARY_LDAP],[1]),AC_MSG_ERROR([ldap library needed for authentication]))
# TODO : dbm check
AC_CHECK_LIB([gdbm],[gdbm_fetch],AC_DEFUN([HAVE_LIBRARY_GDBM],[1]),AC_MSG_ERROR([dbm library needed for authentication]))
AC_CHECK_LIB([crypt], [crypt])
# for gdbm module
AC_CHECK_LIB([gdbm], [gdbm_open])
#
AC_CHECK_LIB([ssl], [SSL_write])

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

# check if we have a version of libipq supporting mark
AC_CHECK_LIB([ipq], [ipq_set_vwmark],AC_DEFINE_UNQUOTED([HAVE_LIBIPQ_MARK],[1],[libipq has support for mark]),AC_MSG_RESULT([libipq has no support for mark]))


#Configure database support, depending on user input
AC_ARG_WITH(mysql-log, [--with-mysql-log  support user activity logging in Mysql database], enable_mysql_log="yes", enable_mysql_log="")
AC_ARG_WITH(pgsql-log, [--with-pgsql-log  support user activity logging in PostgreSQL database], enable_pgsql_log="yes", enable_pgsql_log="")

if test "$enable_mysql_log" = "yes"; then
  AC_CHECK_LIB([mysqlclient],[mysql_real_connect],AC_DEFUN([HAVE_LIBRARY_MYSQL],[1]),AC_MSG_ERROR([mysqlclient library needed if selected]))
fi
AM_CONDITIONAL(USE_MYSQL_LOG, test x$enable_mysql_log = xyes)
  
if test "$enable_pgsql_log" = "yes"; then
  AC_CHECK_LIB([pq],[PQconnectdb],AC_DEFUN([HAVE_LIBRARY_PGSQL],[1]),AC_MSG_ERROR([libpq library needed if PostgreSQL support selected]))
fi
AM_CONDITIONAL(USE_PGSQL_LOG, test x$enable_pgsql_log = xyes)

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 src/lib/Makefile
                 src/nuauth/Makefile
		 src/nuauth/modules/Makefile
  		 src/nuauth/modules/ldap/Makefile
  		 src/nuauth/modules/dbm/Makefile
  		 src/nuauth/modules/log_pgsql/Makefile
  		 src/nuauth/modules/log_mysql/Makefile
  		 src/nuauth/modules/log_syslog/Makefile
		 src/clients/Makefile
		 src/clients/nutcpc/Makefile
		 src/clients/lib/Makefile
		 src/nufw/Makefile
		 ])

AM_INIT_AUTOMAKE
AC_OUTPUT

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(NuFW, 0.5, nufw-devel@nongnu.org)
AC_CONFIG_SRCDIR([src/nufw/main.c])
AM_CONFIG_HEADER([src/include/config.h])

# Checks for programs.
AC_PROG_CC

AC_PROG_LIBTOOL
AC_PROG_INSTALL

# Checks for libraries.

AC_CHECK_LIB([ipq], [ipq_message_type])

AC_CHECK_LIB([pthread], [pthread_mutex_init])
# TODO : ldap check
AC_CHECK_LIB([ldap],[ldap_simple_bind_s],AC_DEFUN([HAVE_LIBRARY_LDAP],[1]),AC_MSG_ERROR([ldap library needed for authentication]))
# TODO : dbm check
AC_CHECK_LIB([gdbm],[gdbm_fetch],AC_DEFUN([HAVE_LIBRARY_GDBM],[1]),AC_MSG_ERROR([dbm library needed for authentication]))
AC_CHECK_LIB([crypt], [crypt])

# glib stuff
AM_PATH_GLIB_2_0(2.0.0, , AC_MSG_ERROR([glib is required in order to compile authsrv]),[gthread gmodule])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_STAT
AC_CHECK_FUNCS([gethostbyname memset socket strcasecmp strspn])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 src/nuauth/Makefile
		 src/nuauth/modules/Makefile
  		 src/nuauth/modules/ldap/Makefile
  		 src/nuauth/modules/dbm/Makefile
		 src/clients/Makefile
		 src/clients/nutcpc/Makefile
		 src/nufw/Makefile
		 ])

AM_INIT_AUTOMAKE
AC_OUTPUT

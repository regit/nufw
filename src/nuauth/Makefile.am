
AM_CPPFLAGS = -O2 -Wall -Werror-implicit-function-declaration
INCLUDES = $(GLIB_CFLAGS) -Iinclude/

sbin_PROGRAMS = nuauth


#authsrv
nuauth_SOURCES = authsrv.c pckt_authsrv.c user_authsrv.c  auth_common.c check_acls.c ldap.c user_logs.c
#ldap.c
LIBS = $(GLIB_LIBS) -lldap -lcrypt

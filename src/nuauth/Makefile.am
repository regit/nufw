SUBDIRS = modules

AM_CPPFLAGS = -O2 -Wall -fno-strict-aliasing -Werror-implicit-function-declaration -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\" -DLOCAL_STATE_DIR=\"$(localstatedir)\"
INCLUDES = $(GLIB_CFLAGS) -Iinclude/

sbin_PROGRAMS = nuauth

#authsrv
nuauth_SOURCES = authsrv.c pckt_authsrv.c user_authsrv.c  auth_common.c\
	check_acls.c user_logs.c debug.c conffile.c
#ldap.c
LIBS = $(GLIB_LIBS)  -lcrypt -lm

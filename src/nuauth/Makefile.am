SUBDIRS = modules

AM_CPPFLAGS = -O2 -Wall -fno-strict-aliasing -Werror-implicit-function-declaration -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\" -DLOCAL_STATE_DIR=\"$(localstatedir)\"
INCLUDES = $(GLIB_CFLAGS) -Iinclude/

sbin_PROGRAMS = nuauth

#authsrv
nuauth_SOURCES = authsrv.c pckt_authsrv.c user_authsrv.c  auth_common.c\
	check_acls.c user_logs.c debug.c conffile.c tls.c gcrypt.c cache.c acls.c audit.c ip_auth.c \
	x509_parsing.c parsing.c users.c client_mngr.c

nuauth_LDADD = $(GLIB_LIBS) -lm  -lgnutls -lsasl2

nuauth$(EXEEXT): $(nuauth_OBJECTS) $(nuauth_DEPENDENCIES) 
	@rm -f nuauth$(EXEEXT)
	$(LINK) $(nuauth_LDFLAGS) $(nuauth_OBJECTS) $(nuauth_LDADD)

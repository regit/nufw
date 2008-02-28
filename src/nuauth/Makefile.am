SUBDIRS = modules

AM_CFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\" -DLOCAL_STATE_DIR=\"$(localstatedir)\" -L$(top_srcdir)/src/include/ -L$(top_srcdir)/src/nuauth/
INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/nuauth/ -I$(top_srcdir)/src/libs/nussl/ -I$(top_srcdir)/src/libs/nubase

sbin_PROGRAMS = nuauth

EXTRA_DIST = splint.sh valgrind.sh valgrind.supp

#authsrv
nodist_nuauth_SOURCES = acls.h audit.h auth_common.h auth_srv.h cache.h client_mngr.h command_codec.h \
	command_enc.h command.h conffile.h connections.h conntrack.h gcrypt_init.h \
	internal_messages.h ip_auth.h localid_auth.h log.h modules_definition.h \
	modules.h nuauthconf.h nuauth_debug.h nuauth_gcrypt.h nuauth_params.h \
	nufw_servers.h nu_gcrypt.h nuthread.h parsing.h pckt_authsrv.h \
	pckt_authsrv_v3.h period.h sasl.h take_decision.h user_authsrv.h \
	user_logs.h users.h x509_parsing.h

nuauth_SOURCES = nuthread.c acls.c audit.c auth_common.c authsrv.c cache.c \
	check_acls.c client_mngr.c conffile.c debug.c gcrypt.c ip_auth.c \
	localid_auth.c parsing.c pckt_authsrv.c pckt_authsrv_v3.c\
	sasl.c tls_user.c tls_nufw.c tls_sasl.c user_authsrv.c user_logs.c users.c x509_parsing.c \
	modules.c nuauthconf.c conntrack.c period.c auth_hash.c take_decision.c \
	command.c command_enc.c nufw_servers.c connections.c \
	${nodist_nuauth_SOURCES}

nuauth_LDADD = $(GLIB_LIBS) -lm  -lgnutls -lsasl2 -L$(top_builddir)/src/include/ -L$(top_builddir)/src/libs/nussl -lnussl -L$(top_builddir)/src/libs/nubase -lnubase

if BUILD_NUAUTH_COMMAND
install-exec-local:
	install -d $(localstatedir)/run/nuauth/
endif

nuauth$(EXEEXT): $(nuauth_OBJECTS) $(nuauth_DEPENDENCIES)
	@rm -f nuauth$(EXEEXT)
	$(LINK) $(nuauth_LDFLAGS) $(nuauth_OBJECTS) $(nuauth_LDADD)

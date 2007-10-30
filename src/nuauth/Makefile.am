SUBDIRS = modules

AM_CFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\" -DLOCAL_STATE_DIR=\"$(localstatedir)\"
INCLUDES = $(GLIB_CFLAGS) -Iinclude/

sbin_PROGRAMS = nuauth

#authsrv
nodist_nuauth_SOURCES = acls.h audit.h auth_common.h auth_srv.h cache.h client_mngr.h command_codec.h \
	command_enc.h command.h conffile.h connections.h conntrack.h gcrypt_init.h \
	internal_messages.h ip_auth.h ipv6.h localid_auth.h log.h modules_definition.h \
	modules.h nuauthconf.h nuauth_debug.h nuauth_gcrypt.h nuauth_params.h \
	nufw_servers.h nu_gcrypt.h nuthread.h parsing.h pckt_authsrv.h \
	pckt_authsrv_v3.h period.h sasl.h take_decision.h tls.h user_authsrv.h \
	user_logs.h users.h x509_parsing.h

nuauth_SOURCES = ipv6.c nuthread.c acls.c audit.c auth_common.c authsrv.c cache.c \
	check_acls.c client_mngr.c conffile.c debug.c gcrypt.c ip_auth.c \
	localid_auth.c parsing.c pckt_authsrv.c pckt_authsrv_v3.c\
	sasl.c tls.c tls_user.c tls_nufw.c tls_sasl.c user_authsrv.c user_logs.c users.c x509_parsing.c \
	modules.c nuauthconf.c conntrack.c period.c auth_hash.c take_decision.c \
	command.c command_enc.c ../include/packet_parser.c nufw_servers.c connections.c \
	${nodist_nuauth_SOURCES}

nuauth_LDADD = $(GLIB_LIBS) -lm  -lgnutls -lsasl2

nuauth$(EXEEXT): $(nuauth_OBJECTS) $(nuauth_DEPENDENCIES)
	@rm -f nuauth$(EXEEXT)
	$(LINK) $(nuauth_LDFLAGS) $(nuauth_OBJECTS) $(nuauth_LDADD)

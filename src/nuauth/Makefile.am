SUBDIRS = modules

AM_CFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\" -DLOCAL_STATE_DIR=\"$(localstatedir)\"
INCLUDES = $(GLIB_CFLAGS) -Iinclude/

sbin_PROGRAMS = nuauth

#authsrv
nuauth_SOURCES = nuthread.c acls.c audit.c auth_common.c authsrv.c cache.c \
	check_acls.c client_mngr.c conffile.c debug.c gcrypt.c ip_auth.c \
	localid_auth.c parsing.c pckt_authsrv.c pckt_authsrv_v3.c\
	sasl.c tls.c tls_user.c tls_nufw.c tls_sasl.c user_authsrv.c user_logs.c users.c x509_parsing.c \
	modules.c nuauthconf.c conntrack.c period.c auth_hash.c take_decision.c\
	command.c command_enc.c ../include/packet_parser.c nufw_servers.c


nuauth_LDADD = $(GLIB_LIBS) -lm  -lgnutls -lsasl2

nuauth$(EXEEXT): $(nuauth_OBJECTS) $(nuauth_DEPENDENCIES)
	@rm -f nuauth$(EXEEXT)
	$(LINK) $(nuauth_LDFLAGS) $(nuauth_OBJECTS) $(nuauth_LDADD)

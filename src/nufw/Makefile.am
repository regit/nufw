if HAVE_LIBIPQ
AM_CPPFLAGS = -O2 -Wall -DLOCAL_STATE_DIR=\"$(localstatedir)\"  -DCONFIG_DIR=\"$(sysconfdir)\"

sbin_PROGRAMS = nufw

# nufw
nufw_SOURCES = authsrv.c  common.c  main.c  packetsrv.c  proto.h  structure.h\
		debug.c tls.c audit.c
nufw_LDADD = -lipq -lpthread -lgnutls

nufw$(EXEEXT): $(nufw_OBJECTS) $(nufw_DEPENDENCIES) 
	@rm -f nufw$(EXEEXT)
	$(LINK) $(nufw_LDFLAGS) $(nufw_OBJECTS) $(nufw_LDADD)

endif

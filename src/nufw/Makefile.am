if HAVE_NETFILTER
AM_CPPFLAGS = -O2 -Wall -DLOCAL_STATE_DIR=\"$(localstatedir)\"  -DCONFIG_DIR=\"$(sysconfdir)\"

sbin_PROGRAMS = nufw

# nufw
nufw_SOURCES = authsrv.c  common.c  main.c  packetsrv.c  proto.h  structure.h\
		debug.c tls.c audit.c
if HAVE_IPQ
nufw_LDADD = -lipq -lpthread -lgnutls
endif
if HAVE_NFQUEUE
nufw_LDADD = -lnfnetlink -lnetfilter_queue -lpthread -lgnutls
endif

nufw$(EXEEXT): $(nufw_OBJECTS) $(nufw_DEPENDENCIES) 
	@rm -f nufw$(EXEEXT)
	$(LINK) $(nufw_LDFLAGS) $(nufw_OBJECTS) $(nufw_LDADD)

endif

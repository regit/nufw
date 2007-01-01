if BUILD_NUFW
AM_CPPFLAGS = -DLOCAL_STATE_DIR=\"$(localstatedir)\"  -DCONFIG_DIR=\"$(sysconfdir)\"

sbin_PROGRAMS = nufw

# nufw
nufw_SOURCES = authsrv.c  common.c  main.c  packetsrv.c  proto.h  structure.h\
		tls.c audit.c conntrack.c log.c iface.c
if HAVE_IPQ
nufw_LDADD = -lipq -lpthread -lgnutls
endif
if HAVE_NFQUEUE_CONNTRACK
nufw_LDADD = -lnfnetlink -lnetfilter_queue -lnetfilter_conntrack -lpthread -lgnutls -ldl
endif

if HAVE_NFQUEUE_ONLY
nufw_LDADD = -lnfnetlink -lnetfilter_queue -lpthread -lgnutls
endif

if HAVE_CONNTRACK_ONLY
nufw_LDADD = -lnfnetlink -lipq -lnetfilter_conntrack -ldl -lpthread -lgnutls
endif

nufw$(EXEEXT): $(nufw_OBJECTS) $(nufw_DEPENDENCIES) 
	@rm -f nufw$(EXEEXT)
	$(LINK) $(nufw_LDFLAGS) $(nufw_OBJECTS) $(nufw_LDADD)

endif

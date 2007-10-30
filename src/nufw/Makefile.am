if BUILD_NUFW
AM_CPPFLAGS = -DLOCAL_STATE_DIR=\"$(localstatedir)\"  -DCONFIG_DIR=\"$(sysconfdir)\"

sbin_PROGRAMS = nufw

# nufw

nodist_include_HEADERS = iface.h log.h nufw.h structure.h

nufw_SOURCES = authsrv.c  common.c  main.c  packetsrv.c \
		tls.c audit.c conntrack.c log.c iface.c \
		../include/ipv6.c \
		${nodist_include_HEADERS}

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

if BUILD_NUFW
AM_CPPFLAGS = -DLOCAL_STATE_DIR=\"$(localstatedir)\"  -DCONFIG_DIR=\"$(sysconfdir)\" 
INCLUDES = -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nubase/

sbin_PROGRAMS = nufw

EXTRA_DIST = valgrind.sh

# nufw

nodist_include_HEADERS = iface.h log.h nufw.h structure.h

nufw_SOURCES = authsrv.c  common.c  main.c  packetsrv.c \
		tls.c audit.c conntrack.c iface.c \
		${nodist_include_HEADERS}

if HAVE_IPQ
nufw_LDADD = -lipq -lpthread -lgnutls -lnufw -L$(top_builddir)/src/libs/nubase -lnubase
endif
if HAVE_NFQUEUE_CONNTRACK
nufw_LDADD = -lnfnetlink -lnetfilter_queue -lnetfilter_conntrack -lpthread -lgnutls -ldl -lnufw -L$(top_builddir)/src/libs/nubase -lnubase
endif

if HAVE_NFQUEUE_ONLY
nufw_LDADD = -lnfnetlink -lnetfilter_queue -lpthread -lgnutls -lnufw -L$(top_builddir)/src/libs/nubase -lnubase
endif

if HAVE_CONNTRACK_ONLY
nufw_LDADD = -lnfnetlink -lipq -lnetfilter_conntrack -ldl -lpthread -lgnutls -lnufw -L$(top_builddir)/src/libs/nubase -lnubase
endif

nufw$(EXEEXT): $(nufw_OBJECTS) $(nufw_DEPENDENCIES)
	@rm -f nufw$(EXEEXT)
	$(LINK) $(nufw_LDFLAGS) $(nufw_OBJECTS) $(nufw_LDADD) -L$(top_builddir)/src/include/

endif

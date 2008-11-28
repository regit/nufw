if BUILD_NUFW
AM_CPPFLAGS = -DLOCAL_STATE_DIR=\"$(localstatedir)\"  -DCONFIG_DIR=\"$(sysconfdir)\"
INCLUDES = -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nubase/ -I$(top_srcdir)/src/libs/nussl/ -D_REENTRANT

sbin_PROGRAMS = nufw

EXTRA_DIST = valgrind.sh

# nufw

nodist_include_HEADERS = iface.h nufw.h structure.h

nufw_SOURCES = authsrv.c  common.c  main.c  packetsrv.c \
		tls.c audit.c conntrack.c iface.c \
		${nodist_include_HEADERS}

if HAVE_IPQ
nufw_LDADD = -lipq ../libs/nubase/libnubase.la ../libs/nussl/libnussl.la
endif
if HAVE_NFQUEUE_CONNTRACK
nufw_LDADD = -lnfnetlink -lnetfilter_queue -lnetfilter_conntrack -ldl ../libs/nubase/libnubase.la ../libs/nussl/libnussl.la
endif

if HAVE_NFQUEUE_ONLY
nufw_LDADD = -lnfnetlink -lnetfilter_queue ../libs/nubase/libnubase.la ../libs/nussl/libnussl.la
endif

if HAVE_CONNTRACK_ONLY
nufw_LDADD = -lnfnetlink -lipq -lnetfilter_conntrack -ldl ../libs/nubase/libnubase.la ../libs/nussl/libnussl.la
endif

nufw$(EXEEXT): $(nufw_OBJECTS) $(nufw_DEPENDENCIES)
	@rm -f nufw$(EXEEXT)
	$(LINK) $(nufw_LDFLAGS) $(nufw_OBJECTS) $(nufw_LDADD) -L$(top_builddir)/src/include/

endif

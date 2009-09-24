if BUILD_NUFW
AM_CPPFLAGS = -DLOCAL_STATE_DIR=\"$(localstatedir)\"  -DCONFIG_DIR=\"$(sysconfdir)\"
INCLUDES = -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nubase/ -I$(top_srcdir)/src/libs/nussl/ -I$(top_srcdir)/src/libs/nubase -I$(top_srcdir)/src/libs/nuconfparser -D_REENTRANT

sbin_PROGRAMS = nufw

EXTRA_DIST = valgrind.sh

# nufw

noinst_nufw_SOURCES = iface.h nufw.h structure.h nufwconf.h

nufw_SOURCES = authsrv.c  common.c  main.c  packetsrv.c \
		tls.c audit.c conntrack.c iface.c \
		nufwconf.c \
		${noinst_nufw_SOURCES}

if HAVE_NFQUEUE_CONNTRACK
nufw_LDADD = -lnfnetlink -lnetfilter_queue -lnetfilter_conntrack -ldl ../libs/nussl/libnussl.la ../libs/nuconfparser/libnuconfparser.la ../libs/nubase/libnubase.la
endif

if HAVE_NFQUEUE_ONLY
nufw_LDADD = -lnfnetlink -lnetfilter_queue ../libs/nussl/libnussl.la ../libs/nuconfparser/libnuconfparser.la ../libs/nubase/libnubase.la
endif

nufw$(EXEEXT): $(nufw_OBJECTS) $(nufw_DEPENDENCIES)
	@rm -f nufw$(EXEEXT)
	$(LINK) $(nufw_LDFLAGS) $(nufw_OBJECTS) $(nufw_LDADD) -L$(top_builddir)/src/include/

endif

if HAVE_CONNTRACK
AM_CPPFLAGS = -O2 -Wall -DLOCAL_STATE_DIR=\"$(localstatedir)\"  -DCONFIG_DIR=\"$(sysconfdir)\"

INCLUDES = -I$(KERNELDIR) 

sbin_PROGRAMS = nutrackd

# nutrackd
nutrackd_SOURCES = nutrackd.c  sql.c 
nutrackd_LDADD = -lnfnetlink -lnetfilter_conntrack -ldl
#nutrackd_LDADD = -lnfnetlink -lnetfilter_conntrack -ldl -lpthread

nutrackd$(EXEEXT): $(nutrackd_OBJECTS) $(nutrackd_DEPENDENCIES) 
	@rm -f nutrackd$(EXEEXT)
	$(LINK) $(nutrackd_LDFLAGS) $(nutrackd_OBJECTS) $(nutrackd_LDADD)

endif

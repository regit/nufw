if BUILD_NUTRACKD

AM_CPPFLAGS = -DLOCAL_STATE_DIR=\"$(localstatedir)\"  -DCONFIG_DIR=\"$(sysconfdir)\"

sbin_PROGRAMS = nutrackd

# nutrackd
if USE_MYSQL_LOG
nutrackd_SOURCES = nutrackd.c  mysql.c conf.c
nutrackd_LDADD = -lnfnetlink -lnetfilter_conntrack -ldl -lmysqlclient
#nutrackd_LDADD = -lnfnetlink -lnetfilter_conntrack -ldl -lpthread
else
INCLUDES = -I/usr/include/postgresql/
nutrackd_SOURCES = nutrackd.c  pgsql.c conf.c
nutrackd_LDADD = -lnfnetlink -lnetfilter_conntrack -ldl -lpq
endif

nutrackd$(EXEEXT): $(nutrackd_OBJECTS) $(nutrackd_DEPENDENCIES) 
	@rm -f nutrackd$(EXEEXT)
	$(LINK) $(nutrackd_LDFLAGS) $(nutrackd_OBJECTS) $(nutrackd_LDADD)

endif

# MYSQL log plugin

if USE_SYSLOG_LOG

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I../../ -I../../include/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libsyslog.la

libsyslog_la_SOURCES = syslog.c

libsyslog.la: $(libsyslog_la_OBJECTS) $(libsyslog_la_DEPENDENCIES) 
	$(LINK) -rpath $(plugindir) $(libsyslog_la_LDFLAGS) $(libsyslog_la_OBJECTS) $(libsyslog_la_LIBADD)

endif


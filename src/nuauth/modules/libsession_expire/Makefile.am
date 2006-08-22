# session_expire plugin

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I../../ -I../../include/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libsession_expire.la

libsession_expire_la_SOURCES = session_expire.c

libsession_expire.la: $(libsession_expire_la_OBJECTS) $(libsession_expire_la_DEPENDENCIES) 
	$(LINK) -rpath $(plugindir) $(lib_session_expire_la_LDFLAGS) $(lib_session_expire_la_OBJECTS) $(libsessin_uid_la_LIBADD)

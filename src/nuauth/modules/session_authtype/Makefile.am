# session_authtype plugin

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/nuauth/ -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nubase -I$(top_srcdir)/src/libs/nussl/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libsession_authtype.la

libsession_authtype_la_SOURCES = session_authtype.c
libsession_authtype_la_LDFLAGS = -module -avoid-version

libsession_authtype.la: $(libsession_authtype_la_OBJECTS) $(libsession_authtype_la_DEPENDENCIES)
	$(LINK) -rpath $(plugindir) $(libsession_authtype_la_LDFLAGS) $(libsession_authtype_la_OBJECTS) $(libsession_authtype_la_LIBADD)

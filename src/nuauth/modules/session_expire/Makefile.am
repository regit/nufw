# session_expire plugin

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/nuauth/ -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nubase
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libsession_expire.la

libsession_expire_la_SOURCES = session_expire.c
libsession_expire_la_LIBADD = -L$(top_builddir)/src/libs/nubase -lnubase

libsession_expire.la: $(libsession_expire_la_OBJECTS) $(libsession_expire_la_DEPENDENCIES)
	$(LINK) -rpath $(plugindir) $(lib_sessionexpire_la_LDFLAGS) $(libsession_expire_la_OBJECTS) $(libsession_expire_la_LIBADD)

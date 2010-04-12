# NND plugin

AM_CPPFLAGS = -fPIC -DLOCAL_STATE_DIR=\"$(localstatedir)\"   -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/nuauth/ -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nubase/ -I$(top_srcdir)/src/libs/nussl/
plugindir = $(libdir)/nuauth/modules/

plugin_LTLIBRARIES = libnnd.la

noinst_libnnd_la_SOURCES = auth_nnd.h
libnnd_la_SOURCES = nnd.c ${noinst_libnnd_la_SOURCES}

libnnd_la_LDFLAGS = -module -avoid-version

libnnd.la: $(libnnd_la_OBJECTS) $(libnnd_la_DEPENDENCIES)
	$(LINK) -rpath $(plugindir) $(am_libnnd_la_rpath) $(libnnd_la_LDFLAGS) $(libnnd_la_OBJECTS) $(libnnd_la_LIBADD)

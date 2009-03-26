# Prelude log plugin

if USE_PRELUDE_LOG

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"

# XXX: Forcing the prelude inclusion path is evil
INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/nuauth/ -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nubase/ -I$(top_srcdir)/src/libs/nussl/ -I/usr/include/libprelude/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libnuprelude.la

noinst_libnuprelude_la_SOURCES = log_prelude.h
libnuprelude_la_SOURCES = nuprelude.c ${noinst_libnuprelude_la_SOURCES}

libnuprelude_la_LIBADD = -lprelude
libnuprelude_la_LDFLAGS = -module -avoid-version

libnuprelude.la: $(libnuprelude_la_OBJECTS) $(libnuprelude_la_DEPENDENCIES)
	$(LINK) $(am_libnuprelude_la_rpath) $(libnuprelude_la_LDFLAGS) $(libnuprelude_la_OBJECTS) $(libnuprelude_la_LIBADD)

endif


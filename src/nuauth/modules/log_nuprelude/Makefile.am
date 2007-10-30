# Prelude log plugin

if USE_PRELUDE_LOG

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/nuauth/ -I$(top_srcdir)/src/include/ -I/usr/include/libprelude/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libnuprelude.la

nodist_include_HEADERS = log_prelude.h
libnuprelude_la_SOURCES = nuprelude.c ${nodist_include_HEADERS}

libnuprelude_la_LIBADD = -lprelude

libnuprelude.la: $(libnuprelude_la_OBJECTS) $(libnuprelude_la_DEPENDENCIES) 
	$(LINK) $(am_libnuprelude_la_rpath) $(libnuprelude_la_LDFLAGS) $(libnuprelude_la_OBJECTS) $(libnuprelude_la_LIBADD)

endif


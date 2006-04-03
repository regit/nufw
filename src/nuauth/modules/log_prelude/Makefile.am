# Prelude log plugin

if USE_PRELUDE_LOG

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I../../ -I../../include/ -I/usr/include/libprelude/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libprelude.la

libprelude_la_SOURCES = prelude.c

libprelude_la_LIBADD =

libprelude.la: $(libprelude_la_OBJECTS) $(libprelude_la_DEPENDENCIES) 
	$(LINK) $(am_libprelude_la_rpath) $(libprelude_la_LDFLAGS) $(libprelude_la_OBJECTS) $(libprelude_la_LIBADD)

endif


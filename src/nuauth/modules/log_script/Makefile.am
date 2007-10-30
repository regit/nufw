AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/nuauth/ -I$(top_srcdir)/src/include/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libscript.la

libscript_la_SOURCES = script.c

libscript.la: $(libscript_la_OBJECTS) $(libscript_la_DEPENDENCIES) 
	$(LINK) -rpath $(plugindir) $(libscript_la_LDFLAGS) $(libscript_la_OBJECTS) $(libscript_la_LIBADD)

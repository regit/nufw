# xml_defs plugin

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I../../ -I../../include/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libxml_defs.la

nodist_include_HEADERS = xml_defs.h
libxml_defs_la_SOURCES = xml_defs.c ${nodist_include_HEADERS}

libxml_defs.la: $(libxml_defs_la_OBJECTS) $(libxml_defs_la_DEPENDENCIES) 
	$(LINK) -rpath $(plugindir) $(libxml_defs_la_LDFLAGS) $(libxml_defs_la_OBJECTS) $(libxml_defs_la_LIBADD)

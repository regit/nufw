# xml_defs plugin

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/nuauth/ -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nubase -I$(top_srcdir)/src/libs/nussl/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libxml_defs.la

noinst_libxml_defs_la_SOURCES = xml_defs.h
libxml_defs_la_SOURCES = xml_defs.c ${noinst_libxml_defs_la_SOURCES}
libxml_defs_la_LDFLAGS = -module -avoid-version

libxml_defs.la: $(libxml_defs_la_OBJECTS) $(libxml_defs_la_DEPENDENCIES)
	$(LINK) -rpath $(plugindir) $(libxml_defs_la_LDFLAGS) $(libxml_defs_la_OBJECTS) $(libxml_defs_la_LIBADD)

# mark field plugin

if USE_MARK_FIELD

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/nuauth/ -I$(top_srcdir)/src/include/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libmark_field.la

nodist_include_HEADERS = mark_field.h
libmark_field_la_SOURCES = mark_field.c ${nodist_include_HEADERS}

libmark_field.la: $(libmark_field_la_OBJECTS) $(libmark_field_la_DEPENDENCIES)
	$(LINK) -rpath $(plugindir) $(libmark_field_la_LDFLAGS) $(libmark_field_la_OBJECTS) $(libmark_field_la_LIBADD)

endif


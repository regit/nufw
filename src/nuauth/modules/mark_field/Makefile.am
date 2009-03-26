# mark field plugin

if USE_MARK_FIELD

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/nuauth/ -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nubase -I$(top_srcdir)/src/libs/nussl/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libmark_field.la

noinst_libmark_field_la_SOURCES = mark_field.h
libmark_field_la_SOURCES = mark_field.c ${noinst_libmark_field_la_SOURCES}
libmark_field_la_LDFLAGS = -module -avoid-version

libmark_field.la: $(libmark_field_la_OBJECTS) $(libmark_field_la_DEPENDENCIES)
	$(LINK) -rpath $(plugindir) $(libmark_field_la_LDFLAGS) $(libmark_field_la_OBJECTS) $(libmark_field_la_LIBADD)

endif


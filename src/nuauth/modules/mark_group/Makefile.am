# mark group plugin

if USE_MARK_GROUP

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/nuauth/ -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nubase -I$(top_srcdir)/src/libs/nussl/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libmark_group.la

noinst_libmark_group_la_SOURCES = mark_group.h
libmark_group_la_SOURCES = mark_group.c ${noinst_libmark_group_la_SOURCES}
libmark_group_la_LDFLAGS = -module -avoid-version

libmark_group.la: $(libmark_group_la_OBJECTS) $(libmark_group_la_DEPENDENCIES)
	$(LINK) -rpath $(plugindir) $(libmark_group_la_LDFLAGS) $(libmark_group_la_OBJECTS) $(libmark_group_la_LIBADD)

endif


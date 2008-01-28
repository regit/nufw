# mark group plugin

if USE_MARK_GROUP

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/nuauth/ -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nubase
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libmark_group.la

nodist_include_HEADERS = mark_group.h
libmark_group_la_SOURCES = mark_group.c ${nodist_include_HEADERS}
libmark_group_la_LIBADD = -L$(top_builddir)/src/libs/nubase -lnubase

libmark_group.la: $(libmark_group_la_OBJECTS) $(libmark_group_la_DEPENDENCIES)
	$(LINK) -rpath $(plugindir) $(libmark_group_la_LDFLAGS) $(libmark_group_la_OBJECTS) $(libmark_group_la_LIBADD)

endif


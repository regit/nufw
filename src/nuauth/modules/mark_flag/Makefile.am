# mark_flag plugin

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/nuauth/ -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nubase
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libmark_flag.la

libmark_flag_la_SOURCES = mark_flag.c
libmark_flag_la_LIBADD = -L$(top_builddir)/src/libs/nubase -lnubase

libmark_flag.la: $(libmark_flag_la_OBJECTS) $(libmark_flag_la_DEPENDENCIES)
	$(LINK) -rpath $(plugindir) $(libmark_flag_la_LDFLAGS) $(libmark_flag_la_OBJECTS) $(libmark_flag_la_LIBADD)

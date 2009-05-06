# multi_mode plugin

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/nuauth/ -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nubase -I$(top_srcdir)/src/libs/nussl/ -I$(top_srcdir)/src/emc/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libmulti_mode.la

libmulti_mode_la_SOURCES = multi_mode.c
libmulti_mode_la_LDFLAGS = -module -avoid-version ../../../libs/nussl/libnussl.la

libmulti_mode.la: $(libmulti_mode_la_OBJECTS) $(libmulti_mode_la_DEPENDENCIES)
	$(LINK) -rpath $(plugindir) $(libmulti_mode_la_LDFLAGS) $(libmulti_mode_la_OBJECTS) $(libmulti_mode_la_LIBADD)

# mark_uid plugin

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/nuauth/ -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nubase -I$(top_srcdir)/src/libs/nussl/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libmark_uid.la

libmark_uid_la_SOURCES = mark_uid.c
libmark_uid_la_LDFLAGS = -module -avoid-version

libmark_uid.la: $(libmark_uid_la_OBJECTS) $(libmark_uid_la_DEPENDENCIES)
	$(LINK) -rpath $(plugindir) $(libmark_uid_la_LDFLAGS) $(libmark_uid_la_OBJECTS) $(libmark_uid_la_LIBADD)

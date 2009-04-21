# postauth_locamulti plugin

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = -I$(top_srcdir)/src/clients/lib/ -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nubase -I$(top_srcdir)/src/libs/nussl/
plugindir = $(libdir)/nuclient/modules

plugin_LTLIBRARIES = multi.la

multi_la_SOURCES = multi_main.c
multi_la_LDFLAGS = -module -avoid-version ../../../../libs/nubase/libnubase.la

multi.la: $(multi_la_OBJECTS) $(multi_la_DEPENDENCIES)
	$(LINK) -rpath $(plugindir) $(multi_la_LDFLAGS) $(multi_la_OBJECTS) $(multi_la_LIBADD)

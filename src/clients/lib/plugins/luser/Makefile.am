# postauth_localuser plugin

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = -I$(top_srcdir)/src/clients/lib/ -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nubase -I$(top_srcdir)/src/libs/nussl/
plugindir = $(libdir)/nuclient/modules

plugin_LTLIBRARIES = luser.la

luser_la_SOURCES = luser_main.c
luser_la_LDFLAGS = -module -avoid-version ../../../../libs/nubase/libnubase.la

luser.la: $(luser_la_OBJECTS) $(luser_la_DEPENDENCIES)
	$(LINK) -rpath $(plugindir) $(luser_la_LDFLAGS) $(luser_la_OBJECTS) $(luser_la_LIBADD)

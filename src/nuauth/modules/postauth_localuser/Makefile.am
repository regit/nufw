# postauth_localuser plugin

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/nuauth/ -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nubase -I$(top_srcdir)/src/libs/nussl/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libpostauth_localuser.la

libpostauth_localuser_la_SOURCES = libpostauth_localuser.c
libpostauth_localuser_la_LDFLAGS = -module -avoid-version ../../../libs/nubase/libnubase.la

libpostauth_localuser.la: $(libpostauth_localuser_la_OBJECTS) $(libpostauth_localuser_la_DEPENDENCIES)
	$(LINK) -rpath $(plugindir) $(libpostauth_localuser_la_LDFLAGS) $(libpostauth_localuser_la_OBJECTS) $(libpostauth_localuser_la_LIBADD)

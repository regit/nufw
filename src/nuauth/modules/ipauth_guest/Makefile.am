# ipauth_guest plugin

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/nuauth/ -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nubase -I$(top_srcdir)/src/libs/nussl/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libipauth_guest.la

libipauth_guest_la_SOURCES = libipauth_guest.c

libipauth_guest.la: $(libipauth_guest_la_OBJECTS) $(libipauth_guest_la_DEPENDENCIES)
	$(LINK) -rpath $(plugindir) $(libipauth_guest_la_LDFLAGS) $(libipauth_guest_la_OBJECTS) $(libipauth_guest_la_LIBADD)

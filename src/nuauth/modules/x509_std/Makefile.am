# x509_std plugin

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/nuauth/ -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nubase -I$(top_srcdir)/src/libs/nussl/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libx509_std.la

noinst_libx509_std_la_SOURCES = x509_std.h
libx509_std_la_SOURCES = x509_std.c ${noinst_libx509_std_la_SOURCES}
libx509_std_la_LDFLAGS = -module -avoid-version

libx509_std.la: $(libx509_std_la_OBJECTS) $(libx509_std_la_DEPENDENCIES)
	$(LINK) -rpath $(plugindir) $(libx509_std_la_LDFLAGS) $(libx509_std_la_OBJECTS) $(libx509_std_la_LIBADD)

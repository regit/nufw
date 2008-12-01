# x509_std plugin

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/nuauth/ -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nubase -I$(top_srcdir)/src/libs/nussl/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libx509_std.la

nodist_include_HEADERS = x509_std.h
libx509_std_la_SOURCES = x509_std.c ${nodist_include_HEADERS}

libx509_std.la: $(libx509_std_la_OBJECTS) $(libx509_std_la_DEPENDENCIES)
	$(LINK) -rpath $(plugindir) $(libx509_std_la_LDFLAGS) $(libx509_std_la_OBJECTS) $(libx509_std_la_LIBADD)

# x509_ocsp plugin

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/nuauth/ -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nubase -I$(top_srcdir)/src/libs/nussl/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libx509_ocsp.la

nodist_include_HEADERS = x509_ocsp.h
libx509_ocsp_la_SOURCES = x509_ocsp.c x509_ocsp_request.c ${nodist_include_HEADERS}

libx509_ocsp.la: $(libx509_ocsp_la_OBJECTS) $(libx509_ocsp_la_DEPENDENCIES)
	$(LINK) -rpath $(plugindir) $(libx509_ocsp_la_LDFLAGS) $(libx509_ocsp_la_OBJECTS) $(libx509_ocsp_la_LIBADD)

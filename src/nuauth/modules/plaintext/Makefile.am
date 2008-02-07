# plaintext plugin

if USE_PLAINTEXT_AUTH

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/nuauth/ -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nubase -I$(top_srcdir)/src/libs/nussl/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libplaintext.la

nodist_include_HEADERS = auth_plaintext.h
libplaintext_la_SOURCES = plaintext.c ${nodist_include_HEADERS}
libplaintext_la_LIBADD = -L$(top_builddir)/src/libs/nubase -lnubase

libplaintext.la: $(libplaintext_la_OBJECTS) $(libplaintext_la_DEPENDENCIES)
	$(LINK) -rpath $(plugindir) $(libplaintext_la_LDFLAGS) $(libplaintext_la_OBJECTS) $(libplaintext_la_LIBADD)

endif


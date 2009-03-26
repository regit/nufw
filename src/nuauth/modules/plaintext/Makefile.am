# plaintext plugin

if USE_PLAINTEXT_AUTH

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/nuauth/ -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nubase -I$(top_srcdir)/src/libs/nussl/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libplaintext.la

noinst_libplaintext_la_SOURCES = auth_plaintext.h
libplaintext_la_SOURCES = plaintext.c ${noinst_libplaintext_la_SOURCES}
libplaintext_la_LDFLAGS = -module -avoid-version

libplaintext.la: $(libplaintext_la_OBJECTS) $(libplaintext_la_DEPENDENCIES)
	$(LINK) -rpath $(plugindir) $(libplaintext_la_LDFLAGS) $(libplaintext_la_OBJECTS) $(libplaintext_la_LIBADD)

endif


# plaintext plugin

if USE_PLAINTEXT_AUTH

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I../../ -I../../include/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libplaintext.la

libplaintext_la_SOURCES = plaintext.c

libplaintext.la: $(libplaintext_la_OBJECTS) $(libplaintext_la_DEPENDENCIES) 
	$(LINK) -rpath $(plugindir) $(libplaintext_la_LDFLAGS) $(libplaintext_la_OBJECTS) $(libplaintext_la_LIBADD)
	
endif


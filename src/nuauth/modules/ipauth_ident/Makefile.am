# ident ip authentication plugin
if USE_IDENT

AM_CPPFLAGS = -O2 -Wall -Werror-implicit-function-declaration -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I../../ -I../../include/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libipauthident.la

libipauthident_la_SOURCES = ipauthident.c

libipauthident_la_LIBADD = -lident

libipauthident.la: $(libipauthident_la_OBJECTS) $(libipauthident_la_DEPENDENCIES) 
	$(LINK) -rpath $(plugindir) $(libipauthident_la_LDFLAGS) $(libipauthident_la_OBJECTS) $(libipauthident_la_LIBADD)

endif

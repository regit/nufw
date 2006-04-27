# PGSQL log plugin

if USE_PGSQL_LOG

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I../../ -I../../include/ -I/usr/include/postgresql/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libpgsql.la

libpgsql_la_SOURCES = pgsql.c

libpgsql_la_LIBADD = -lpq

libpgsql.la: $(libpgsql_la_OBJECTS) $(libpgsql_la_DEPENDENCIES) 
	$(LINK) -rpath $(plugindir) $(am_libpgsql_la_rpath) $(libpgsql_la_LDFLAGS) $(libpgsql_la_OBJECTS) $(libpgsql_la_LIBADD)

endif





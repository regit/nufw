# PGSQL log plugin

if USE_PGSQL_LOG

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/nuauth/ -I$(top_srcdir)/src/include/ -I/usr/include/postgresql/ -I$(top_srcdir)/src/libs/nubase -I$(top_srcdir)/src/libs/nussl/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libpgsql.la

noinst_libpgsql_la_SOURCES = log_pgsql.h
libpgsql_la_SOURCES = pgsql.c ${noinst_libpgsql_la_SOURCES}

libpgsql_la_LDFLAGS = -module -avoid-version
libpgsql_la_LIBADD = -lpq

libpgsql.la: $(libpgsql_la_OBJECTS) $(libpgsql_la_DEPENDENCIES)
	$(LINK) -rpath $(plugindir) $(am_libpgsql_la_rpath) $(libpgsql_la_LDFLAGS) $(libpgsql_la_OBJECTS) $(libpgsql_la_LIBADD)

endif





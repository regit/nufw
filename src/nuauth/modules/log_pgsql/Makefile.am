# PGSQL log plugin

AM_CPPFLAGS = -O2 -Wall -Werror-implicit-function-declaration -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I../../ -I../../include/ -I/usr/include/postgresql/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libpgsql.la

libpgsql_la_SOURCES = pgsql.c


LIBS = $(GLIB_LIBS) -lpq

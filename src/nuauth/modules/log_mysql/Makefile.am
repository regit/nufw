# MYSQL log plugin

if USE_MYSQL_LOG

AM_CPPFLAGS = -O2 -Wall -Werror-implicit-function-declaration -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I../../ -I../../include/ -I/usr/include/postgresql/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libmysql.la

libmysql_la_SOURCES = mysql.c

LIBS = $(GLIB_LIBS) -lmysqlclient

endif





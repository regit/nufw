# MYSQL log plugin

if USE_MYSQL_LOG

AM_CPPFLAGS = -O2 -Wall -Werror-implicit-function-declaration -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I../../ -I../../include/ -I/usr/include/postgresql/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libmysql.la

libmysql_la_SOURCES = mysql.c

libmysql_la_LIBADD = -lmysqlclient

libmysql.la: $(libmysql_la_OBJECTS) $(libmysql_la_DEPENDENCIES) 
	$(LINK) $(am_libmysql_la_rpath) $(libmysql_la_LDFLAGS) $(libmysql_la_OBJECTS) $(libmysql_la_LIBADD)

endif





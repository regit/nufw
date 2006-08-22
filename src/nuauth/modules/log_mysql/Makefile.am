# MYSQL log plugin

if USE_MYSQL_LOG

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"

if HAVE_MYSQL_CONFIG
MYSQL_INCLUDE = `mysql_config --include`
MYSQL_LIBS = `mysql_config --libs`
endif

INCLUDES = $(GLIB_CFLAGS) -I../../ -I../../include/ $(MYSQL_INCLUDE)

plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libmysql.la

libmysql_la_SOURCES = mysql.c

libmysql_la_LIBADD = -lmysqlclient

libmysql.la: $(libmysql_la_OBJECTS) $(libmysql_la_DEPENDENCIES) 
	$(LINK) -rpath $(plugindir) $(am_libmysql_la_rpath) $(libmysql_la_LDFLAGS) $(libmysql_la_OBJECTS) $(MYSQL_LIBS) $(libmysql_la_LIBADD)

endif





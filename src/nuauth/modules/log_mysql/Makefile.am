# MYSQL log plugin

if USE_MYSQL_LOG

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"

if HAVE_MYSQL_CONFIG
MYSQL_INCLUDE = `mysql_config --include`
MYSQL_LIBS = `mysql_config --libs_r`
endif

INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/nuauth/ -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nubase/ -I$(top_srcdir)/src/libs/nussl/ $(MYSQL_INCLUDE)

plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libmysql.la

noinst_libmysql_la_SOURCES = log_mysql.h
libmysql_la_SOURCES = mysql.c ${noinst_libmysql_la_SOURCES}
libmysql_la_LDFLAGS = -module -avoid-version 

libmysql.la: $(libmysql_la_OBJECTS) $(libmysql_la_DEPENDENCIES)
	$(LINK) -rpath $(plugindir) $(am_libmysql_la_rpath) $(libmysql_la_LDFLAGS) $(libmysql_la_OBJECTS) $(MYSQL_LIBS) $(libmysql_la_LIBADD)

endif





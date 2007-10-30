# auth_mysql plugin

# if USE_MYSQL_AUTH

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"

if HAVE_MYSQL_CONFIG
MYSQL_INCLUDE = `mysql_config --include`
MYSQL_LIBS = `mysql_config --libs_r`
endif

INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/nuauth/ -I$(top_srcdir)/src/include/ $(MYSQL_INCLUDE)

plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libauth_mysql.la

nodist_include_HEADERS = mysql_auth.h mysql.h

libauth_mysql_la_SOURCES = mysql_auth.c ${nodist_include_HEADERS}

#libauth_mysql_la_LIBADD = -lmysqlclient_r

libauth_mysql.la: $(libauth_mysql_la_OBJECTS) $(libauth_mysql_la_DEPENDENCIES) 
	$(LINK) -rpath $(plugindir) $(am_libauth_mysql_la_rpath) $(libauth_mysql_la_LDFLAGS) $(libauth_mysql_la_OBJECTS) $(MYSQL_LIBS) $(libauth_mysql_la_LIBADD)

# endif


# ipauth_mysql plugin

# if USE_MYSQL_AUTH

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"

if HAVE_MYSQL_CONFIG
MYSQL_INCLUDE = `mysql_config --include`
MYSQL_LIBS = `mysql_config --libs_r`
endif

INCLUDES = $(GLIB_CFLAGS) -I../../ -I../../include/ $(MYSQL_INCLUDE)

plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libipauth_mysql.la

libipauth_mysql_la_SOURCES = ipauth.c

#libipauth_mysql_la_LIBADD = -lmysqlclient_r

libipauth_mysql.la: $(libipauth_mysql_la_OBJECTS) $(libipauth_mysql_la_DEPENDENCIES) 
	$(LINK) -rpath $(plugindir) $(am_libipauth_mysql_la_rpath) $(libipauth_mysql_la_LDFLAGS) $(libipauth_mysql_la_OBJECTS) $(MYSQL_LIBS) $(libipauth_mysql_la_LIBADD)

# endif


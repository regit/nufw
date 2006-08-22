# BOFH "log" plugin

if USE_BOFH_MYSQL

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I../../ -I../../include/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libbofh_mysql.la

libbofh_mysql_la_SOURCES = bofh_mysql.c

libbofh_mysql_la_LIBADD = -lmysqlclient

libbofh_mysql.la: $(libbofh_mysql_la_OBJECTS) $(libbofh_mysql_la_DEPENDENCIES) 
	$(LINK) -rpath $(plugindir) $(am_libbofh_mysql_la_rpath) $(libbofh_mysql_la_LDFLAGS) $(libbofh_mysql_la_OBJECTS) $(libbofh_mysql_la_LIBADD)

endif





# LDAP plugin

if USE_SYSTEM_AUTH

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/nuauth/ -I$(top_srcdir)/src/include/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libsystem.la

libsystem_la_SOURCES = system.c getugroups.c

libsystem_la_LIBADD = -lpam $(GLIB_LIBS)

libsystem.la: $(libsystem_la_OBJECTS) $(libsystem_la_DEPENDENCIES) 
	$(LINK) -rpath $(plugindir) $(am_libsystem_la_rpath) $(libsystem_la_LDFLAGS) $(libsystem_la_OBJECTS) $(libsystem_la_LIBADD) 

endif

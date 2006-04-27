# DBM plugin
#
if USE_GDBM

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I../../ -I../../include/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libdbm.la

libdbm_la_SOURCES = dbm.c

libdbm_la_LIBADD = -lgdbm

libdbm.la: $(libdbm_la_OBJECTS) $(libdbm_la_DEPENDENCIES) 
	$(LINK) -rpath $(plugindir) $(am_libdbm_la_rpath) $(libdbm_la_LDFLAGS) $(libdbm_la_OBJECTS) $(libdbm_la_LIBADD)

endif

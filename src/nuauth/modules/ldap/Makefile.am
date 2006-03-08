# LDAP plugin

if USE_LDAP

AM_CPPFLAGS = -fPIC -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I../../ -I../../include/
plugindir = $(libdir)/nuauth/modules/

plugin_LTLIBRARIES = libldap.la

libldap_la_SOURCES = ldap.c

libldap_la_LIBADD = -lldap_r

libldap.la: $(libldap_la_OBJECTS) $(libldap_la_DEPENDENCIES) 
	$(LINK) $(am_libldap_la_rpath) $(libldap_la_LDFLAGS) $(libldap_la_OBJECTS) $(libldap_la_LIBADD)

endif

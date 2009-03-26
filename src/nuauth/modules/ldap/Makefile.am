# LDAP plugin

if USE_LDAP

AM_CPPFLAGS = -fPIC -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/nuauth/ -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nubase/ -I$(top_srcdir)/src/libs/nussl/
plugindir = $(libdir)/nuauth/modules/

plugin_LTLIBRARIES = libldap.la

noinst_libldap_la_SOURCES = auth_ldap.h
libldap_la_SOURCES = ldap.c ${noinst_libldap_la_SOURCES}

libldap_la_LIBADD = -lldap_r
libldap_la_LDFLAGS = -module -avoid-version

libldap.la: $(libldap_la_OBJECTS) $(libldap_la_DEPENDENCIES)
	$(LINK) -rpath $(plugindir) $(am_libldap_la_rpath) $(libldap_la_LDFLAGS) $(libldap_la_OBJECTS) $(libldap_la_LIBADD)

endif

# ulogd2 log plugin

if USE_ULOGD2_LOG

AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"
INCLUDES = $(GLIB_CFLAGS) -I$(top_srcdir)/src/nuauth -I$(top_srcdir)/src/include -I$(top_srcdir)/src/libs/nubase -I$(top_srcdir)/src/libs/nussl/
plugindir = $(libdir)/nuauth/modules

plugin_LTLIBRARIES = libulogd2.la

nodist_include_HEADERS = log_ulogd2.h log_ulogd2_request.h
libulogd2_la_SOURCES = ulogd2.c log_ulogd2_request.c ${nodist_include_HEADERS}
libulogd2_la_LDFLAGS = -module -avoid-version

libulogd2.la: $(libulogd2_la_OBJECTS) $(libulogd2_la_DEPENDENCIES)
	$(LINK) -rpath $(plugindir) $(libulogd2_la_LDFLAGS) $(libulogd2_la_OBJECTS) $(libulogd2_la_LIBADD)

endif


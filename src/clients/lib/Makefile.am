AM_CPPFLAGS = -O2 -Wall -Werror-implicit-function-declaration -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"

lib_LTLIBRARIES = libnuclient.la

# libnuclient
libnuclient_la_SOURCES = libnuclient.c 
include_HEADERS = nuclient.h


LIBS = -lcrypt -lssl ../../lib/libcssl.a 

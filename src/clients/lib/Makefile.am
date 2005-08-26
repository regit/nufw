AM_CPPFLAGS = -O2 -Wall -Werror-implicit-function-declaration -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"

lib_LTLIBRARIES = libnuclient.la

libnuclient_la_SOURCES = libnuclient.c proc.c iconv.c
LIBS = -lgnutls -lsasl2 -lpthread

include_HEADERS = nuclient.h

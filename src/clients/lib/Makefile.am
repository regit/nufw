AM_CPPFLAGS = -O2 -Wall -Werror-implicit-function-declaration -DCONFIG_DIR=\"$(sysconfdir)\" -DMODULE_DIR=\"$(libdir)\"

lib_LTLIBRARIES = libnuclient.la

libnuclient_la_SOURCES = libnuclient.c proc.c iconv.c checks.c
LIBS = -lgnutls -lsasl2 -lpthread

LIBNUCLIENT_AC=1
LIBNUCLIENT_REV=1
LIBNUCLIENT_ANC=0

libnuclient_la_LDFLAGS=-version-info ${LIBNUCLIENT_AC}:${LIBNUCLIENT_REV}:${LIBNUCLIENT_ANC}

include_HEADERS = nuclient.h

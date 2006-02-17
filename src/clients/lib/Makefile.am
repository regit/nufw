if BUILD_LIBNUCLIENT
AM_CPPFLAGS = -O2 -Wall -Werror-implicit-function-declaration -DCONFIG_DIR=\"$(sysconfdir)\" 

lib_LTLIBRARIES = libnuclient.la

libnuclient_la_SOURCES = libnuclient.c proc.c iconv.c checks.c sending.c tcptable.c
libnuclient_la_LIBADD = -lgcrypt -lgnutls -lsasl2 

LIBNUCLIENT_AC=1
LIBNUCLIENT_REV=2
LIBNUCLIENT_ANC=1

libnuclient_la_LDFLAGS=-version-info ${LIBNUCLIENT_AC}:${LIBNUCLIENT_REV}:${LIBNUCLIENT_ANC} 

include_HEADERS = nuclient.h
endif

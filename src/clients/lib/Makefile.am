if BUILD_LIBNUCLIENT
AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\"

SUBDIRS = tests

lib_LTLIBRARIES = libnuclient.la

libnuclient_la_SOURCES = libnuclient.c proc.c iconv.c checks.c sending.c tcptable.c \
			 internal.c
libnuclient_la_LIBADD = -lgcrypt -lgnutls -lsasl2 

LIBNUCLIENT_AC=3
LIBNUCLIENT_REV=0
LIBNUCLIENT_ANC=0

libnuclient_la_LDFLAGS=-version-info ${LIBNUCLIENT_AC}:${LIBNUCLIENT_REV}:${LIBNUCLIENT_ANC} 

include_HEADERS = nuclient.h
endif

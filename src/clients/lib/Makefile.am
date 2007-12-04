if BUILD_LIBNUCLIENT
AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -I$(top_srcdir)/src/include/

SUBDIRS = tests

lib_LTLIBRARIES = libnuclient.la

nodist_include_HEADERS = checks.h client.h internal.h libnuclient.h proc.h \
			 sys_config.h sending.h tcptable.h

libnuclient_la_SOURCES = ${nodist_include_HEADERS} libnuclient.c proc.c iconv.c checks.c sending.c sys_config.c\
			 tcptable.c internal.c


libnuclient_la_LIBADD = -lgcrypt -lgnutls -lsasl2 -lnufw -L$(top_builddir)/src/include/

LIBNUCLIENT_AC=3
LIBNUCLIENT_REV=0
LIBNUCLIENT_ANC=0

libnuclient_la_LDFLAGS=-version-info ${LIBNUCLIENT_AC}:${LIBNUCLIENT_REV}:${LIBNUCLIENT_ANC}

include_HEADERS = nuclient.h
endif

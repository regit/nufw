if BUILD_LIBNUCLIENT
AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\"
INCLUDES = -I$(top_srcdir)/src/include/ -I$(top_srcdir)/src/libs/nussl/  -I$(top_srcdir)/src/libs/nubase/

SUBDIRS = tests

lib_LTLIBRARIES = libnuclient.la

EXTRA_DIST = checks.h getdelim.h internal.h libnuclient.h \
			 proc.h sys_config.h sending.h tcptable.h

include_HEADERS = nuclient.h

libnuclient_la_SOURCES = ${include_HEADERS} libnuclient.c proc.c iconv.c checks.c getdelim.c sending.c \
			 sys_config.c tcptable.c internal.c


libnuclient_la_LIBADD = -lgcrypt -lgnutls -lsasl2 -L$(top_builddir)/src/include/ -L$(top_builddir)/src/libs/nussl -lnussl -L$(top_builddir)/src/libs/nubase -lnubase

LIBNUCLIENT_AC=3
LIBNUCLIENT_REV=0
LIBNUCLIENT_ANC=0

libnuclient_la_LDFLAGS=-version-info ${LIBNUCLIENT_AC}:${LIBNUCLIENT_REV}:${LIBNUCLIENT_ANC}

endif

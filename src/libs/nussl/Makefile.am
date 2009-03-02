lib_LTLIBRARIES = libnussl.la

HEADERS_FILE = nussl_alloc.h nussl_config.h nussl_constants.h nussl_dates.h nussl_defs.h nussl.h nussl_internal.h \
	  nussl_private.h nussl_privssl.h nussl_request.h nussl_session.h nussl_socket.h \
	nussl_ssl_common.h nussl_ssl.h nussl_string.h nussl_utils.h
EXTRA_DIST = README $(HEADERS_FILE)

libnussl_la_SOURCES = nussl_alloc.c nussl_dates.c nussl_openssl.c nussl_openssl_ctx.c nussl_gnutls.c nussl_gnutls_ctx.c nussl_ssl_common.c nussl_request.c nussl_session.c nussl_socket.c nussl_string.c nussl_utils.c
AM_CPPFLAGS = -I$(top_srcdir)/src/include/ -D_REENTRANT

LIBNUSSL_AC=1
LIBNUSSL_REV=0
LIBNUSSL_ANC=0

if USE_OPENSSL
AM_CFLAGS=$(AM_CPPFLAGS) @OPENSSL_CFLAGS@
libnussl_la_LIBADD = -lpthread @OPENSSL_LIBS@
else
libnussl_la_LIBADD = -lpthread -lgcrypt -lgnutls
endif

libnussl_la_LDFLAGS = -version-info ${LIBNUSSL_AC}:${LIBNUSSL_REV}:${LIBNUSSL_ANC}



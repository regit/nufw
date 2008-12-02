/*
 ** Copyright (C) 2007 INL
 ** Written by S.Tricaud <stricaud@inl.fr>
 **            L.Defert <ldefert@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** $Id: nussl_socket.c 4305 2008-01-11 15:56:09Z lds $
 **
 ** NuSSL: OpenSSL / GnuTLS layer based on libneon
 */

#ifndef __NUSSL_CONSTANTS__
#define __NUSSL_CONSTANTS__

/* Context creation modes: */
typedef enum {
	NUSSL_SSL_CTX_CLIENT,		/* client context */
	NUSSL_SSL_CTX_SERVER,		/* default server context */
	NUSSL_SSL_CTX_SERVERv2,		/* SSLv2 specific server context */
} nussl_mode_t;

typedef enum {
	NUSSL_CERT_IGNORE,
	NUSSL_CERT_REQUEST,
	NUSSL_CERT_REQUIRE,
} nussl_cert_t;

typedef enum {
	NUSSL_OK=0,		/*!< Success */
	NUSSL_ERROR,		/*!< Generic error; use nussl_get_error(session) for message */
	NUSSL_LOOKUP,		/*!< Server or proxy hostname lookup failed */
	NUSSL_AUTH,		/*!< User authentication failed on server */
	NUSSL_PROXYAUTH,	/*!< User authentication failed on proxy */
	NUSSL_CONNECT,		/*!< Could not connect to server */
	NUSSL_TIMEOUT,		/*!< Connection timed out */
	NUSSL_FAILED,		/*!< The precondition failed */
	NUSSL_RETRY,		/*!< Retry request (nussl_end_request ONLY) */
	NUSSL_REDIRECT,		/*!< See nussl_redirect.h */
} nussl_error_t;

typedef enum {
	NUSSL_SOCK_ERROR=-1,	/* Read/Write timed out */
	NUSSL_SOCK_TIMEOUT=-2,	/* Socket was closed */
	NUSSL_SOCK_CLOSED=-3,	/* Connection was reset (e.g. server crashed) */
	NUSSL_SOCK_RESET=-4,	/* Secure connection was closed without proper SSL shutdown. */
	NUSSL_SOCK_TRUNC=-5,
} ssl_sock_error_t;


/* Defined session flags: */
typedef enum nussl_session_flag_e {
	NUSSL_SESSFLAG_PERSIST = 0,	/* disable this flag to prevent use of
					 * persistent connections. */

	NUSSL_SESSFLAG_ICYPROTO,	/* enable this flag to enable support for
					 * non-HTTP ShoutCast-style "ICY" responses. */

	NUSSL_SESSFLAG_SSLv2,	/* disable this flag to disable support for
				 * SSLv2, if supported by the SSL library. */

	NUSSL_SESSFLAG_RFC4918,	/* enable this flag to enable support for
				 * RFC4918-only WebDAV features; losing
				 * backwards-compatibility with RFC2518
				 * servers. */

	NUSSL_SESSFLAG_CONNAUTH,	/* enable this flag if an awful, broken,
					 * RFC-violating, connection-based HTTP
					 * authentication scheme is in use. */

	NUSSL_SESSFLAG_TLS_SNI,	/* disable this flag to disable use of the
				 * TLS Server Name Indication extension. */

	NUSSL_SESSFLAG_IGNORE_ID_MISMATCH,	/* Enable this flag to ignore mismatch
						 * between server FQDN and certificate CN value. */

	NUSSL_SESSFLAG_LAST	/* enum sentinel value */
} nussl_session_flag;

#endif /* __NUSSL_CONSTANTS__ */


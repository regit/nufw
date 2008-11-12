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



#endif /* __NUSSL_CONSTANTS__ */


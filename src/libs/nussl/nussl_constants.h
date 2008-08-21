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

typedef enum {
	NUSSL_CERT_IGNORE,
	NUSSL_CERT_REQUEST,
	NUSSL_CERT_REQUIRE,
} nussl_cert_t;

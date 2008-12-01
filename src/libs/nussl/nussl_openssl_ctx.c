/*
 ** Copyright (C) 2007-2008 INL
 ** Written by S.Tricaud <stricaud@inl.fr>
 **            L.Defert <ldefert@inl.fr>
 **            Pierre Chifflier <chifflier@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** $Id: nussl_openssl.c 4310 2008-01-14 17:05:56Z lds $
 **
 ** NuSSL: OpenSSL / GnuTLS layer based on libneon
 */


/*
   neon SSL/TLS support using OpenSSL
   Copyright (C) 2007, Joe Orton <joe@manyfish.co.uk>
   Portions are:
   Copyright (C) 1999-2000 Tommi Komulainen <Tommi.Komulainen@iki.fi>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
   MA 02111-1307, USA

*/

#include "config.h"

#ifdef HAVE_OPENSSL

#include "nussl_config.h"

#include <sys/types.h>

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <stdio.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>

#ifdef NUSSL_HAVE_TS_SSL
#include <stdlib.h>		/* for abort() */
#include <pthread.h>
#endif

#include "nussl_ssl.h"
#include "nussl_ssl_common.h"
#include "nussl_string.h"
#include "nussl_session.h"
#include "nussl_internal.h"

#include "nussl_private.h"
#include "nussl_privssl.h"
#include "nussl_utils.h"

nussl_ssl_context *nussl_ssl_context_create(int mode)
{
	nussl_ssl_context *ctx = nussl_calloc(sizeof *ctx);
	if (mode == NUSSL_SSL_CTX_CLIENT) {
		ctx->ctx = SSL_CTX_new(SSLv23_client_method());
		ctx->sess = NULL;
		/* set client cert callback. */
		//SSL_CTX_set_client_cert_cb(ctx->ctx, provide_client_cert);
		/* enable workarounds for buggy SSL server implementations */
		SSL_CTX_set_options(ctx->ctx, SSL_OP_ALL);
	} else if (mode == NUSSL_SSL_CTX_SERVER) {
		ctx->ctx = SSL_CTX_new(SSLv23_server_method());
		SSL_CTX_set_session_cache_mode(ctx->ctx,
					       SSL_SESS_CACHE_CLIENT);
	} else {
		ctx->ctx = SSL_CTX_new(SSLv2_server_method());
		SSL_CTX_set_session_cache_mode(ctx->ctx,
					       SSL_SESS_CACHE_CLIENT);
	}
	return ctx;
}

void nussl_ssl_context_set_flag(nussl_ssl_context * ctx, int flag,
				int value)
{
	long opts = SSL_CTX_get_options(ctx->ctx);

	switch (flag) {
	case NUSSL_SSL_CTX_SSLv2:
		if (value) {
			/* Enable SSLv2 support; clear the "no SSLv2" flag. */
			opts &= ~SSL_OP_NO_SSLv2;
		} else {
			/* Disable it: set the flag. */
			opts |= SSL_OP_NO_SSLv2;
		}
		break;
	}

	SSL_CTX_set_options(ctx->ctx, opts);
}

int nussl_ssl_context_keypair(nussl_ssl_context * ctx, const char *cert,
			      const char *key)
{
	int ret;

	ret = SSL_CTX_use_PrivateKey_file(ctx->ctx, key, SSL_FILETYPE_PEM);
	if (ret == 1) {
		ret =
		    SSL_CTX_use_certificate_file(ctx->ctx, cert,
						 SSL_FILETYPE_PEM);
	}

	return ret == 1 ? 0 : -1;
}

int nussl_ssl_context_keypair_from_data(nussl_ssl_context * ctx,
					nussl_ssl_client_cert * cert)
{
	int ret;
	ret = SSL_CTX_use_PrivateKey(ctx->ctx, cert->pkey);

	if (ret != 1)
		return NUSSL_ERROR;

	ret = SSL_CTX_use_certificate(ctx->ctx, cert->cert.subject);
	return (ret == 1) ? NUSSL_OK : NUSSL_ERROR;
}

int nussl_ssl_context_set_verify(nussl_ssl_context * ctx,
				 int required,
				 const char *ca_names,
				 const char *verify_cas)
{
	if (required) {
		SSL_CTX_set_verify(ctx->ctx, SSL_VERIFY_PEER |
				   SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	}
	if (ca_names) {
		SSL_CTX_set_client_CA_list(ctx->ctx,
					   SSL_load_client_CA_file
					   (ca_names));
	}
	if (verify_cas) {
		SSL_CTX_load_verify_locations(ctx->ctx, verify_cas, NULL);
	}
	return 0;
}

void nussl_ssl_context_destroy(nussl_ssl_context * ctx)
{
	SSL_CTX_free(ctx->ctx);
	if (ctx->sess)
		SSL_SESSION_free(ctx->sess);
	nussl_free(ctx);
}

int nussl_ssl_context_trustcert(nussl_ssl_context * ctx,
				const nussl_ssl_certificate * cert)
{
	X509_STORE *store = SSL_CTX_get_cert_store(ctx->ctx);

	if (store == NULL)
		return NUSSL_ERROR;

	return (X509_STORE_add_cert(store, cert->subject) ==
		1) ? NUSSL_OK : NUSSL_ERROR;
}

/* Server mode: Set DH parameters */
int nussl_ssl_context_set_dh_bits(nussl_ssl_context * ctx,
				  unsigned int dh_bits)
{
#warning "Function is not yet implemented"
	/* XXX see man SSL_CTX_set_tmp_dh_callback */

	return NUSSL_OK;
}


#endif				/* HAVE_OPENSSL */

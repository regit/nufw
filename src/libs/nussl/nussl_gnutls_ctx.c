/*
 ** Copyright (C) 2007-2008 INL
 ** Written by S.Tricaud <stricaud@inl.fr>
 **            L.Defert <ldefert@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** $Id: nussl_gnutls.c 4490 2008-02-26 15:40:35Z toady $
 **
 ** NuSSL: OpenSSL / GnuTLS layer based on libneon
 */


/*
   neon SSL/TLS support using GNU TLS
   Copyright (C) 2007, Joe Orton <joe@manyfish.co.uk>
   Copyright (C) 2004, Aleix Conchillo Flaque <aleix@member.fsf.org>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
   MA 02111-1307, USA

*/

#ifdef HAVE_GNUTLS

#include "config.h"
#include "nussl_config.h"
#include "nussl_ssl_common.h"

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include <gnutls/gnutls.h>
#include <gnutls/pkcs12.h>

#ifdef NUSSL_HAVE_TS_SSL
#include <errno.h>
#include <pthread.h>
#include <gcrypt.h>
GCRY_THREAD_OPTION_PTHREAD_IMPL;

#endif        /* HAVE_GNUTLS */

#ifdef HAVE_ICONV
#include <iconv.h>
#endif

#include "nussl_ssl.h"
#include "nussl_string.h"
#include "nussl_session.h"
#include "nussl_internal.h"

#include "nussl_private.h"
#include "nussl_privssl.h"
#include "nussl_utils.h"

#define UGLY_DEBUG() printf("%s %s:%i\n", __FUNCTION__, __FILE__, __LINE__)


nussl_ssl_context *nussl_ssl_context_create(int flags)
{
    nussl_ssl_context *ctx = nussl_calloc(sizeof *ctx);
    UGLY_DEBUG();
    gnutls_certificate_allocate_credentials(&ctx->cred);
/*    if (flags == NUSSL_SSL_CTX_CLIENT) {
        gnutls_certificate_client_set_retrieve_function(ctx->cred,
                                                        provide_client_cert);
    }*/
    return ctx;
}

#if 0
int nussl_ssl_context_keypair(nussl_ssl_context *ctx,
                           const char *cert, const char *key)
{
    UGLY_DEBUG();
    return (gnutls_certificate_set_x509_key_file(ctx->cred, cert, key,
                                         GNUTLS_X509_FMT_PEM) == 0) ? NUSSL_OK : NUSSL_ERROR;
}
#endif

int nussl_ssl_context_keypair_from_data(nussl_ssl_context *ctx, nussl_ssl_client_cert* cert)
{
    UGLY_DEBUG();
    int ret;
    ret = gnutls_certificate_set_x509_key(ctx->cred, &cert->cert.subject, 1, cert->pkey);
    return (ret == 0) ? NUSSL_OK : NUSSL_ERROR;
}

#if 0
int nussl_ssl_context_set_verify(nussl_ssl_context *ctx, int required,
                              const char *ca_names, const char *verify_cas)
{
    UGLY_DEBUG();
    ctx->verify = required;
    if (verify_cas) {
        gnutls_certificate_set_x509_trust_file(ctx->cred, verify_cas,
                                               GNUTLS_X509_FMT_PEM);
    }
    /* gnutls_certificate_send_x509_rdn_sequence in gnutls >= 1.2 can
     * be used to *suppress* sending the CA names, but not control it,
     * it seems. */
    return 0;
}
#endif

void nussl_ssl_context_set_flag(nussl_ssl_context *ctx, int flag, int value)
{
    /* SSLv2 not supported. */
}

void nussl_ssl_context_destroy(nussl_ssl_context *ctx)
{
    UGLY_DEBUG();
    gnutls_certificate_free_credentials(ctx->cred);
    if (ctx->cache.client.data) {
        nussl_free(ctx->cache.client.data);
    } else if (ctx->cache.server.key.data) {
        gnutls_free(ctx->cache.server.key.data);
        gnutls_free(ctx->cache.server.data.data);
    }
    nussl_free(ctx);
}

int nussl_ssl_context_trustcert(nussl_ssl_context *ctx, const nussl_ssl_certificate *cert)
{
    UGLY_DEBUG();
    gnutls_x509_crt certs = cert->subject;
    return (gnutls_certificate_set_x509_trust(ctx->cred, &certs, 1) == 0) ? NUSSL_OK : NUSSL_ERROR;
}



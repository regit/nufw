/*
 ** Copyright (C) 2007 INL
 ** Written by S.Tricaud <stricaud@inl.fr>
 **            L.Defert <ldefert@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** $Id$
 **
 ** NuSSL: OpenSSL / GnuTLS layer based on libneon
 */

#ifndef NUSSL_SSL_COMMON_H
#define NUSSL_SSL_COMMON_H

#include <config.h>
#include "nussl_config.h"
#include "nussl_privssl.h"
#include "nussl_session.h"

#ifdef HAVE_GNUTLS
#include <gnutls/gnutls.h>
#include <gnutls/pkcs12.h>

struct nussl_ssl_dname_s {
    int subject; /* non-zero if this is the subject DN object */
    gnutls_x509_crt cert;
};

struct nussl_ssl_certificate_s{
    nussl_ssl_dname subj_dn, issuer_dn;
    gnutls_x509_crt subject;
    nussl_ssl_certificate *issuer;
    char *identity;
};

struct nussl_ssl_client_cert_s{
    gnutls_pkcs12 p12;
    int decrypted; /* non-zero if successfully decrypted. */
    nussl_ssl_certificate cert;
    gnutls_x509_privkey pkey;
    char *friendly_name;
};
#endif /* HAVE_GNUTLS */

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>

struct nussl_ssl_dname_s {
    X509_NAME *dn;
};

struct nussl_ssl_certificate_s {
    nussl_ssl_dname subj_dn, issuer_dn;
    X509 *subject;
    nussl_ssl_certificate *issuer;
    char *identity;
};

struct nussl_ssl_client_cert_s {
    PKCS12 *p12;
    int decrypted; /* non-zero if successfully decrypted. */
    nussl_ssl_certificate cert;
    EVP_PKEY *pkey;
    char *friendly_name;
};
#endif

#endif /* NUSSL_SSL_COMMON_H */

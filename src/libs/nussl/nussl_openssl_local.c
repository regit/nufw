/*
 ** Copyright (C) 2009 INL
 ** Written by Pierre Chifflier <chifflier@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** $Id$
 **
 ** NuSSL: OpenSSL / GnuTLS layer based on libneon
 */


#include "config.h"

#ifdef HAVE_OPENSSL

#include "nussl_privssl.h"

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



#include "nussl_ssl.h"
#include "nussl_ssl_common.h"
#include "nussl_string.h"
#include "nussl_session.h"
#include "nussl_internal.h"

#include "nussl_private.h"
#include "nussl_privssl.h"
#include "nussl_utils.h"

/*  caller must free result using X509_free */
static X509 * read_pem(const char *name)
{
	X509 *cert = NULL;
	BIO *bio;

	bio = BIO_new_file(name, "r");
	if (!bio)
		return NULL;

	cert = (X509*)PEM_read_bio_X509(bio, NULL, NULL, NULL);

	BIO_free(bio);

	return cert;
}

/* local check of certificate against CA and CRL (optional) */
int nussl_local_check_certificate(const char *cert,
	const char *ca_cert,
	const char *ca_path,
	const char *crl,
	char *ret_message,
	size_t message_sz)
{
	X509_STORE *cert_ctx = NULL;
	X509_LOOKUP *lookup = NULL; /* free "lookup" -> crash & burn */
	X509_STORE_CTX *cert_store_ctx = NULL;
	int result = -1;
	int err;
	X509 *cert_x509 = NULL;

	cert_x509 = read_pem(cert);
	if (cert_x509 == NULL) {
		if (ret_message != NULL && message_sz > 0)
			snprintf (ret_message, message_sz, "Could not read file\n");
		return -1;
	}

	cert_ctx = X509_STORE_new();
	if (cert_ctx == NULL)
		goto label_local_check_cleanup;

	// set trusted authority
	if (ca_cert != NULL) {
		lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file());
		result = X509_LOOKUP_load_file(lookup, ca_cert, X509_FILETYPE_PEM);
	}

	// CRL
	if (crl != NULL) {
		lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file());
		result = X509_load_crl_file(lookup, crl, X509_FILETYPE_PEM);
		X509_STORE_set_flags(cert_ctx, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
	}

	// CA path
	if (ca_path != NULL) {
		lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_hash_dir());
		result = X509_LOOKUP_add_dir(lookup, ca_path, X509_FILETYPE_PEM);
		// CA path can contain both CA and CRL files
		X509_STORE_set_flags(cert_ctx, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
	}

	cert_store_ctx = X509_STORE_CTX_new();
	if (cert_store_ctx == NULL)
		goto label_local_check_cleanup;

	result = X509_STORE_CTX_init(cert_store_ctx, cert_ctx, cert_x509, NULL);
	if (result != 1)
		goto label_local_check_cleanup;

	result = X509_verify_cert(cert_store_ctx);
// if result == 0, then verification failed. otherwise, verification passed.

	if (ret_message != NULL && message_sz > 0) {
		err = X509_STORE_CTX_get_error (cert_store_ctx);
		snprintf (ret_message, message_sz, "%s (%d)",
				X509_verify_cert_error_string(err), err);
	}

label_local_check_cleanup:
	X509_free(cert_x509);

	if (cert_store_ctx) {
		X509_STORE_CTX_cleanup(cert_store_ctx);
		X509_STORE_CTX_free(cert_store_ctx);
	}
	if (cert_ctx)
		X509_STORE_free(cert_ctx);

	return result;
}

#endif				/* HAVE_OPENSSL */

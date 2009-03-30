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


#ifdef HAVE_GNUTLS

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

#include <dirent.h>

#include <gnutls/gnutls.h>
#include <gnutls/pkcs12.h>

#include <errno.h>
#include <pthread.h>
#include <gcrypt.h>

#ifdef HAVE_ICONV
#include <iconv.h>
#endif

#include "nussl_config.h"
#include "nussl_ssl_common.h"

#include "nussl_ssl.h"
#include "nussl_string.h"
#include "nussl_session.h"
#include "nussl_internal.h"

#include "nussl_private.h"
#include "nussl_privssl.h"
#include "nussl_utils.h"


int read_to_datum(const char *filename, gnutls_datum * datum);

/* append src to dst, guaranteeing a null terminator.
 * If dst+src is too big, truncate it.
 * Return strlen(old dst)+dstrlen(src).
 */
size_t safe_strlcat(char *dst, const char *src, size_t size)
{
	size_t n=0;

	/* find the end of string in dst */
#ifdef STRLEN_FASTER
	if (!size)
		return strlen(src);
	n = strlen(dst);
	dst += n;
#else
	while (n < size && *dst++)
		++n;

	if (n >= size)
		return size + strlen(src);
	/* back up over the '\0' */
	--dst;
#endif

	/* copy bytes from src to dst.
	 * If there's no space left, stop copying
	 * if we copy a '\0', stop copying
	 */
	while (n < size) {
		if (!(*dst++ = *src++))
			return n;
		++n;
	}

	if (n == size) {
		/* overflow, so truncate the string, and ... */
		if (size)
			dst[-1] = '\0';
		/* ... work out what the length would have been had there been
		 * enough space in the buffer
		 */
		n += strlen(dst);
	}

	return n;
}

/* Verifies a certificate against an other certificate
 * which is supposed to be it's issuer. Also checks the
 * crl_list if the certificate is revoked.
 */
static int verify_cert2 (gnutls_x509_crt_t crt, gnutls_x509_crt_t issuer,
			 gnutls_x509_crl_t * crl_list, int crl_list_size,
			 char *buf, size_t buf_sz)
{
	unsigned int output;
	int ret;
	time_t now = time (0);
	int result = 0;

	/* Do the actual verification.
	 */
	gnutls_x509_crt_verify (crt, &issuer, 1, 0, &output);

	if (output & GNUTLS_CERT_INVALID)
	{
		result++;
		if (buf != NULL && buf_sz > 0)
			snprintf(buf, buf_sz, "Not trusted");

		if (output & GNUTLS_CERT_SIGNER_NOT_FOUND)
			if (buf != NULL && buf_sz > 0)
				safe_strlcat(buf, ": no issuer was found", buf_sz);
		if (output & GNUTLS_CERT_SIGNER_NOT_CA)
			if (buf != NULL && buf_sz > 0)
				safe_strlcat(buf, ": issuer is not a CA", buf_sz);
	}
	else
		if (buf != NULL && buf_sz > 0)
			snprintf(buf, buf_sz, "Trusted");


	/* Now check the expiration dates.
	 */
	if (gnutls_x509_crt_get_activation_time (crt) > now) {
		result++;
		if (buf != NULL && buf_sz > 0)
			safe_strlcat(buf, " / Not yet activated", buf_sz);
	}

	if (gnutls_x509_crt_get_expiration_time (crt) < now) {
		result++;
		if (buf != NULL && buf_sz > 0)
			safe_strlcat(buf, " / Expired", buf_sz);
	}

	/* Check if the certificate is revoked.
	 */
	ret = gnutls_x509_crt_check_revocation (crt, crl_list, crl_list_size);
	if (ret == 1)
	{				/* revoked */
		result++;
		if (buf != NULL && buf_sz > 0)
			safe_strlcat(buf, " / Revoked", buf_sz);
	}

	return result;
}




/* local check of certificate against CA and CRL (optional) */
int nussl_local_check_certificate(const char *cert_file,
	const char *ca_cert_file,
	const char *ca_path,
	const char *crl_file,
	char *ret_message,
	size_t message_sz)

{
	gnutls_datum datum_cert, datum_ca, datum_crl;
	gnutls_x509_crt_t cert;
	gnutls_x509_crt_t ca;
	gnutls_x509_crl_t crl;
	int ret;
	int result=-1;

	datum_cert.data = NULL;
	datum_ca.data = NULL;
	datum_crl.data = NULL;

	if (read_to_datum(cert_file, &datum_cert))
		return -1;

	gnutls_x509_crt_init(&cert);

	ret = gnutls_x509_crt_import(cert, &datum_cert, GNUTLS_X509_FMT_PEM);
	if (ret) {
		if (ret_message != NULL && message_sz > 0)
			snprintf(ret_message, message_sz, "TLS: Could not import cert data\n");
		goto label_local_check_certificate;
	}

	if (ca_cert_file != NULL) {
		ret = read_to_datum(ca_cert_file, &datum_ca);
		if (ret != 0)
			goto label_local_check_certificate;

		gnutls_x509_crt_init(&ca);
		ret = gnutls_x509_crt_import(ca, &datum_ca, GNUTLS_X509_FMT_PEM);
		if (ret) {
			if (ret_message != NULL && message_sz > 0)
				snprintf(ret_message, message_sz, "TLS: Could not import CA data\n");
			goto label_local_check_certificate;
		}
	}

	if (crl_file != NULL) {
		ret = read_to_datum(crl_file, &datum_crl);
		if (ret != 0)
			goto label_local_check_certificate;

		gnutls_x509_crl_init(&crl);
		ret = gnutls_x509_crl_import(crl, &datum_crl, GNUTLS_X509_FMT_PEM);
		if (ret) {
			if (ret_message != NULL && message_sz > 0)
				snprintf(ret_message, message_sz, "TLS: Could not import CRL data\n");
			goto label_local_check_certificate;
		}
	}


	result = verify_cert2(cert, ca, &crl, 1 /* crl list size */, ret_message, message_sz);


label_local_check_certificate:
	if (datum_cert.data != NULL) {
		gnutls_free(datum_cert.data);
	}
	if (datum_ca.data != NULL) {
		gnutls_x509_crt_deinit(ca);
		gnutls_free(datum_ca.data);
	}
	if (datum_crl.data != NULL) {
		gnutls_x509_crl_deinit(crl);
		gnutls_free(datum_crl.data);
	}

	gnutls_x509_crt_deinit(cert);

	return result;
}


#endif				/* HAVE_GNUTLS */

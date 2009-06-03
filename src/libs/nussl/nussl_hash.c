/*
 ** Copyright (C) 2009 INL
 ** Written by Pierre Chifflier <chifflier@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** NuSSL: OpenSSL / GnuTLS layer based on libneon
 */


#include "config.h"

#include "nussl_privssl.h"

#include <sys/types.h>

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <stdio.h>

#include "nussl_hash.h"

#ifdef HAVE_OPENSSL

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

int nussl_hash_compute(nussl_hash_algo_t algo, const char *data, size_t datasz, char *out, size_t *outsz)
{
	return nussl_hash_compute_with_salt(algo, data, datasz, NULL, 0, out, outsz);
}

int nussl_hash_compute_with_salt(nussl_hash_algo_t algo, const char *data, size_t datasz, const char *salt, size_t saltsz, char *out, size_t *outsz)
{
	const EVP_MD *md;
	EVP_MD_CTX mdctx;

	switch (algo) {
	case NUSSL_HASH_MD5:
		md = EVP_md5();
		break;
	case NUSSL_HASH_SHA1:
		md = EVP_sha1();
		break;
	case NUSSL_HASH_SHA256:
		md = EVP_sha256();
		break;
	case NUSSL_HASH_SHA512:
		md = EVP_sha512();
		break;
	default:
		return -1;
	};

	EVP_MD_CTX_init(&mdctx);
	EVP_DigestInit_ex(&mdctx, md, NULL);
	EVP_DigestUpdate(&mdctx, (unsigned char*)data, datasz);
	if (salt != NULL && saltsz > 0) {
		EVP_DigestUpdate(&mdctx, (unsigned char*)salt, saltsz);
	}
	EVP_DigestFinal_ex(&mdctx, (unsigned char*)out, outsz);
	EVP_MD_CTX_cleanup(&mdctx);

	return 0;
}


#else	/* HAVE_OPENSSL */

#include <gcrypt.h>

int nussl_hash_compute(nussl_hash_algo_t algo, const char *data, size_t datasz, char *out, size_t *outsz)
{
	return nussl_hash_compute_with_salt(algo, data, datasz, NULL, 0, out, outsz);
}

int nussl_hash_compute_with_salt(nussl_hash_algo_t algo, const char *data, size_t datasz, const char *salt, size_t saltsz, char *out, size_t *outsz)
{
	gcry_md_hd_t hd;
	int g_algo = 0;
	char *res;

	switch (algo) {
	case NUSSL_HASH_MD5:
		g_algo = GCRY_MD_MD5;
		break;
	case NUSSL_HASH_SHA1:
		g_algo = GCRY_MD_SHA1;
		break;
	case NUSSL_HASH_SHA256:
		g_algo = GCRY_MD_SHA256;
		break;
	case NUSSL_HASH_SHA512:
		g_algo = GCRY_MD_SHA512;
		break;
	default:
		return -1;
	};

	gcry_md_open(&hd, g_algo, 0);
	gcry_md_write(hd, data, datasz);
	if (salt != NULL && saltsz > 0) {
		gcry_md_write(hd, salt, saltsz);
	}
	res = (char *) gcry_md_read(hd, algo);

	*outsz = strlen(res);
	strncpy(out, res, *outsz);

	gcry_md_close(hd);

	return 0;
}


#endif	/* HAVE_OPENSSL */

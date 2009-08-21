/*
 ** Copyright (C) 2009 INL
 ** Written by Pierre Chifflier <chifflier@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** NuSSL: OpenSSL / GnuTLS layer based on libneon
 */


#ifndef NUSSL_HASH_H
#define NUSSL_HASH_H 1

#ifdef __cplusplus
extern "C" {
#endif

/* don't change order or it will break compatibility
   between client and server */
typedef enum {
	NUSSL_HASH_NONE = 0,
	NUSSL_HASH_MD5,
	NUSSL_HASH_SHA1,
	NUSSL_HASH_SHA256,
	NUSSL_HASH_SHA512,
} nussl_hash_algo_t;

#define NUSSL_HASH_MAX_SIZE 64	/* longest known is SHA512 */

/* out buffer must at least NUSSL_HASH_MAX_SIZE bytes long */
int nussl_hash_compute(nussl_hash_algo_t algo, const char *data, size_t datasz, char *out, size_t *outsz);

/* out buffer must at least NUSSL_HASH_MAX_SIZE bytes long */
int nussl_hash_compute_with_salt(nussl_hash_algo_t algo, const char *data, size_t datasz, const char *salt, size_t saltsz, char *out, size_t *outsz);


int nussl_hash_file(nussl_hash_algo_t algo, const char * filename,
		    unsigned char *out, size_t *outsz);

#ifdef __cplusplus
}
#endif

#endif	/* NUSSL_HASH_H */

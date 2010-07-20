/*
 ** Copyright (C) 2009 INL
 ** Written by Pierre Chifflier <chifflier@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** NuSSL: OpenSSL / GnuTLS layer based on libneon

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

   In addition, as a special exception, INL
   gives permission to link the code of its release of NuSSL with the
   OpenSSL project's "OpenSSL" library (or with modified versions of it
   that use the same license as the "OpenSSL" library), and distribute
   the linked executables.  You must obey the GNU General Public License
   in all respects for all of the code used other than "OpenSSL".  If you
   modify this file, you may extend this exception to your version of the
   file, but you are not obligated to do so.  If you do not wish to do
   so, delete this exception statement from your version.
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
		    unsigned char *out, size_t *outsz)
#ifdef __GNUC__
	__attribute__ ((warn_unused_result))
#endif
;

#ifdef __cplusplus
}
#endif

#endif	/* NUSSL_HASH_H */

/*
 ** Copyright(C) 2004-2009 INL
 ** Written by  Eric Leblond <regit@inl.fr>
 **             Pierre Chifflier <chifflier@inl.fr>
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, version 3 of the License.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software
 ** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 **
 ** Changelog :
 **  20/06/2005 : deal with seeded/unseeded cases. Patch from Julian Reich <jreich@epplehaus.de>
 **  02/06/2009 : use hash functions from NuSSL. Recode hash format
 **
 */
#include <auth_srv.h>
#include <tls.h>
#include <sasl/saslutil.h>
#include "../include/security.h"

#include <nussl_hash.h>

/**
 * \ingroup TLSUser
 * @{
 *
 * \file gcrypt.c
 * \brief Contain function used to ease authentication task
 *
 * In particular, it does handle hash verification
 */

/**
 * verify user password against user authentication module.
 */
int verify_user_password(const char *given, const char *ours)
{
	int ret;
	char *decoded;
	unsigned int decoded_len;
	char **splitted_secret;
	int algo = 0;
	int seeded = 0;
	char seed[NUSSL_HASH_MAX_SIZE];
	unsigned int seed_len;
	char res[NUSSL_HASH_MAX_SIZE];
	size_t res_len;


	if (g_str_has_prefix(ours, "{")) {
		splitted_secret = g_strsplit(ours, "}", 2);
		if (splitted_secret == NULL)	/* We received an empty string */
			return SASL_BADAUTH;

		if (strncmp("{", splitted_secret[0], 1)) {	/* Not starting with "{" means this is plaintext */
			if (strcmp(given, splitted_secret[0])) {
				g_strfreev(splitted_secret);
				return SASL_BADAUTH;
			} else {
				g_strfreev(splitted_secret);
				return SASL_OK;
			}
		}

		if (!(strcmp("{SSHA", splitted_secret[0]))) {	/* SHA1 (seeded) */
			algo = NUSSL_HASH_SHA1;
			seeded = 1;
		} else if (!(strcmp("{SMD5", splitted_secret[0]))) {	/* MD5 (seeded) */
			algo = NUSSL_HASH_MD5;
			seeded = 1;
		} else if (!(strcmp("{SHA1", splitted_secret[0])))	/* SHA1 */
			algo = NUSSL_HASH_SHA1;
		else if (!(strcmp("{SHA", splitted_secret[0])))	/* SHA1 */
			algo = NUSSL_HASH_SHA1;
		else if (!(strcmp("{MD5", splitted_secret[0])))	/* MD5 */
			algo = NUSSL_HASH_MD5;
		else {
			log_message(WARNING, DEBUG_AREA_AUTH,
				    "verify_user_password() : Unsupported hash algorithm");
			g_strfreev(splitted_secret);
			return SASL_BADAUTH;
		}

		if (seeded) {
			/* get seed */
			if (sasl_decode64(splitted_secret[1], strlen(splitted_secret[1]),
					seed, sizeof(seed), &seed_len) != SASL_OK) {
				log_message(INFO, DEBUG_AREA_AUTH,
					    "sasl_decode64 failed in gcrypt.c, where seeded is used");
				g_strfreev(splitted_secret);
				return SASL_BADAUTH;
			}

			ret = nussl_hash_compute_with_salt(algo, given, strlen(given), seed, seed_len, res, &res_len);
		} else {
			ret = nussl_hash_compute(algo, given, strlen(given), res, &res_len);
		}

		/* alloc decoded to reasonnable length */
		decoded = g_new0(char, 50);
		if (sasl_encode64(res, res_len, decoded, 50, &decoded_len) != SASL_OK) {
				log_message(INFO, DEBUG_AREA_AUTH,
					    "sasl_encode64 failed in gcrypt.c");
				g_strfreev(splitted_secret);
				return SASL_BADAUTH;
		}

		/* convert password from utf-8 to locale */
		if (nuauthconf->uses_utf8) {
			size_t bwritten = 0;
			gchar *traduc;
			traduc = g_locale_from_utf8(decoded,
						    -1,
						    NULL, &bwritten, NULL);
			if (traduc) {
				g_free(decoded);
				decoded = traduc;
			} else {
				log_message(WARNING, DEBUG_AREA_AUTH,
					    "can not convert password %s at %s:%d",
					    decoded, __FILE__, __LINE__);
			}
		}
		debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_AUTH,
				  "given %s, decoded %s, stored : %s",
				  given, decoded, ours);

		if (memcmp(decoded, splitted_secret[1+seeded], decoded_len) == 0) {
#ifdef DEBUG_ENABLE
			if (DEBUG_OR_NOT
			    (DEBUG_LEVEL_VERBOSE_DEBUG, DEBUG_AREA_MAIN)) {
				char temp_decoded[NUSSL_HASH_MAX_SIZE];
				char temp_stored[NUSSL_HASH_MAX_SIZE];

				SECURE_STRNCPY(temp_decoded, decoded,
					       sizeof(temp_decoded));
				SECURE_STRNCPY(temp_stored, decoded,
					       sizeof(temp_stored));

				g_message("%s == %s",
					  temp_decoded, temp_stored);
			}
#endif

			g_strfreev(splitted_secret);
			g_free(decoded);
			return SASL_OK;
		} else {
			log_message(DEBUG, DEBUG_AREA_AUTH, "given (%s) != stored (%s)",
				decoded, splitted_secret[1+seeded]);

			g_strfreev(splitted_secret);
			g_free(decoded);
			return SASL_BADAUTH;
		}
	} else {
		/* convert password from utf-8 to locale */
		if (nuauthconf->uses_utf8) {
			size_t bwritten = 0;
			gchar *traduc;
			traduc = g_locale_from_utf8(given,
						    strlen(given),
						    NULL, &bwritten, NULL);
			if (traduc) {
				given = traduc;
			} else {
				if (DEBUG_OR_NOT
				    (DEBUG_LEVEL_WARNING,
				     DEBUG_AREA_MAIN)) {
					const char *ccharset;
					g_get_charset(&ccharset);
					g_message
					    ("Can not convert password %s to %s at %s:%d",
					     given, ccharset, __FILE__,
					     __LINE__);
				}
			}
		}
		if (!strcmp(given, ours)) {
			if (nuauthconf->uses_utf8) {
				g_free((char *) given);
			}
			return SASL_OK;
		} else {
			if (nuauthconf->uses_utf8) {
				g_free((char *) given);
			}
			return SASL_BADAUTH;
		}
	}

	return SASL_BADAUTH;
}

/* @} */

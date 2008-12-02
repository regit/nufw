/*
 ** Copyright(C) 2004-2008 INL
 ** Written by  Eric Leblond <regit@inl.fr>
 **             Pierre Chifflier <chifflier@inl.fr>
 **
 ** $Id$
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
 **
 */
#include <auth_srv.h>
#include <tls.h>
#include <sasl/saslutil.h>
#include "../include/security.h"

#ifdef HAVE_GNUTLS

#include <gcrypt.h>
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
	gcry_md_hd_t hd;
	char *res;
	char *decoded;
	unsigned int len;
	char **splitted_secret;
	int algo = 0;

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

		int seeded = 0;

		if (!(strcmp("{SSHA", splitted_secret[0]))) {	/* SHA1 (seeded) */
			algo = GCRY_MD_SHA1;
			seeded = 1;
		} else if (!(strcmp("{SMD5", splitted_secret[0]))) {	/* MD5 (seeded) */
			algo = GCRY_MD_MD5;
			seeded = 1;
		} else if (!(strcmp("{SHA1", splitted_secret[0])))	/* SHA1 */
			algo = GCRY_MD_SHA1;
		else if (!(strcmp("{SHA", splitted_secret[0])))	/* SHA1 */
			algo = GCRY_MD_SHA1;
		else if (!(strcmp("{MD5", splitted_secret[0])))	/* MD5 */
			algo = GCRY_MD_MD5;
		else {
			log_message(WARNING, DEBUG_AREA_AUTH,
				    "verify_user_password() : Unsupported hash algorithm");
			g_strfreev(splitted_secret);
			return SASL_BADAUTH;
		}


		gcry_md_open(&hd, algo, 0);
		gcry_md_write(hd, given, strlen(given));

		if ((algo == GCRY_MD_SHA1) && seeded) {
			char temp[24];

			if (sasl_decode64
			    (splitted_secret[1],
			     strlen(splitted_secret[1]), temp,
			     sizeof(temp), &len) != SASL_OK) {
				log_message(INFO, DEBUG_AREA_AUTH,
					    "sasl_decode64 failed in gcrypt.c, where seeded SHA1 is used");
				return (SASL_BADAUTH);
			}
			gcry_md_write(hd, temp + 20, 4);
		} else if ((algo == GCRY_MD_MD5) && seeded) {
			char temp[20];

			if (sasl_decode64
			    (splitted_secret[1],
			     strlen(splitted_secret[1]), temp,
			     sizeof(temp), &len) != SASL_OK) {
				log_message(INFO, DEBUG_AREA_AUTH,
					    "sasl_decode64 failed in gcrypt.c, where seeded MD5 is used");
				return (SASL_BADAUTH);
			}
			gcry_md_write(hd, temp + 16, 4);
		}

		res = (char *) gcry_md_read(hd, algo);
		/* alloc decoded to reasonnable length */
		decoded = g_new0(char, 50);
		sasl_encode64(res, strlen(res), decoded, 50, &len);

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
				  "given %s, hash %s, decoded %s, stored : %s",
				  given, res, decoded, ours);

		if (!seeded && !strcmp(decoded, splitted_secret[1])) {
			debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_AUTH,
					  "%s == %s", decoded,
					  splitted_secret[1]);

			g_free(decoded);
			g_strfreev(splitted_secret);
			return SASL_OK;
		} else if (seeded && (algo == GCRY_MD_SHA1)
			   && !memcmp(decoded, splitted_secret[1], 20)) {
#ifdef DEBUG_ENABLE
			if (DEBUG_OR_NOT
			    (DEBUG_LEVEL_VERBOSE_DEBUG, DEBUG_AREA_MAIN)) {
				char temp_decoded[21];
				char temp_stored[21];

				SECURE_STRNCPY(temp_decoded, decoded,
					       sizeof(temp_decoded));
				SECURE_STRNCPY(temp_stored,
					       splitted_secret[1],
					       sizeof(temp_stored));

				g_message("%s == %s (first 20 chars)",
					  temp_decoded, temp_stored);
			}
#endif

			g_strfreev(splitted_secret);
			g_free(decoded);
			return SASL_OK;
		} else if (seeded && (algo == GCRY_MD_MD5)
			   && !memcmp(decoded, splitted_secret[1], 16)) {
#ifdef DEBUG_ENABLE
			if (DEBUG_OR_NOT
			    (DEBUG_LEVEL_VERBOSE_DEBUG, DEBUG_AREA_MAIN)) {
				char temp_decoded[17];
				char temp_stored[17];

				SECURE_STRNCPY(temp_decoded, decoded,
					       sizeof(temp_decoded));
				SECURE_STRNCPY(temp_stored, decoded,
					       sizeof(temp_stored));

				g_message("%s == %s (first 16 chars)",
					  temp_decoded, temp_stored);
			}
#endif

			g_strfreev(splitted_secret);
			g_free(decoded);
			return SASL_OK;
		} else {
			log_message(DEBUG, DEBUG_AREA_AUTH, "given != stored");

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
}

#elif HAVE_OPENSSL /* HAVE_GNUTLS */

int verify_user_password(const char *given, const char *ours)
{
	char *res;
	char *decoded;
	unsigned int len;
	char **splitted_secret;
	int algo = 0;

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

#warning "MD5 and SHA1 hash for plaintext are not implemented"
	// XXX see EVP_DigestInit
#if 0
		int seeded = 0;

		if (!(strcmp("{SSHA", splitted_secret[0]))) {	/* SHA1 (seeded) */
			algo = GCRY_MD_SHA1;
			seeded = 1;
		} else if (!(strcmp("{SMD5", splitted_secret[0]))) {	/* MD5 (seeded) */
			algo = GCRY_MD_MD5;
			seeded = 1;
		} else if (!(strcmp("{SHA1", splitted_secret[0])))	/* SHA1 */
			algo = GCRY_MD_SHA1;
		else if (!(strcmp("{SHA", splitted_secret[0])))	/* SHA1 */
			algo = GCRY_MD_SHA1;
		else if (!(strcmp("{MD5", splitted_secret[0])))	/* MD5 */
			algo = GCRY_MD_MD5;
		else {
			log_message(WARNING, DEBUG_AREA_AUTH,
				    "verify_user_password() : Unsupported hash algorithm");
			g_strfreev(splitted_secret);
			return SASL_BADAUTH;
		}


		gcry_md_open(&hd, algo, 0);
		gcry_md_write(hd, given, strlen(given));

		if ((algo == GCRY_MD_SHA1) && seeded) {
			char temp[24];

			if (sasl_decode64
			    (splitted_secret[1],
			     strlen(splitted_secret[1]), temp,
			     sizeof(temp), &len) != SASL_OK) {
				log_message(INFO, DEBUG_AREA_AUTH,
					    "sasl_decode64 failed in gcrypt.c, where seeded SHA1 is used");
				return (SASL_BADAUTH);
			}
			gcry_md_write(hd, temp + 20, 4);
		} else if ((algo == GCRY_MD_MD5) && seeded) {
			char temp[20];

			if (sasl_decode64
			    (splitted_secret[1],
			     strlen(splitted_secret[1]), temp,
			     sizeof(temp), &len) != SASL_OK) {
				log_message(INFO, DEBUG_AREA_AUTH,
					    "sasl_decode64 failed in gcrypt.c, where seeded MD5 is used");
				return (SASL_BADAUTH);
			}
			gcry_md_write(hd, temp + 16, 4);
		}

		res = (char *) gcry_md_read(hd, algo);
		/* alloc decoded to reasonnable length */
		decoded = g_new0(char, 50);
		sasl_encode64(res, strlen(res), decoded, 50, &len);

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
				  "given %s, hash %s, decoded %s, stored : %s",
				  given, res, decoded, ours);

		if (!seeded && !strcmp(decoded, splitted_secret[1])) {
			debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_AUTH,
					  "%s == %s", decoded,
					  splitted_secret[1]);

			g_free(decoded);
			g_strfreev(splitted_secret);
			return SASL_OK;
		} else if (seeded && (algo == GCRY_MD_SHA1)
			   && !memcmp(decoded, splitted_secret[1], 20)) {
#ifdef DEBUG_ENABLE
			if (DEBUG_OR_NOT
			    (DEBUG_LEVEL_VERBOSE_DEBUG, DEBUG_AREA_MAIN)) {
				char temp_decoded[21];
				char temp_stored[21];

				SECURE_STRNCPY(temp_decoded, decoded,
					       sizeof(temp_decoded));
				SECURE_STRNCPY(temp_stored,
					       splitted_secret[1],
					       sizeof(temp_stored));

				g_message("%s == %s (first 20 chars)",
					  temp_decoded, temp_stored);
			}
#endif

			g_strfreev(splitted_secret);
			g_free(decoded);
			return SASL_OK;
		} else if (seeded && (algo == GCRY_MD_MD5)
			   && !memcmp(decoded, splitted_secret[1], 16)) {
#ifdef DEBUG_ENABLE
			if (DEBUG_OR_NOT
			    (DEBUG_LEVEL_VERBOSE_DEBUG, DEBUG_AREA_MAIN)) {
				char temp_decoded[17];
				char temp_stored[17];

				SECURE_STRNCPY(temp_decoded, decoded,
					       sizeof(temp_decoded));
				SECURE_STRNCPY(temp_stored, decoded,
					       sizeof(temp_stored));

				g_message("%s == %s (first 16 chars)",
					  temp_decoded, temp_stored);
			}
#endif

			g_strfreev(splitted_secret);
			g_free(decoded);
			return SASL_OK;
		} else {
			log_message(DEBUG, DEBUG_AREA_AUTH, "given != stored");

			g_strfreev(splitted_secret);
			g_free(decoded);
			return SASL_BADAUTH;
		}
#endif /* 0 */
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

	return -1;
}

#else

#error "You need either GnuTLS or OpenSSL"

#endif /* HAVE_GNUTLS */

/* @} */

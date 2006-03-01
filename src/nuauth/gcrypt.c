/*
 ** Copyright(C) 2004 Eric Leblond <regit@inl.fr>
 **
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, version 2 of the License.
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
#include <gcrypt.h>
#include <sasl/saslutil.h>
#include "../include/security.h"

/**
 * verify user password against user authentication module.
 */
int verify_user_password(const char* given,const char* ours){
	gcry_md_hd_t hd;
	char * res;
	char* decoded; 
	size_t len;
	char **splitted_secret; 
	int algo=0;

	if (g_str_has_prefix(ours,"{")) {
		splitted_secret=g_strsplit    (ours, "}", 2);
		if (splitted_secret == NULL) //We received an empty string
			return SASL_BADAUTH;

		if (strncmp("{",splitted_secret[0],1)) { // Not starting with "{" means this is plaintext
			if (strcmp(given,splitted_secret[0])){
				g_strfreev(splitted_secret);
				return SASL_BADAUTH;
			}
			else {
				g_strfreev(splitted_secret);
				return SASL_OK;
			}
		}

		int seeded = 0;

		if (!(strcmp("{SSHA",splitted_secret[0]))) {      // SHA1 (seeded)
			algo = GCRY_MD_SHA1;
			seeded = 1;
		}
		else if (!(strcmp("{SMD5",splitted_secret[0]))) { // MD5 (seeded)
			algo = GCRY_MD_MD5;
			seeded = 1;
		}
		else if (!(strcmp("{SHA1",splitted_secret[0]))) // SHA1
			algo = GCRY_MD_SHA1;
		else if (!(strcmp("{SHA",splitted_secret[0])))  // SHA1
			algo = GCRY_MD_SHA1;
		else if (!(strcmp("{MD5",splitted_secret[0])))  // MD5
			algo = GCRY_MD_MD5;
		else {
			if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
				g_message("verify_user_password() : Unsupported hash algorithm\n");
			g_strfreev(splitted_secret);
			return SASL_BADAUTH;
		}


		gcry_md_open (&hd, algo,0);
		gcry_md_write(hd,given,strlen(given));

		if ((algo == GCRY_MD_SHA1) && seeded) {
			char temp[24];

			if (sasl_decode64(splitted_secret[1],strlen(splitted_secret[1]),temp,sizeof(temp),&len) != SASL_OK){
				if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN))
					g_message("sasl_decode64 failed in gcrypt.c, where seeded SHA1 is used");
				return(SASL_BADAUTH);
			}
			gcry_md_write(hd,temp+20,4);
		}
		else if ((algo == GCRY_MD_MD5) && seeded) {
			char temp[20];

			if (sasl_decode64(splitted_secret[1],strlen(splitted_secret[1]),temp,sizeof(temp),&len) != SASL_OK){
				if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN))
					g_message("sasl_decode64 failed in gcrypt.c, where seeded MD5 is used");
				return(SASL_BADAUTH);
			}
			gcry_md_write(hd,temp+16,4);
		}

		res=(char*)gcry_md_read(hd,algo);
		/* alloc decoded to reasonnable length */
		decoded = g_new0(char, 50);
		sasl_encode64(res,strlen(res),decoded,50,&len);

		/* convert password from utf-8 to locale */
		if (nuauthconf->uses_utf8){
			size_t bwritten=0;
			gchar * traduc;
			traduc = g_locale_from_utf8  (decoded,
					-1,
					NULL,
					&bwritten,
					NULL);
			if (traduc){
				g_free(decoded);	
				decoded=traduc;
			} else {
				if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
					g_message("can not convert password %s at %s:%d",decoded,__FILE__,__LINE__);
				}
			}
		}
#ifdef DEBUG_ENABLE
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
			g_message("given %s, hash %s, decoded %s, stored : %s",given,res,decoded,ours);
#endif

		if (!seeded && !strcmp(decoded,splitted_secret[1])) {
#ifdef DEBUG_ENABLE
			if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
				g_message("%s == %s\n",decoded,splitted_secret[1]);
#endif

			g_free(decoded);
			g_strfreev(splitted_secret);
			return SASL_OK;
		}
		else if (seeded && (algo == GCRY_MD_SHA1) && !memcmp(decoded,splitted_secret[1],20)) {
#ifdef DEBUG_ENABLE
			if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)) {
				char temp_decoded[21];
				char temp_stored[21];

                SECURE_STRNCPY (temp_decoded, decoded, sizeof(temp_decoded));
				SECURE_STRNCPY (temp_stored, splitted_secret[1], sizeof(temp_stored));

				g_message("%s == %s (first 20 chars)\n",temp_decoded,temp_stored);
			}
#endif

			g_strfreev(splitted_secret);
			g_free(decoded);
			return SASL_OK;
		}
		else if (seeded && (algo == GCRY_MD_MD5) && !memcmp(decoded,splitted_secret[1],16)) {
#ifdef DEBUG_ENABLE
			if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)) {
				char temp_decoded[17];
				char temp_stored[17];

                SECURE_STRNCPY(temp_decoded, decoded, sizeof(temp_decoded));
                SECURE_STRNCPY(temp_stored, decoded, sizeof(temp_stored));

				g_message("%s == %s (first 16 chars)\n", temp_decoded, temp_stored);
			}
#endif

			g_strfreev(splitted_secret);
			g_free(decoded);
			return SASL_OK;
		}
		else {
			if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)) {
				g_message("given != stored\n");
			}

			g_strfreev(splitted_secret);
			g_free(decoded);
			return SASL_BADAUTH;
		}
	} else {
		/* convert password from utf-8 to locale */
		if (nuauthconf->uses_utf8){
			size_t bwritten=0;
			gchar * traduc;
			traduc = g_locale_from_utf8  (given,
					strlen(given),
					NULL,
					&bwritten,
					NULL);
			if (traduc){
				given=traduc;
			} else {
				if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
					const char *ccharset;
					g_get_charset(&ccharset);
					g_message("Can not convert password %s to %s at %s:%d",given,
							ccharset,__FILE__,__LINE__);
				}
			}
		}
		if (!strcmp(given,ours)){
			if (nuauthconf->uses_utf8){
				g_free((char*)given);
			}
			return SASL_OK;
		}
		else {
			if (nuauthconf->uses_utf8){
				g_free((char*)given);
			}
			return SASL_BADAUTH;
		}
	}
}

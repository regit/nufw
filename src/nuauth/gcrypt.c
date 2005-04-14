/*
 ** Copyright(C) 2004 Eric Leblond <regit@inl.fr>
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
 */
#include <auth_srv.h>
#include <tls.h>
#include <gcrypt.h>
#include <sasl/saslutil.h>

/**
 * verify user password against user authentication module.
 */
int verify_user_password(const char* given,const char* ours){
    gcry_md_hd_t hd;
    char * res;
    char decoded[50]; 
    int len;
    char **splitted_secret; 
    int algo=0;

    if (g_str_has_prefix(ours,"{")){
        splitted_secret=g_strsplit    (ours, "}", 2);
        if (splitted_secret == NULL) //We received an empty string
            return SASL_BADAUTH;

        if (strncmp("{",splitted_secret[0],1)) {// Not starting with "{" means this is plaintext
            if (strcmp(given,splitted_secret[0])){
                g_strfreev(splitted_secret);
                return SASL_BADAUTH;
            }
            else {
                g_strfreev(splitted_secret);
                return SASL_OK;
            }
        }

        if (!(strcmp("{SSHA",splitted_secret[0]))) // SHA1
            algo = GCRY_MD_SHA1;
        else if (!(strcmp("{SMD5",splitted_secret[0]))) // MD5
            algo = GCRY_MD_MD5;
        else if (!(strcmp("{SHA1",splitted_secret[0]))){ // SHA1
            algo = GCRY_MD_SHA1;
        }
        else {
        	if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
            		g_message("verify_user_password() : Unsupported hash algorithm\n");
            g_strfreev(splitted_secret);
            return SASL_BADAUTH;
        }


        gcry_md_open (&hd, algo,0);
        gcry_md_write(hd,given,strlen(given));
        res=gcry_md_read(hd,algo);
        sasl_encode64(res,strlen(res),decoded,50,&len);
#ifdef DEBUG_ENABLE
        if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
            g_message("given %s, hash %s, decoded %s, stored : %s\n",given,res,decoded,ours);
#endif
        if (!strcmp(decoded,splitted_secret[1])){
            g_strfreev(splitted_secret);
            return SASL_OK;
        } else {
            g_strfreev(splitted_secret);
            return SASL_BADAUTH;
        }
    } else {
        if (!strcmp(given,ours)){
            return SASL_OK;
        } else {
            return SASL_BADAUTH;
        }

    }
}


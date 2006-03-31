/*
** Copyright(C) 2006 INL
**          written by Eric Leblond <regit@inl.fr>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; version 2 of the License.
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
#include <gnutls/x509.h>

#define DN_LENGTH 256

G_MODULE_EXPORT gboolean module_params_unload(gpointer params_p)
{
  return TRUE;
}

G_MODULE_EXPORT gboolean init_module_from_conf (module_t* module)
{
  return TRUE;
}


G_MODULE_EXPORT int certificate_check (gnutls_session* session, gnutls_x509_crt* cert,gpointer params)
{
	time_t expiration_time, activation_time;
    int size;
    char dn[DN_LENGTH];
    
	expiration_time = gnutls_x509_crt_get_expiration_time(*cert);
	activation_time = gnutls_x509_crt_get_activation_time(*cert);

    log_message(VERBOSE_DEBUG,AREA_MAIN
            , "Certificate validity starts at: %s\nCertificate expires: %s"
            , ctime(&activation_time)
            , ctime(&expiration_time));

    /* verify date */
    if (expiration_time<time(NULL)){
        log_message(INFO, AREA_MAIN, "Certificate expired at: %s", ctime(&expiration_time));
		gnutls_x509_crt_deinit( *cert);
		return SASL_EXPIRED;
	}

	if (activation_time>time(NULL)){
        log_message(INFO, AREA_MAIN, "Certificate only activates at: %s", ctime(&activation_time));
		gnutls_x509_crt_deinit( *cert);
		return SASL_DISABLED;
	}
	

/* TODO  test if we trust this Issuer */
	size = sizeof(dn);
	gnutls_x509_crt_get_issuer_dn( *cert, dn, &size);
	log_message(VERBOSE_DEBUG, AREA_USER, "\tIssuer's DN: %s", dn);


    return SASL_OK;
}

G_MODULE_EXPORT gchar* certificate_to_uid (gnutls_session* session, gnutls_x509_crt* cert,gpointer params)
{
    int size;
	char dn[DN_LENGTH];
    gchar* pointer;

	size = sizeof(dn);
	gnutls_x509_crt_get_dn( *cert, dn, &size);

	log_message(VERBOSE_DEBUG, AREA_USER, "\tDN: %s", dn);
	
	/* parse DN and extract username is there is one */
	pointer=g_strrstr_len(dn,DN_LENGTH-1,",CN=");
	if (pointer){
		char* string_end=NULL;
		pointer+=4;
		string_end=g_strrstr_len(pointer,dn-pointer,",");
		if (string_end) {
			*string_end=0;
			return g_strdup(pointer);
		}
	}

    return NULL;
}

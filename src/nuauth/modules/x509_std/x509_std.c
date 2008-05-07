/*
** Copyright(C) 2006 INL
**          written by Eric Leblond <regit@inl.fr>
**
** $Id$
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

#include "x509_std.h"

/**
 * \ingroup NuauthModules
 * \defgroup X509NuauthModules X509 Checking modules
 */

/**
 *
 * \ingroup X509NuauthModules
 * \defgroup X509STDModule X509 standard checking module
 *
 * @{ */



#define DN_LENGTH 256

/*
 * Returns version of nuauth API
 */
G_MODULE_EXPORT uint32_t get_api_version()
{
	return NUAUTH_API_VERSION;
}

G_MODULE_EXPORT gboolean unload_module_with_params(gpointer params_p)
{
	struct x509_std_params *params =
	    (struct x509_std_params *) params_p;
	/*  Free user list */
	if (params) {
		g_free(params->trusted_issuer_dn);
	}
	g_free(params);

	return TRUE;
}

G_MODULE_EXPORT gboolean init_module_from_conf(module_t * module)
{
	struct x509_std_params *params = g_new0(struct x509_std_params, 1);

	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		    "X509_std module ($Revision$)");

	/*  set variables */
	params->trusted_issuer_dn = nubase_config_table_get("nauth_tls_trusted_issuer_dn");

	module->params = (gpointer) params;

	return TRUE;

}


G_MODULE_EXPORT int certificate_check(nussl_session* session,
				      gpointer params_p)
{
#if 0
	struct x509_std_params *params =
	    (struct x509_std_params *) params_p;
	time_t expiration_time, activation_time;

	expiration_time = gnutls_x509_crt_get_expiration_time(cert);
	activation_time = gnutls_x509_crt_get_activation_time(cert);

	if (expiration_time == (time_t)-1 || activation_time == (time_t)-1) {
		log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
			    "Unable to check certificate date validity"
		    );
		return SASL_DISABLED;
	}

	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		    "Certificate validity starts at: %s",
		    ctime(&activation_time)
	    );
	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN, "Certificate expires: %s",
		    ctime(&expiration_time));

	/* verify date */
	if (expiration_time < time(NULL)) {
		log_message(INFO, DEBUG_AREA_USER, "Certificate expired at: %s",
			    ctime(&expiration_time));
		/* gnutls_x509_crt_deinit(cert); */
		return SASL_EXPIRED;
	}

	if (activation_time > time(NULL)) {
		log_message(INFO, DEBUG_AREA_USER,
			    "Certificate only activates at: %s",
			    ctime(&activation_time));
		/* gnutls_x509_crt_deinit(cert); */
		return SASL_DISABLED;
	}

	if (params->trusted_issuer_dn) {
		size_t size;
		char dn[DN_LENGTH];
		size = sizeof(dn);
		gnutls_x509_crt_get_issuer_dn(cert, dn, &size);
		if (strcmp(dn, params->trusted_issuer_dn)) {
			log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
				    "\tIssuer's DN is not trusted: %s",
				    dn);
			/* gnutls_x509_crt_deinit(cert); */
			return SASL_DISABLED;
		}
	}
#endif
	return SASL_OK;
}

G_MODULE_EXPORT gchar *certificate_to_uid(nussl_session* session,
					  gpointer params)
{
	size_t size;
	char dn[DN_LENGTH];
	gchar *pointer;

	size = sizeof(dn);
	nussl_get_peer_dn(session, dn, &size);

	log_message(VERBOSE_DEBUG, DEBUG_AREA_USER, "\tDN: %s", dn);

	/* parse DN and extract username is there is one */
	pointer = g_strrstr_len(dn, DN_LENGTH - 1, ",CN=");
	if (pointer) {
		char *string_end = NULL;
		pointer += 4;
		string_end = g_strrstr_len(pointer, (DN_LENGTH - 1 ) - (pointer - dn), ",");
		if (string_end) {
			*string_end = 0;
		}
		return g_strdup(pointer);
	}

	return NULL;
}

/** @} */

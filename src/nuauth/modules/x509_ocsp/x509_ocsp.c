/*
** Copyright(C) 2008 INL
**          written by Pierre Chifflier <chifflier@inl.fr>
**
** $Id$
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; version 3 of the License.
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

#include "x509_ocsp.h"

/**
 * \ingroup NuauthModules
 * \defgroup X509NuauthModules X509 OCSP Checking modules
 */

/**
 *
 * \ingroup X509NuauthModules
 * \defgroup X509STDModule X509 OCSP checking module
 *
 * @{ */



/*
 * Returns version of nuauth API
 */
G_MODULE_EXPORT uint32_t get_api_version()
{
	return NUAUTH_API_VERSION;
}


G_MODULE_EXPORT gboolean unload_module_with_params(gpointer params_p)
{
	struct x509_ocsp_params *params =
	    (struct x509_ocsp_params *) params_p;
	/*  Free user list */
	if (params) {
		g_free(params->ca);
		g_free(params->ocsp_server);
		g_free(params->ocsp_path);
	}
	g_free(params);

	return TRUE;
}

G_MODULE_EXPORT gboolean init_module_from_conf(module_t * module)
{
	struct x509_ocsp_params *params = g_new0(struct x509_ocsp_params, 1);

	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		    "X509_ocsp module ($Revision$)");

	/*  set variables */
	params->ca = nuauth_config_table_get("nuauth_tls_cacert");
	params->ocsp_server = nuauth_config_table_get("nuauth_tls_ocsp_server");
	params->ocsp_port = nuauth_config_table_get_or_default_int("nuauth_tls_ocsp_port", 80);
	params->ocsp_path = nuauth_config_table_get("nuauth_tls_ocsp_path");
	params->ocsp_ca_use_aia = nuauth_config_table_get_or_default_int("nuauth_tls_ocsp_ca_use_aia", 0);

	module->params = (gpointer) params;

	return TRUE;

}


G_MODULE_EXPORT int certificate_check(nussl_session* session,
				      gpointer params_p)
{
	int ret;

	ret = 0;
	if (session)
		ret = check_ocsp(session, params_p);

	return (ret == 0 ) ? SASL_OK : SASL_FAIL;
}


/** @} */


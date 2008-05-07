/*
 ** Copyright(C) 2006 INL
 ** written by Eric Leblond <regit@inl.fr>
 **
 ** $Id$
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

/**
 * \ingroup NuauthModules
 */

#define IP_AUTH_GUEST_USERNAME "guest"

struct ipauth_guest_params {
	gchar *username;
};

/*
 * Returns version of nuauth API
 */
G_MODULE_EXPORT uint32_t get_api_version()
{
	return NUAUTH_API_VERSION;
}


G_MODULE_EXPORT gchar *unload_module_with_params(gpointer params_p)
{
	struct ipauth_guest_params *params =
	    (struct ipauth_guest_params *) params_p;

	g_free(params->username);
	g_free(params);

	return NULL;
}

G_MODULE_EXPORT gboolean init_module_from_conf(module_t * module)
{
	struct ipauth_guest_params *params =
	    g_new0(struct ipauth_guest_params, 1);

	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		    "Ipauth_guest module ($Revision$)");

	params->username = nubase_config_table_get_or_default("ipauth_guest_username", IP_AUTH_GUEST_USERNAME);

	module->params = (gpointer) params;
	return TRUE;
}

/**
 * @{ */

G_MODULE_EXPORT gchar *ip_authentication(tracking_t * header,
					 struct ipauth_guest_params *
					 params)
{
	if (params->username) {
		return g_strdup(params->username);
	} else {
		return NULL;
	}
}

/** @} */

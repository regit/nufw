/*
 ** Copyright(C) 2008 INL
 **	written by Eric Leblond <regit@inl.fr>
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
 */
#include <auth_srv.h>


typedef struct {
	GSList * blacklist_groups;
	GSList * whitelist_groups;
	GSList * sasl_groups;
	GSList * ssl_groups;
} session_authtype_config_t;

/*
 * Returns version of nuauth API
 */
G_MODULE_EXPORT uint32_t get_api_version()
{
	return NUAUTH_API_VERSION;
}

G_MODULE_EXPORT gboolean unload_module_with_params(gpointer params_p)
{
	return TRUE;
}

static GSList * parse_group_list(gchar *string)
{
	gchar **groups_list;
	gchar **groups_item;
	uint32_t group_id;
	GSList *result = NULL;

	if (! string) {
		RETURN_NO_LOG NULL;
	}
	groups_list = g_strsplit(string, ",", 0);
	groups_item = groups_list;
	while (*groups_item) {
		/* read group */
		if (!str_to_uint32(*groups_item, &group_id)) {
			log_message(WARNING, DEBUG_AREA_MAIN,
					"session_authtype: Invalid group identifier (%s)",
					*groups_item);
			break;
		}
		result = g_slist_append(result, GUINT_TO_POINTER(group_id));
		groups_item++;
	}
	g_strfreev(groups_list);

	return result;
}

G_MODULE_EXPORT gboolean init_module_from_conf(module_t * module)
{

	session_authtype_config_t *config = g_new0(session_authtype_config_t, 1);
	gchar *result = NULL;

	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		    "Session_authtype module ($Revision$)");
	result = nubase_config_table_get("session_authtype_blacklist_groups");
	config->blacklist_groups = parse_group_list(result);

	result = nubase_config_table_get("session_authtype_whitelist_groups");
	config->whitelist_groups = parse_group_list(result);

	result = nubase_config_table_get("session_authtype_sasl_groups");
	config->sasl_groups = parse_group_list(result);

	result = nubase_config_table_get("session_authtype_ssl_groups");
	config->ssl_groups = parse_group_list(result);

	/* store config and exit */
	module->params = config;
	return TRUE;
}


static gboolean groups_intersect(GSList * a, GSList * b)
{
	GSList *iter;
	if (a && b)  {
		for (iter = a; iter != NULL; iter = iter->next) {
			/* group in one of the b groups */
			if (g_slist_find(b, iter->data)) {
				return TRUE;
			}
		}
	}
	return FALSE;
}

G_MODULE_EXPORT int user_session_modify(user_session_t * session,
					gpointer params)
{
	session_authtype_config_t *config = params;
	/* check if user has the right to use NuFW */
	if (config->blacklist_groups && groups_intersect(session->groups, config->blacklist_groups)) {
		log_message(INFO, DEBUG_AREA_USER,
			    "User %s is in user blacklist: not allowed to connect",
			    session->user_name);
		return SASL_FAIL;
	}
	if (config->whitelist_groups && (! groups_intersect(session->groups, config->whitelist_groups))) {
		log_message(INFO, DEBUG_AREA_USER,
			    "User %s is not in user whitelist: not allowed to connect",
			    session->user_name);
		return SASL_FAIL;
	}

	switch (session->auth_type) {
		case AUTH_TYPE_INTERNAL:
			/* no filtering on SASL asked */
			if (config->sasl_groups == NULL) {
				RETURN_NO_LOG SASL_OK;
			}
			/* check if user has the right to use SASL auth */
			if (groups_intersect(session->groups, config->sasl_groups)) {
				RETURN_NO_LOG SASL_OK;
			} else {
				log_message(INFO, DEBUG_AREA_USER,
					    "User %s is not in SASL list: not allowed to connect",
					    session->user_name);
			}
			break;
		case AUTH_TYPE_EXTERNAL:
			/* no filtering on ssl asked */
			if (config->ssl_groups == NULL) {
				RETURN_NO_LOG SASL_OK;
			}
			/* check if user has the right to use SSL auth */
			if (groups_intersect(session->groups, config->ssl_groups)) {
				RETURN_NO_LOG SASL_OK;
			} else {
				log_message(INFO, DEBUG_AREA_USER,
					    "User %s is not in SSL list: not allowed to connect",
					    session->user_name);
			}
			break;
		default:
			log_message(WARNING, DEBUG_AREA_MAIN,
				    "Should not be there");
	}
	/* check us*/
	return SASL_FAIL;
}

/*
 ** Copyright(C) 2010 EdenWall Technologies
 ** written by Eric Leblond <eleblond@edenwall.com>
 **            Pierre Chifflier <chifflier@edenwall.com>
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
#include <auth_nnd.h>

#include <sys/un.h>

/**
 * \ingroup AuthNuauthModules
 * \defgroup NNDModule NND based authentication module
 *
 * @{ */

/**
 * \file nnd.c
 *
 * \brief Core file for nnd module
 *
 */

#define UNIX_MAX_PATH 108

/*
 * Returns version of nuauth API
 */
G_MODULE_EXPORT uint32_t get_api_version()
{
	return NUAUTH_API_VERSION;
}

/* Init module system */
G_MODULE_EXPORT gchar *g_module_check_init(GModule * module)
{
	return NULL;
}


static int nnd_open_socket(struct nnd_params *params)
{
	struct sockaddr_un remote;
	socklen_t len;
	int s;
	int ret;

	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		"Trying to connect to unix socket: %s", params->nnd_socket);

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				"Couldn't create socket");
		return -1;
	}

	remote.sun_family = AF_UNIX;
	strncpy(remote.sun_path, params->nnd_socket, UNIX_MAX_PATH-1);
	len = strlen(remote.sun_path) + sizeof(remote.sun_family);
	ret = connect(s, (struct sockaddr *)&remote, len);
	if (ret < 0) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				"Couldn't connect to unix socket");
		return -1;
	}

	return s;
}


G_MODULE_EXPORT uint32_t get_user_id(const char *username, gpointer params)
{
	/* FIXME something real will be great here */
	return 1;
}

G_MODULE_EXPORT GSList *get_user_groups(const char *username,
					gpointer pparams)
{

	int ret, len;
	int socket;
	char buffer[1024];
	GSList *userlist = NULL;
	gchar **groups_list;
	gchar **groups_list_item;
	struct nnd_params *params = pparams;

	memset(buffer, 0, sizeof(buffer));
	/* open socket for rw if needed */
	socket = GPOINTER_TO_INT(g_private_get(params->nnd_priv));
	if (socket == 0) {
		socket = nnd_open_socket(params);
		if (socket < 0) {
			return NULL;
		} else {
			g_private_set(params->nnd_priv,
				      GINT_TO_POINTER(socket));
		}
	}
	/* Write message to socket
	 *	"grouplist  USERNAME"
	 * */
	log_message(INFO, DEBUG_AREA_MAIN,
		    "writing command: \"grouplist %s\"", username);
	len = snprintf(buffer, 512, "grouplist %s\n", username);
	if (len < 0) {
		return NULL;
	}

	ret = write(socket, buffer, len);
	if (ret < 0) {
		log_message(INFO, DEBUG_AREA_MAIN,
				"Unable to write to nnd daemon socket");
		close(socket);
		g_private_set(params->nnd_priv, NULL);
		/* Try to reopen it */
		socket = nnd_open_socket(params);
		if (socket < 0) {
			return NULL;
		} else {
			ret = write(socket, buffer, len);
			if (ret < 0) {
				log_message(INFO, DEBUG_AREA_MAIN,
					    "Unable to write to nnd daemon after reconnect");
				close(socket);
				return NULL;
			}
			g_private_set(params->nnd_priv,
				      GINT_TO_POINTER(socket));
		}
	}

	debug_log_message(INFO, DEBUG_AREA_MAIN,
		    "Reading from nnd daemon socket");
	/* read result */
	memset(buffer, 0, sizeof(buffer));
	ret = read(socket, buffer, sizeof(buffer));
	if (ret <= 0) {
		log_message(INFO, DEBUG_AREA_MAIN,
			    "Unable to read from nnd daemon socket");
		close(socket);
		g_private_set(params->nnd_priv, NULL);
		return NULL;
	}

	debug_log_message(INFO, DEBUG_AREA_MAIN,
		          "Read %ld bytes from nnd daemon socket: \"%s\"",
			  strlen(buffer),
			  buffer);
	/* parse result */
	buffer[strlen(buffer) - 1] = 0;
	/* search for 200 code */
	if (strncmp("200", buffer, 3)) {
		log_message(INFO, DEBUG_AREA_MAIN,
			    "Unable to get user from nnd daemon socket");
		return NULL;
	}
	groups_list = g_strsplit(buffer + strlen("200 "), ",", 0);
	if (groups_list == NULL) {
		return NULL;
	}
	groups_list_item = groups_list;
	for (groups_list_item = groups_list;
	     groups_list_item != NULL && *groups_list_item != NULL;
	     groups_list_item++) {
		userlist = g_slist_append(userlist,
					  g_strdup(*groups_list_item));
		debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		          "Adding group: \"%s\"",
			  *groups_list_item);
	}
	g_strfreev(groups_list);
	return userlist;
}

G_MODULE_EXPORT int user_check(const char *username,
			       const char *clientpass, unsigned passlen,
			       user_session_t *session,
			       gpointer pparams)
{
	int socket, len, ret;
	char buffer[1024];
	struct nnd_params *params = pparams;

	memset(buffer, 0, sizeof(buffer));
	/* open socket for rw if needed */
	socket = GPOINTER_TO_INT(g_private_get(params->nnd_priv));
	if (socket == 0) {
		socket = nnd_open_socket(params);
		if (socket < 0) {
			return SASL_FAIL;
		} else {
			g_private_set(params->nnd_priv,
				      GINT_TO_POINTER(socket));
		}
	}
	/* Write message to socket
	 *	"auth  USERNAME"
	 * */
	log_message(DEBUG, DEBUG_AREA_MAIN,
		    "writing command: \"auth %s\"", username);
	len = snprintf(buffer, 512, "auth %s\n%s\n", username, clientpass);
	if (len < 0) {
		return SASL_FAIL;
	}

	ret = write(socket, buffer, len);
	if (ret < 0) {
		log_message(INFO, DEBUG_AREA_MAIN,
				"Unable to write to nnd daemon socket");
		close(socket);
		g_private_set(params->nnd_priv, NULL);
		/* Try to reopen it */
		socket = nnd_open_socket(params);
		if (socket < 0) {
			return SASL_FAIL;
		} else {
			ret = write(socket, buffer, len);
			if (ret < 0) {
				log_message(INFO, DEBUG_AREA_MAIN,
					    "Unable to write to nnd daemon after reconnect");
				close(socket);
				return SASL_FAIL;
			}
			g_private_set(params->nnd_priv,
				      GINT_TO_POINTER(socket));
		}
	}

	debug_log_message(INFO, DEBUG_AREA_MAIN,
		    "Reading from nnd daemon socket");
	/* read result */
	memset(buffer, 0, sizeof(buffer));
	ret = read(socket, buffer, sizeof(buffer));
	if (ret <= 0) {
		log_message(INFO, DEBUG_AREA_MAIN,
			    "Unable to read from nnd daemon socket");
		close(socket);
		g_private_set(params->nnd_priv, NULL);
		return SASL_FAIL;
	}

	debug_log_message(INFO, DEBUG_AREA_MAIN,
		          "Read %ld bytes from nnd daemon socket: \"%s\"",
			  strlen(buffer),
			  buffer);
	/* parse result */
	buffer[strlen(buffer) - 1] = 0;
	/* search for 200 code */
	if (! strncmp("200", buffer, 3)) {
		log_message(DEBUG, DEBUG_AREA_MAIN,
			    "Authentification successful for user \"%s\"", username);
		return SASL_OK;
	} else if (! strncmp("400", buffer, 3)) {
		log_message(DEBUG, DEBUG_AREA_MAIN,
			    "Authentification failure for user \"%s\"", username);
		return SASL_BADAUTH;
	} else {
		log_message(WARNING, DEBUG_AREA_MAIN,
			    "Unknown return code during \"%s\" authentication", username);
		return SASL_BADAUTH;
	}

	debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
			  "We are leaving (nnd) user_check()");

	return SASL_OK;
}

G_MODULE_EXPORT gboolean unload_module_with_params(gpointer params_p)
{
	struct nnd_params *params = (struct nnd_params *) params_p;
	if (params) {
		g_free(params->nnd_socket);
	}
	g_free(params);
	return TRUE;
}

G_MODULE_EXPORT gboolean init_module_from_conf(module_t * module)
{
	struct nnd_params *params = g_new0(struct nnd_params, 1);
	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		    "NuFW NSS Daemon module");

	if (nuauthconf->use_groups_name == 0) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				"The NND module requires nuauth_use_groups_name=1\nSetting value automatically.");
		nuauthconf->use_groups_name = 1;
	}

	params->nnd_socket = nuauth_config_table_get_or_default("nuauth_nnd_socket_path", NND_SOCKET_PATH);
	/* init thread private stuff */
	params->nnd_priv = g_private_new((GDestroyNotify) close);

	module->params = params;
	return TRUE;
}

/** @} */

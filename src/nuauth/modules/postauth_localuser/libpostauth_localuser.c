/*
 ** Copyright(C) 2009 INL
 ** written by Eric Leblond <eleblond@inl.fr>
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

#include "nuauthconf.h"
#include <sasl/sasl.h>
#include <sasl/saslutil.h>

/**
 * \ingroup NuauthModules
 */

#define LUSER_EXT_NAME "LUSER"
#define LUSER_USER_CMD "LOCALUSER"
#define POSTAUTH_DEFAULT_USERNAME "unknown"

struct postauth_localuser_params {
	gchar *username;
	int capa_index;
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
	struct postauth_localuser_params *params =
	    (struct postauth_localuser_params *) params_p;

	g_free(params->username);
	g_free(params);

	return NULL;
}

G_MODULE_EXPORT gboolean init_module_from_conf(module_t * module)
{
	struct postauth_localuser_params *params =
	    g_new0(struct postauth_localuser_params, 1);

	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		    "Postauth_localuser module");

	params->username = nuauth_config_table_get_or_default("postauth_localuser_default_username", POSTAUTH_DEFAULT_USERNAME);


	if (register_client_capa(LUSER_EXT_NAME, &(params->capa_index)) != NU_EXIT_OK) {
		log_message(WARNING, DEBUG_AREA_MAIN,
			    "Unable to register capability LUSER");
		return FALSE;
	}

	module->params = (gpointer) params;
	return TRUE;
}

static int process_field(int field_buffer_len,
			   char * buf,
			   char **username)
{
	char pbuf[1024];
	char *lbuf = buf;
	int state = EXT_PROTO_OUTSIDE;

	*username = NULL;
	do {
		sscanf(lbuf,"%s", pbuf);
		switch (state) {
			case EXT_PROTO_OUTSIDE:
				/* should find "BEGIN" */
				if (! strcmp(pbuf, "BEGIN")) {
					state = EXT_PROTO_START;
				}
				break;
			case EXT_PROTO_START:
				if (! strcmp(pbuf, LUSER_EXT_NAME)) {
					state = EXT_PROTO_CMD;
				}
				break;
			case EXT_PROTO_CMD:
				if (! strcmp(pbuf, "END")) {
					state = EXT_PROTO_OUTSIDE;
				}
				if (! strcmp(pbuf, LUSER_USER_CMD)) {
					state = EXT_PROTO_CMD_ARGS;
				}
				break;
			case EXT_PROTO_CMD_ARGS:
				if (*username) {
					g_free(*username);
					*username = NULL;
				}
				*username = g_strdup(pbuf);
				state = EXT_PROTO_CMD;
				break;
		}
		lbuf += strlen(pbuf) + 1;

	} while (lbuf < buf + field_buffer_len);

	if (*username) {
		return SASL_OK;
	} else {
		return SASL_FAIL;
	}
}

/**
 * @{ */

G_MODULE_EXPORT int postauth_proto(user_session_t * session, struct postauth_localuser_params * params)
{
	struct nu_srv_message *msg;
	char buf[8192];
	char *content;
	int buf_size, ret;
	char * username;
	char address[INET6_ADDRSTRLEN];


	if (session->capa_flags & (1 << params->capa_index)) {
		debug_log_message(WARNING, DEBUG_AREA_USER,
				"Asking remote username to user");
		msg = (struct nu_srv_message *) buf;
		/* ask OS to client */
		msg->type = SRV_EXTENDED_PROTO;
		msg->option = CLIENT_SRV;
		content = buf + sizeof(*msg);
		ret = snprintf(content, sizeof(buf) - sizeof(*msg),
				"BEGIN\n" LUSER_EXT_NAME "\n" LUSER_USER_CMD "\nEND\n");
		msg->length = htons(sizeof(*msg) + ret);
		if (nussl_write(session->nussl, buf, sizeof(*msg) + ret) < 0) {
			log_message(WARNING, DEBUG_AREA_USER,
					"nussl_write() failure at %s:%d",
					__FILE__, __LINE__);
			if (nuauthconf->push) {
				clean_session(session);
				return SASL_FAIL;
			} else {
				return SASL_FAIL;
			}
		}

		buf_size = nussl_read(session->nussl, buf, sizeof buf);
		/* FIXME add test on type of field */
		ret = process_field(buf_size - sizeof(struct nu_authfield),
				    buf + sizeof(struct nu_authfield),
				    &username);
		if (ret != SASL_OK)
			return ret;

		format_ipv6(&session->addr, address, INET6_ADDRSTRLEN, NULL);
		log_message(DEBUG, DEBUG_AREA_USER, "User \"%s\" at %s seems to be \"%s\" remotely",
				session->user_name,
				address,
				username);
		g_free(username);
	} else {
		format_ipv6(&session->addr, address, INET6_ADDRSTRLEN, NULL);
		log_message(DEBUG, DEBUG_AREA_USER, "User \"%s\" at %s does not support local user announce",
				session->user_name,
				address);
	}
	return SASL_OK;
}

/** @} */

/*
 ** Copyright(C) 2008-2009 INL
 ** Written by  Pierre Chifflier <chifflier@inl.fr>
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
#include <string.h>
#include <errno.h>

#include <inttypes.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "log_ulogd2.h"

#include "security.h"

/**
 * \ingroup LoggingNuauthModules
 * \defgroup Ulogd2Module Ulogd2 logging module
 *
 * @{ */

static int _connect_ulogd2_socket(struct log_ulogd2_params *params);

/*
 * Returns version of nuauth API
 */
G_MODULE_EXPORT uint32_t get_api_version()
{
	return NUAUTH_API_VERSION;
}


static ssize_t _ulogd2_write(struct log_ulogd2_params *params, const void *data, size_t count)
{
	ssize_t sz;
	int ret;
	unsigned int retry_count = 0;
	unsigned int max_retry_count = 1;

	if (params->fd < 0) {
		ret = _connect_ulogd2_socket(params);
		if (ret < 0) {
			return -1;
		}
		log_message(DEBUG, DEBUG_AREA_MAIN,
				"ulogd2: reconnection successful");
	}

	do {
		sz = write(params->fd, data, count);
		if (sz <= 0) {
			if (errno == EPIPE) {
				retry_count++;
				ret = _connect_ulogd2_socket(params);
				if (ret >= 0) {
					log_message(DEBUG, DEBUG_AREA_MAIN,
							"ulogd2: reconnection successful");
				}
			} else
				break;
		}
	} while (sz <= 0 && retry_count <= max_retry_count);

	if (sz <= 0) {
		log_message(DEBUG, DEBUG_AREA_MAIN,
				"ulogd2: write() failed: %s (%d)",
				strerror(errno), errno);
		return -1;
	}

	return sz;
}

static ssize_t ulogd2_send_request(struct log_ulogd2_params *params, struct ulogd2_request*req)
{
	unsigned char buf[1024];
	int ret;

	ret = ulogd2_request_format(req, buf, sizeof(buf));
	if (ret < 0) {
		log_message(WARNING, DEBUG_AREA_MAIN, "ulogd2: unable to format request");
		return -1;
	}

	ret = _ulogd2_write(params, buf, ret);
	return ret;
}

G_MODULE_EXPORT gint user_packet_logs(void *element, tcp_state_t state,
				      gpointer params_p)
{
	struct log_ulogd2_params *params = (struct log_ulogd2_params*)params_p;
	char *str_state;
	const connection_t *connection = element;
	struct ulogd2_request *req;
	u_int32_t u_time_sec;
	u_int8_t u_state;

	/* contruct request */
	switch (state) {
	case TCP_STATE_OPEN:
		str_state = "Open ";
		break;
	case TCP_STATE_CLOSE:
		str_state = "Close ";
		break;
	case TCP_STATE_ESTABLISHED:
		str_state = "Established ";
		break;
	case TCP_STATE_DROP:
		str_state = "Drop ";
		break;
	default:
		str_state = "Unknown ";
	}

	if (connection->payload_len > sizeof(connection->payload)) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				"ulogd2: invalid payload len %d, ignoring packet !",
				connection->payload_len);
		return 0;
	}

	req = ulogd2_request_new();
	if (req == NULL) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				"ulogd2: unable to allocate request");
		return 0;
	}

	ulogd2_request_set_payload(req, (unsigned char*)connection->payload, connection->payload_len);

	if (connection->log_prefix) {
		gchar *place;
		place = strchr(connection->log_prefix, '?');
		if (place) {
			switch (state) {
				case TCP_STATE_OPEN:
					*place = 'A';
					break;
				case TCP_STATE_DROP:
					*place = 'D';
					break;
				case TCP_STATE_ESTABLISHED:
				case TCP_STATE_CLOSE:
				default:
					break;
			}
		}
		ulogd2_request_add_option(req, ULOGD2_OPT_PREFIX,
				connection->log_prefix, strlen(connection->log_prefix));
	} else {
		ulogd2_request_add_option(req, ULOGD2_OPT_PREFIX,
				str_state, strlen(str_state));
	}

	u_state = (u_int8_t)state;
	ulogd2_request_add_option(req, ULOGD2_OPT_STATE,
			(void*)&u_state,
			sizeof(u_int8_t));

	/* this will work until 2038 */
	u_time_sec = (u_int32_t)connection->timestamp;
	ulogd2_request_add_option(req, ULOGD2_OPT_OOB_TIME_SEC,
			(void*)&u_time_sec,
			sizeof(u_int32_t));

	if (connection->iface_nfo.indev[0] != '\0') {
		ulogd2_request_add_option(req, ULOGD2_OPT_OOB_IN,
				(void*)connection->iface_nfo.indev,
				strlen(connection->iface_nfo.indev));
	}
	if (connection->iface_nfo.outdev[0] != '\0') {
		ulogd2_request_add_option(req, ULOGD2_OPT_OOB_OUT,
				(void*)connection->iface_nfo.outdev,
				strlen(connection->iface_nfo.outdev));
	}

	if (connection->username)
		ulogd2_request_add_option(req, ULOGD2_OPT_USER,
				connection->username,
				strlen(connection->username));
	if (connection->user_id)
		ulogd2_request_add_option(req, ULOGD2_OPT_USERID,
				(void*)&connection->user_id,
				sizeof(u_int32_t));
	if (connection->os_sysname)
		ulogd2_request_add_option(req, ULOGD2_OPT_OSNAME,
				connection->os_sysname,
				strlen(connection->os_sysname));
	if (connection->os_release)
		ulogd2_request_add_option(req, ULOGD2_OPT_OSREL,
				connection->os_release,
				strlen(connection->os_release));
	if (connection->os_version)
		ulogd2_request_add_option(req, ULOGD2_OPT_OSVERS,
				connection->os_version,
				strlen(connection->os_version));
	if (connection->app_name)
		ulogd2_request_add_option(req, ULOGD2_OPT_APPNAME,
				connection->app_name,
				strlen(connection->app_name));

	ulogd2_send_request(params, req);

	ulogd2_request_free(req);

	return 0;
}

G_MODULE_EXPORT gboolean init_module_from_conf(module_t * module)
{
	struct log_ulogd2_params * params = g_new0(struct log_ulogd2_params, 1);
	int ret;

	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		    "Log_ulogd2 module ($Revision$)");

	module->params = (gpointer) params;

	params->path = nuauth_config_table_get_or_default("ulogd2_socket", DEFAULT_ULOGD2_SOCKET);
	params->fd = -1;

	ret = _connect_ulogd2_socket(params);

	return TRUE;
}

G_MODULE_EXPORT gboolean unload_module_with_params(gpointer params_p)
{
	return TRUE;
}


static int _connect_ulogd2_socket(struct log_ulogd2_params *params)
{
	const char *socket_location = params->path;
	struct sockaddr_un server_sock;
	int s;
	socklen_t len;
	int ret;

	if (params->fd >= 0) {
		close(params->fd);
		params->fd = -1;
	}

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0)
		return -1;

	server_sock.sun_family = AF_UNIX;  /* server_sock is declared before socket() ^ */
	strncpy(server_sock.sun_path, socket_location, sizeof(server_sock.sun_path)-1);
	len = strlen(server_sock.sun_path) + sizeof(server_sock.sun_family);

	ret = connect(s, (struct sockaddr *)&server_sock, len);
	if (ret < 0) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				"ulogd2: could not connect to unix socket \'%s\'",
				server_sock.sun_path);
		close(s);
		return -1;
	}

	params->fd = s;

	return s;
}

/** @} */

/*
 ** Copyright(C) 2003-2008 INL
 ** Written by Eric Leblond <regit@inl.fr>
 **            Vincent Deffontaines <vincent@gryzor.com>
 **     INL : http://www.inl.fr/
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

#include "auth_srv.h"
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <ctype.h>         /* isspace() */

#include <nubase.h>

/* See <sys/un.h for details, value is hardcoded */
#define UNIX_MAX_PATH 108

/**
 * \ingroup Nuauth
 * \defgroup NuauthCore Nuauth Core
 * \brief This is the main part of nuauth, real core is search_and_fill().
 * \author Éric Leblond
 *
 * The main functions are :
 *  - search_and_fill() : used to aggregate dates coming from nufw and clients
 *  - take_decision() : decide on packet based on policy coming from module
 *
 * @{
 *
 */

/** \file auth_common.c
 *  \brief Core functions of NuAuth, contain search_and_fill() .
 */

#ifdef PERF_DISPLAY_ENABLE
/* Subtract the `struct timeval' values X and Y,
 *         storing the result in RESULT.
 *                 Return 1 if the difference is negative, otherwise 0.  */

int timeval_substract(struct timeval *result, struct timeval *x,
		      struct timeval *y)
{
	/* Perform the carry for the later subtraction by updating y. */
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	 *           tv_usec is certainly positive. */
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;

	/* Return 1 if result is negative. */
	return x->tv_sec < y->tv_sec;
}
#endif

/**
 * Suppress domain from "user\@domain" string (returns "user").
 *
 * \return Username which need to be freed
 */
char *get_rid_of_domain(const char *user_domain)
{
	char *username = NULL;
	char **user_realm;
	user_realm = g_strsplit(user_domain, "@", 2);
	if (user_realm[0] != NULL) {
		username = g_strdup(user_realm[0]);
	} else {
		username = g_strdup(user_domain);
	}
	g_strfreev(user_realm);
	return username;
}

/**
 * Suppress domain from "DOMAIN\user" string (returns "user").
 *
 * \return Username which need to be freed
 */
char *get_rid_of_prefix_domain(const char *user_domain)
{
	char *username = NULL;
	char **user_realm;
	user_realm = g_strsplit(user_domain, "\\", 2);
	if (user_realm[0] && user_realm[1]) {
		username = g_strdup(user_realm[1]);
	} else {
		username = g_strdup(user_domain);
	}
	g_strfreev(user_realm);
	return username;
}

/**
 * Free a ::tls_buffer_read buffer and all of its memory.
 */
void free_buffer_read(struct tls_buffer_read *datas)
{
	g_free(datas->os_sysname);
	g_free(datas->os_release);
	g_free(datas->os_version);
	g_free(datas->buffer);
	g_free(datas->user_name);
	if (datas->groups != NULL) {
		g_slist_free(datas->groups);
	}
	g_free(datas);
}

/**
 * Check Protocol version agains supported one
 *
 * \param type An ::proto_type_t used to select if we need to check against nufw or client supported protocols
 * \param version A integer coding protocol version to test
 * \return a ::nu_error_t
 */

nu_error_t check_protocol_version(enum proto_type_t type, int version)
{
	switch (type) {
		case NUFW_PROTO:
			switch (version) {
				case PROTO_VERSION_NUFW_V20:
					return NU_EXIT_OK;
				case PROTO_VERSION_NUFW_V22:
					log_message(CRITICAL, DEBUG_AREA_PACKET | DEBUG_AREA_GW,
							"nufw server runs pre 2.2.2 protocol: please upgrade");
					return NU_EXIT_ERROR;
				case PROTO_VERSION_NUFW_V22_2:
					return NU_EXIT_OK;
				default:
					log_message(CRITICAL,
						    DEBUG_AREA_PACKET | DEBUG_AREA_GW,
						    "NUFW protocol is unknown");
					return NU_EXIT_ERROR;
			}
			break;
		case CLIENT_PROTO:
			switch (version) {
				case PROTO_VERSION_V20:
					return NU_EXIT_OK;
				case PROTO_VERSION_V22:
					return NU_EXIT_OK;
				default:
					log_message(CRITICAL,
						    DEBUG_AREA_PACKET | DEBUG_AREA_GW,
						    "Client protocol is unknown");
					return NU_EXIT_ERROR;
			}
			break;
		default:
			return NU_EXIT_ERROR;
	}
	return NU_EXIT_ERROR;
}

/**
 * Convert an integer to a string.
 * Return NULL on error, new allocated string otherwise.
 */
char* int_to_str(int value)
{
	return g_strdup_printf("%i", value);
}

/**
 * Wrapper to g_thread_pool_push(): block on server reload.
 */
void thread_pool_push(GThreadPool *pool, gpointer data, GError **error)
{
	block_on_conf_reload();
	g_thread_pool_push(pool, data, error);
}

int nuauth_bind(char **errmsg, const char *addr, const char *port, char *context)
{
	struct addrinfo *res;
	struct addrinfo hints;
	int ecode;
	int sck_inet;
	gint option_value;
	int result;

	memset(&hints, 0, sizeof hints);
	hints.ai_flags = AI_PASSIVE;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = PF_UNSPEC;

	ecode = getaddrinfo(addr, port,
			&hints, &res);
	if (ecode != 0) {
		*errmsg =
		    g_strdup_printf
		    ("Invalid %s listening address %s:%s, error: %s",
		     context,
		     addr, port,
		     gai_strerror(ecode));
		return -1;
	}

	/* open the socket */
	if (res->ai_family == PF_INET)
		log_message(DEBUG, DEBUG_AREA_USER | DEBUG_AREA_MAIN,
			    "Creating server IPv4 socket (%s:%s)",
			    addr,
			    port);
	else if (res->ai_family == PF_INET6)
		log_message(DEBUG, DEBUG_AREA_USER | DEBUG_AREA_MAIN,
			    "Creating server IPv6 socket ([%s]:%s)",
			    addr,
			    port);
	else
		log_message(DEBUG, DEBUG_AREA_USER | DEBUG_AREA_MAIN,
			    "Creating server (any) socket");

	sck_inet = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sck_inet == -1) {
		*errmsg = g_strdup("Socket creation failed.");
		return -1;
	}

	/* set socket reuse and keep alive option */
	option_value = 1;
	setsockopt(sck_inet,
		   SOL_SOCKET,
		   SO_REUSEADDR, &option_value, sizeof(option_value));
	setsockopt(sck_inet,
		   SOL_SOCKET,
		   SO_KEEPALIVE, &option_value, sizeof(option_value));

	/* bind */
	result = bind(sck_inet, res->ai_addr, res->ai_addrlen);
	if (result < 0) {
		*errmsg = g_strdup_printf("Unable to bind %s socket %s:%s.",
					  context,
					  addr,
					  port);
		close(sck_inet);
		return -1;
	}
	freeaddrinfo(res);
	return sck_inet;
}

int nuauth_bind_unix(char **errmsg, const char *unix_path)
{
	struct sockaddr_un s_addr;
	int sck_unix;
	socklen_t len;

	log_message(DEBUG, DEBUG_AREA_USER | DEBUG_AREA_MAIN,
		    "Creating server (unix socket) on %s", unix_path);

	sck_unix = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sck_unix == -1) {
		*errmsg = g_strdup("Socket creation failed.");
		return -1;
	}

	s_addr.sun_family = AF_UNIX;
	strncpy(s_addr.sun_path, unix_path, UNIX_MAX_PATH-1);
	/* ignore errors, socket may not exist */
	unlink(s_addr.sun_path);
	len = strlen(s_addr.sun_path) + sizeof(s_addr.sun_family);
	if (bind(sck_unix, (struct sockaddr *)&s_addr, len) == -1) {
		*errmsg = g_strdup_printf("Unable to bind socket to %s.",
					  unix_path);
		close(sck_unix);
		return -1;
	}

	return sck_unix;
}

/**
 * Parse "[ipv6]:port", "[ipv6]", "ipv4:port" or "ipv4" string
 */
int parse_addr_port(
	const char *text, const char* default_port,
	char **addr, char **port)
{
	char *pos;
	if (text[0] == '[') {
		pos = strchr(text+1, ']');
	} else {
		pos = NULL;
	}
	if (pos) {
		size_t len = pos - text - 1;
		if (*(pos+1) && *(pos+1) != ':') {
			/* eg. "[ipv6]port", invalid syntax */
			return 0;
		}
		if (*(pos+1) == ':') {
			if (!strlen(pos+2)) {
				/* eg. "[ipv6]:", missing port */
				return 0;
			}
			*port = g_strdup(pos+2);
		} else {
			*port = g_strdup(default_port);
		}
		*addr = g_strndup(text+1, len);
	} else {
		char **context_datas = g_strsplit(text, ":", 2);
		if (!context_datas[0]) {
			g_strfreev(context_datas);
			return 0;
		}
		*addr = g_strdup(context_datas[0]);
		if (context_datas[1]) {
			*port = g_strdup(context_datas[1]);
		} else {
			*port = g_strdup(default_port);
		}
		g_strfreev(context_datas);
	}
	return 1;
}

/** @} */

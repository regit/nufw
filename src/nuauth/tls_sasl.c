/*
 ** Copyright(C) 2004,2005,2006,2007 INL
 ** Written by  Eric Leblond <regit@inl.fr>
 **             Vincent Deffontaines <gryzor@inl.fr>
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
 **
 */

#include "auth_srv.h"
#include "tls.h"

#include <nubase.h>
#include <nussl.h>

/**
 * \addtogroup TLSUser
 * @{
 */

/**
 * \file tls_sasl.c
 * \brief Handle phase after authentication and till client is active
 *
 * It also handle preclient list to be able to disconnect user if authentication take too long.
 */

struct nuauth_tls_t nuauth_tls;

static void policy_refuse_user(user_session_t * c_session, int c,
			       policy_refused_reason_t reason)
{
	switch (reason) {
	case PER_USER_TOO_MANY_LOGINS:
		log_message(INFO, DEBUG_AREA_USER,
			    "Policy: User %s already connected too many times, closing socket",
			    c_session->user_name);
		break;
	case PER_IP_TOO_MANY_LOGINS:
		log_message(INFO, DEBUG_AREA_USER,
			    "Policy: User %s trying to connect from already overused IP, closing socket",
			    c_session->user_name);
		break;
	default:
		log_message(WARNING, DEBUG_AREA_USER,
			    "Policy: User %s has to disconnect for UNKNOWN reason, closing socket",
			    c_session->user_name);
	}
	/* get rid of client */
	clean_session(c_session);
}


static void tls_sasl_connect_ok(user_session_t * c_session, int c)
{
	struct nu_srv_message msg;
	/* Success place */

	if (nuauthconf->log_users_without_realm) {
		gchar *username = get_rid_of_domain(c_session->user_name);
		g_free(c_session->user_name);
		c_session->user_name = username;
	}

	if (nuauthconf->single_user_client_limit > 0) {
		if (!test_username_count_vs_max(c_session->user_name,
				   nuauthconf->single_user_client_limit)) {
			policy_refuse_user(c_session, c, PER_USER_TOO_MANY_LOGINS);
			return;
		}
	}

	/* unlock hash client */
	msg.type = SRV_TYPE;
	if (nuauthconf->push) {
		msg.option = SRV_TYPE_PUSH;
	} else {
		msg.option = SRV_TYPE_POLL;
	}
	msg.length = 0;
	/* send mode to client */
	if (nussl_write(c_session->nussl, (char*)&msg, sizeof(msg)) < 0) {
		log_message(WARNING, DEBUG_AREA_USER,
			    "nussl_write() failure at %s:%d",
			    __FILE__, __LINE__);
		if (nuauthconf->push) {
			clean_session(c_session);
			return;
		} else {
			return;
		}
	}

	if (nuauthconf->push) {
		struct internal_message *message =
		    g_new0(struct internal_message, 1);
		struct tls_insert_data *datas =
		    g_new0(struct tls_insert_data, 1);
		if ((message == NULL) || (datas == NULL)) {
			clean_session(c_session);
			return;
		}
		datas->socket = c;
		datas->data = c_session;
		c_session->activated = FALSE;
		message->datas = datas;
		message->type = INSERT_MESSAGE;
		g_async_queue_push(nuauthdatas->tls_push_queue, message);
	} else {
		add_client(c, c_session);
	}

	c_session->connect_timestamp = time(NULL);
	/* send new valid session to user session logging system */
	log_user_session(c_session, SESSION_OPEN);
	debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
			  "Says we need to work on %d", c);
	g_async_queue_push(mx_queue, GINT_TO_POINTER(c));
}

/**
 * \brief Complete all user connection from SSL to authentication.
 *
 * \param userdata A client_connection:
 * \param data Unused
 */
void tls_sasl_connect(gpointer userdata, gpointer data)
{
	/* session will be removed by nussl */
	user_session_t *c_session;
	int ret;
	/*unsigned int size = 1;*/
	struct client_connection *client = (struct client_connection *)userdata;
	int socket_fd = client->socket;

	c_session = g_new0(user_session_t, 1);
	c_session->nussl = client->nussl;
	c_session->socket = socket_fd;
	c_session->tls_lock = g_mutex_new();
	c_session->addr = client->addr;
	(void)getsockname_ipv6(socket_fd, &c_session->server_addr);
	c_session->sport = client->sport;
	c_session->groups = NULL;
	c_session->user_name = NULL;
	c_session->user_id = 0;
	g_free(userdata);

	/* Check the user is authorized to connect
	 * when he already have an open connection */
	if (nuauthconf->single_ip_client_limit > 0) {
		if (g_slist_length(get_client_sockets_by_ip(&c_session->addr)) >=
				nuauthconf->single_ip_client_limit) {
			char address[INET6_ADDRSTRLEN];
			format_ipv6(&c_session->addr, address, INET6_ADDRSTRLEN, NULL);
			clean_session(c_session);
			remove_socket_from_pre_client_list(socket_fd);
		        log_message(INFO, DEBUG_AREA_USER,
				    "Policy: too many connection attempts from already overused IP %s, closing socket",
				    address);
			return;
		}
	}

	if ((nuauth_tls.auth_by_cert > NO_AUTH_BY_CERT)) {
		gchar *username = NULL;
		/* need to parse the certificate to see if it is a sufficient credential */
		username = modules_certificate_to_uid(c_session->nussl);

		/* parsing complete */
		if (username) {
			debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
					  "Using username %s from certificate",
					  username);
			c_session->groups =
			    modules_get_user_groups(username);
			c_session->user_id =
			    modules_get_user_id(username);
			if (c_session->groups == NULL) {
				debug_log_message(DEBUG, DEBUG_AREA_USER,
						  "error when searching user groups");
				c_session->groups = NULL;
				c_session->user_id = 0;
				/* we free username as it is not a good one */
				g_free(username);
			} else {
				c_session->user_name = username;
			}
		}
	}

	if ((nuauth_tls.auth_by_cert == NUSSL_CERT_REQUIRE) &&
			(c_session->groups == NULL)) {

		log_message(INFO, DEBUG_AREA_AUTH | DEBUG_AREA_USER,
			    "Certificate authentication failed, closing session");
		ret = SASL_BADAUTH;
	} else {
		ret = sasl_user_check(c_session);
	}

	remove_socket_from_pre_client_list(socket_fd);
	switch (ret) {
	case SASL_OK:
		/* remove socket from the list of pre auth socket */
		tls_sasl_connect_ok(c_session, socket_fd);
		break;

	case SASL_FAIL:
	default:
		if (ret == SASL_FAIL) {
			debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
					  "Crash on user side, closing socket");
		} else {
			debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
					  "Problem with user, closing socket");
		}
		clean_session(c_session);
	}


}

/**
 * @}
 */

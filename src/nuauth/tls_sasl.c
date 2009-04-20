/*
 ** Copyright(C) 2004,2005,2006,2007,2008 INL
 ** Written by  Eric Leblond <regit@inl.fr>
 **             Vincent Deffontaines <gryzor@inl.fr>
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
 **
 */

#include "auth_srv.h"
#include <sasl/saslutil.h>
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
			    "Policy: Too many opened sessions for user \"%s\", closing socket",
			    c_session->user_name);
		break;
	case PER_IP_TOO_MANY_LOGINS:
		log_message(INFO, DEBUG_AREA_USER,
			    "Policy: User \"%s\" trying to connect from already overused IP, closing socket",
			    c_session->user_name);
		break;
	default:
		log_message(WARNING, DEBUG_AREA_USER,
			    "Policy (bug!): User \"%s\" has to disconnect for UNKNOWN reason, closing socket",
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

	if (c_session->proto_version < PROTO_VERSION_V24) {
		/* send mode to client */
		msg.type = SRV_TYPE;
		if (nuauthconf->push) {
			msg.option = SRV_TYPE_PUSH;
		} else {
			msg.option = SRV_TYPE_POLL;
		}
		msg.length = 0;
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
	}

	/* unlock hash client */
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

static int add_client_capa(user_session_t * c_session, const char * value)
{
	int i;
	if (! value)
		return SASL_FAIL;

	for (i = 0; i < 32; i++) {
		if (! capa_array[i]) {
			return SASL_NOTDONE;
		}
		if (!strcmp(capa_array[i], value)) {
			c_session->capa_flags = c_session->capa_flags | (1 << i);
			return SASL_OK;
		}

	}
	return SASL_NOTDONE;
}

static int parse_user_capabilities(user_session_t * c_session, char *buf, int buf_size)
{
	unsigned int len;
	int decode;
	struct nu_authfield *vfield;
	gchar *dec_buf = NULL;
	gchar **v_strings;
	int dec_buf_size;
	char address[INET6_ADDRSTRLEN];

	vfield = (struct nu_authfield *) buf;

	/* check buffer underflow */
	if (buf_size < (int) sizeof(struct nu_authfield)) {
		format_ipv6(&c_session->addr, address, INET6_ADDRSTRLEN, NULL);
		g_message("%s sent a too small vfield", address);
		return SASL_FAIL;
	}

	if (vfield->type != CAPA_FIELD) {
#ifdef DEBUG_ENABLE
		log_message(DEBUG, DEBUG_AREA_USER | DEBUG_AREA_AUTH,
			    "capa field received %d,%d,%d from %s",
			    vfield->type, vfield->option,
			    ntohs(vfield->length), address);
#endif
		return SASL_FAIL;
	}

	dec_buf_size = ntohs(vfield->length);
	if (dec_buf_size > 1024 || (ntohs(vfield->length) <= 4)) {
		format_ipv6(&c_session->addr, address, INET6_ADDRSTRLEN, NULL);
		log_message(WARNING, DEBUG_AREA_USER | DEBUG_AREA_AUTH,
				"error capa field from %s is uncorrect, announced %d",
				address, ntohs(vfield->length));
		/* One more gryzor hack */
		if (dec_buf_size > 4096)
			log_message(WARNING, DEBUG_AREA_USER | DEBUG_AREA_AUTH,
				    "   Is %s running a 1.0 client?",
				    address);
#ifdef DEBUG_ENABLE
		log_message(DEBUG, DEBUG_AREA_USER | DEBUG_AREA_AUTH,
			    "%s:%d version field received %d,%d,%d ", __FILE__,
			    __LINE__, vfield->type, vfield->option,
			    ntohs(vfield->length));
#endif
		return SASL_BADAUTH;
	}
	dec_buf = g_new0(gchar, dec_buf_size);
	decode = sasl_decode64(buf + sizeof(struct nu_authfield),
			  ntohs(vfield->length) - sizeof(struct nu_authfield),
			  dec_buf, dec_buf_size, &len);
	if (decode != SASL_OK) {
		g_free(dec_buf);
		return SASL_BADAUTH;
	}

	/* should always be true for the moment */
	if (vfield->option == CLIENT_SRV) {
		char *value;
		int i, ret;

		v_strings = g_strsplit(dec_buf, ";", 0);
		for (value = v_strings[0], i = 0; value != NULL; i++, value = v_strings[i]) {
			debug_log_message(DEBUG, DEBUG_AREA_USER,
					  "client capa field: %s",
					  value);
			ret = add_client_capa(c_session, value);
			if (ret == SASL_FAIL) {
				g_strfreev(v_strings);
				g_free(dec_buf);
				return SASL_FAIL;
			}
		}
		/* print information */
		if (c_session->capa_flags) {
#ifdef DEBUG_ENABLE
			if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG, DEBUG_AREA_USER)) {
				format_ipv6(&c_session->addr, address, INET6_ADDRSTRLEN, NULL);
				g_message
					("user %s at %s uses client with capabilities %d",
					 c_session->user_name, address,
					 c_session->capa_flags);

			}
#endif
		}
		g_strfreev(v_strings);

	} else {
		format_ipv6(&c_session->addr, address, INET6_ADDRSTRLEN, NULL);
		log_message(DEBUG, DEBUG_AREA_USER | DEBUG_AREA_AUTH,
				"from %s : vfield->option is not CLIENT_SRV ?!",
				address);
		g_free(dec_buf);
		return SASL_FAIL;

	}
	g_free(dec_buf);
	return SASL_OK;
}



static int parse_user_version(user_session_t * c_session, char *buf, int buf_size)
{
	unsigned int len;
	int decode;
	struct nu_authfield *vfield;
	gchar *dec_buf = NULL;
	gchar **v_strings;
	int dec_buf_size;
	char address[INET6_ADDRSTRLEN];

	vfield = (struct nu_authfield *) buf;

	/* check buffer underflow */
	if (buf_size < (int) sizeof(struct nu_authfield)) {
		format_ipv6(&c_session->addr, address, INET6_ADDRSTRLEN, NULL);
		g_message("%s sent a too small vfield", address);
		return SASL_FAIL;
	}

	if (vfield->type != VERSION_FIELD) {
#ifdef DEBUG_ENABLE
		log_message(DEBUG, DEBUG_AREA_USER | DEBUG_AREA_AUTH,
			    "osfield received %d,%d,%d from %s",
			    vfield->type, vfield->option,
			    ntohs(vfield->length), address);
#endif
		return SASL_FAIL;
	}

	dec_buf_size = ntohs(vfield->length);
	if (dec_buf_size > 1024 || (ntohs(vfield->length) <= 4)) {
		format_ipv6(&c_session->addr, address, INET6_ADDRSTRLEN, NULL);
		log_message(WARNING, DEBUG_AREA_USER | DEBUG_AREA_AUTH,
				"error osfield from %s is uncorrect, announced %d",
				address, ntohs(vfield->length));
		/* One more gryzor hack */
		if (dec_buf_size > 4096)
			log_message(WARNING, DEBUG_AREA_USER | DEBUG_AREA_AUTH,
				    "   Is %s running a 1.0 client?",
				    address);
#ifdef DEBUG_ENABLE
		log_message(DEBUG, DEBUG_AREA_USER | DEBUG_AREA_AUTH,
			    "%s:%d version field received %d,%d,%d ", __FILE__,
			    __LINE__, vfield->type, vfield->option,
			    ntohs(vfield->length));
#endif
		return SASL_BADAUTH;
	}
	dec_buf = g_new0(gchar, dec_buf_size);
	decode = sasl_decode64(buf + sizeof(struct nu_authfield),
			  ntohs(vfield->length) - sizeof(struct nu_authfield),
			  dec_buf, dec_buf_size, &len);
	if (decode != SASL_OK) {
		g_free(dec_buf);
		return SASL_BADAUTH;
	}

	/* should always be true for the moment */
	if (vfield->option == CLIENT_SRV) {
		v_strings = g_strsplit(dec_buf, ";", 2);
		if (v_strings[0] == NULL || v_strings[1] == NULL) {
			g_strfreev(v_strings);
			g_free(dec_buf);
			return SASL_BADAUTH;
		}
		if (strlen(v_strings[0]) < 128) {
			c_session->client_name = string_escape(v_strings[0]);
			if (c_session->client_name == NULL) {
				format_ipv6(&c_session->addr, address, INET6_ADDRSTRLEN, NULL);
				log_message(WARNING, DEBUG_AREA_USER | DEBUG_AREA_AUTH,
						"received client name with invalid characters from %s",
						address);
				g_strfreev(v_strings);
				g_free(dec_buf);
				return SASL_BADAUTH;
			}
		} else {
			c_session->client_name = g_strdup(UNKNOWN_STRING);
		}
		if (strlen(v_strings[1]) < 128) {
			c_session->client_version = string_escape(v_strings[1]);
			if (c_session->client_version == NULL) {
				format_ipv6(&c_session->addr, address, INET6_ADDRSTRLEN, NULL);
				log_message(WARNING, DEBUG_AREA_USER | DEBUG_AREA_AUTH,
						"received client version with invalid characters from %s",
						address);
				g_strfreev(v_strings);
				g_free(dec_buf);
				return SASL_BADAUTH;
			}
		} else {
			c_session->client_version = g_strdup(UNKNOWN_STRING);
		}
	/* print information */
		if (c_session->client_name && c_session->client_version) {
#ifdef DEBUG_ENABLE
			if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG, DEBUG_AREA_USER)) {
				format_ipv6(&c_session->addr, address, INET6_ADDRSTRLEN, NULL);
				g_message
					("user %s at %s uses client %s, %s",
					 c_session->user_name, address,
					 c_session->client_name,
					 c_session->client_version);

			}
#endif
		}
		g_strfreev(v_strings);

	} else {
		format_ipv6(&c_session->addr, address, INET6_ADDRSTRLEN, NULL);
		log_message(DEBUG, DEBUG_AREA_USER | DEBUG_AREA_AUTH,
				"from %s : vfield->option is not CLIENT_SRV ?!",
				address);
		g_free(dec_buf);
		return SASL_FAIL;

	}
	g_free(dec_buf);
	return SASL_OK;
}

static int parse_user_os(user_session_t * c_session, char *buf, int buf_size)
{
	unsigned int len;
	int decode;
	struct nu_authfield *osfield;
	gchar *dec_buf = NULL;
	gchar **os_strings;
	int dec_buf_size;
	char address[INET6_ADDRSTRLEN];

	osfield = (struct nu_authfield *) buf;

	/* check buffer underflow */
	if (buf_size < (int) sizeof(struct nu_authfield)) {
		format_ipv6(&c_session->addr, address, INET6_ADDRSTRLEN, NULL);
		g_message("%s sent a too small osfield", address);
		return SASL_FAIL;
	}

	if (osfield->type != OS_FIELD) {
#ifdef DEBUG_ENABLE
		log_message(DEBUG, DEBUG_AREA_USER | DEBUG_AREA_AUTH,
			    "osfield received %d,%d,%d from %s",
			    osfield->type, osfield->option,
			    ntohs(osfield->length), address);
#endif
		return SASL_FAIL;
	}

	dec_buf_size = ntohs(osfield->length);
	if (dec_buf_size > 1024 || (ntohs(osfield->length) <= 4)) {
		format_ipv6(&c_session->addr, address, INET6_ADDRSTRLEN, NULL);
		log_message(WARNING, DEBUG_AREA_USER | DEBUG_AREA_AUTH,
				"error osfield from %s is uncorrect, announced %d",
				address, ntohs(osfield->length));
		/* One more gryzor hack */
		if (dec_buf_size > 4096)
			log_message(WARNING, DEBUG_AREA_USER | DEBUG_AREA_AUTH,
				    "   Is %s running a 1.0 client?",
				    address);
#ifdef DEBUG_ENABLE
		log_message(DEBUG, DEBUG_AREA_USER | DEBUG_AREA_AUTH,
			    "%s:%d osfield received %d,%d,%d ", __FILE__,
			    __LINE__, osfield->type, osfield->option,
			    ntohs(osfield->length));
#endif
		return SASL_BADAUTH;
	}
	dec_buf = g_new0(gchar, dec_buf_size);
	decode = sasl_decode64(buf + sizeof(struct nu_authfield),
			  ntohs(osfield->length) - sizeof(struct nu_authfield), dec_buf,
			  dec_buf_size, &len);
	if (decode != SASL_OK) {
		g_free(dec_buf);
		return SASL_BADAUTH;
	}

	/* should always be true for the moment */
	if (osfield->option == OS_SRV) {
		os_strings = g_strsplit(dec_buf, ";", 5);
		if (os_strings[0] == NULL || os_strings[1] == NULL
		    || os_strings[2] == NULL) {
			g_strfreev(os_strings);
			g_free(dec_buf);
			return SASL_BADAUTH;
		}
		if (strlen(os_strings[0]) < 128) {
			c_session->sysname = string_escape(os_strings[0]);
			if (c_session->sysname == NULL) {
				format_ipv6(&c_session->addr, address, INET6_ADDRSTRLEN, NULL);
				log_message(WARNING, DEBUG_AREA_USER | DEBUG_AREA_AUTH,
						"received sysname with invalid characters from %s",
						address);
				g_strfreev(os_strings);
				g_free(dec_buf);
				return SASL_BADAUTH;
			}
		} else {
			c_session->sysname = g_strdup(UNKNOWN_STRING);
		}
		if (strlen(os_strings[1]) < 128) {
			c_session->release = string_escape(os_strings[1]);
			if (c_session->release == NULL) {
				format_ipv6(&c_session->addr, address, INET6_ADDRSTRLEN, NULL);
				log_message(WARNING, DEBUG_AREA_USER | DEBUG_AREA_AUTH,
						"received release with invalid characters from %s",
						address);
				g_strfreev(os_strings);
				g_free(dec_buf);
				return SASL_BADAUTH;
			}
		} else {
			c_session->release = g_strdup(UNKNOWN_STRING);
		}
		if (strlen(os_strings[2]) < 128) {
			c_session->version = string_escape(os_strings[2]);
			if (c_session->version == NULL) {
				format_ipv6(&c_session->addr, address, INET6_ADDRSTRLEN, NULL);
				log_message(WARNING, DEBUG_AREA_USER | DEBUG_AREA_AUTH,
						"received version with invalid characters from %s",
						address);
				g_strfreev(os_strings);
				g_free(dec_buf);
				return SASL_BADAUTH;
			}
		} else {
			c_session->version = g_strdup(UNKNOWN_STRING);
		}
		if (os_strings[3]) {
		}
		/* print information */
		if (c_session->sysname && c_session->release &&
		    c_session->version) {

#ifdef DEBUG_ENABLE
			if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG, DEBUG_AREA_USER)) {
				format_ipv6(&c_session->addr, address, INET6_ADDRSTRLEN, NULL);
				g_message
					("user %s at %s uses OS %s ,%s, %s",
					 c_session->user_name, address,
					 c_session->sysname,
					 c_session->release,
					 c_session->version);

			}
#endif
		}
		g_strfreev(os_strings);
	} else {
		format_ipv6(&c_session->addr, address, INET6_ADDRSTRLEN, NULL);
		log_message(DEBUG, DEBUG_AREA_USER | DEBUG_AREA_AUTH,
				"from %s : osfield->option is not OS_SRV ?!",
				address);
		g_free(dec_buf);
		return SASL_FAIL;

	}
	g_free(dec_buf);
	return SASL_OK;
}

static int wait_client_os(user_session_t * c_session)
{
	char buf[8192];
	int buf_size, ret;

	/* recv OS datas from client */
	buf_size = nussl_read(c_session->nussl, buf, sizeof buf);
	if (buf_size < 0) {
		/* allo houston */
		debug_log_message(DEBUG, DEBUG_AREA_USER,
				  "error when receiving user OS");
		return SASL_FAIL;
	}

	/* parse and validate OS */
	ret = parse_user_os(c_session, buf, buf_size);
	if (ret != SASL_OK)
		return ret;

	return SASL_OK;
}

static int finish_nego(user_session_t * c_session)
{
	char buf[8192];
	struct nu_srv_message msg;
	int buf_size, ret;

	/* ask OS to client */
	msg.type = SRV_REQUIRED_INFO;
	msg.option = OS_VERSION;
	if (nussl_write(c_session->nussl, (char*)&msg, sizeof(msg)) < 0) {
		log_message(WARNING, DEBUG_AREA_USER,
			    "nussl_write() failure at %s:%d",
			    __FILE__, __LINE__);
		if (nuauthconf->push) {
			clean_session(c_session);
			return SASL_FAIL;
		} else {
			return SASL_FAIL;
		}
	}

	buf_size = nussl_read(c_session->nussl, buf, sizeof buf);
	ret = parse_user_os(c_session, buf, buf_size);
	if (ret != SASL_OK)
		return ret;
	debug_log_message(DEBUG, DEBUG_AREA_USER,
				  "user OS read");

	/* ask version to client */
	msg.option = CLIENT_VERSION;
	if (nussl_write(c_session->nussl, (char*)&msg, sizeof(msg)) < 0) {
		log_message(WARNING, DEBUG_AREA_USER,
			    "nussl_write() failure at %s:%d",
			    __FILE__, __LINE__);
		if (nuauthconf->push) {
			clean_session(c_session);
			return SASL_FAIL;
		} else {
			return SASL_FAIL;
		}
	}
	debug_log_message(DEBUG, DEBUG_AREA_USER,
				  "user version asked");

	buf_size = nussl_read(c_session->nussl, buf, sizeof buf);
	ret = parse_user_version(c_session, buf, buf_size);

	if (ret != SASL_OK)
		return ret;
	debug_log_message(DEBUG, DEBUG_AREA_USER,
				  "user version read");

	/* ask version to client */
	msg.option = CLIENT_CAPA;
	if (nussl_write(c_session->nussl, (char*)&msg, sizeof(msg)) < 0) {
		log_message(WARNING, DEBUG_AREA_USER,
			    "nussl_write() failure at %s:%d",
			    __FILE__, __LINE__);
		if (nuauthconf->push) {
			clean_session(c_session);
			return SASL_FAIL;
		} else {
			return SASL_FAIL;
		}
	}
	debug_log_message(DEBUG, DEBUG_AREA_USER,
				  "user capabilities asked");

	buf_size = nussl_read(c_session->nussl, buf, sizeof buf);
	ret = parse_user_capabilities(c_session, buf, buf_size);

	if (ret != SASL_OK)
		return ret;
	debug_log_message(DEBUG, DEBUG_AREA_USER,
				  "user version read");

	/* call module for plugin modification of protocol */
	ret = modules_postauth_proto(c_session);
	if (ret != SASL_OK) {
		if (nuauthconf->push) {
			clean_session(c_session);
			return SASL_FAIL;
		} else {
			return SASL_FAIL;
		}
	}

	/* send mode to client */
	msg.type = SRV_TYPE;
	if (nuauthconf->push) {
		msg.option = SRV_TYPE_PUSH;
	} else {
		msg.option = SRV_TYPE_POLL;
	}
	msg.length = 0;
	if (nussl_write(c_session->nussl, (char*)&msg, sizeof(msg)) < 0) {
		log_message(WARNING, DEBUG_AREA_USER,
			    "nussl_write() failure at %s:%d",
			    __FILE__, __LINE__);
		if (nuauthconf->push) {
			clean_session(c_session);
			return SASL_FAIL;
		} else {
			return SASL_FAIL;
		}
	}

	/* send nego done */
	msg.type = SRV_INIT;
	msg.option = INIT_OK;
	if (nussl_write(c_session->nussl, (char*)&msg, sizeof(msg)) < 0) {
		log_message(WARNING, DEBUG_AREA_USER,
			    "nussl_write() failure at %s:%d",
			    __FILE__, __LINE__);
		if (nuauthconf->push) {
			clean_session(c_session);
			return SASL_FAIL;
		} else {
			return SASL_FAIL;
		}
	}
	debug_log_message(DEBUG, DEBUG_AREA_USER,
				  "negotation finished");

	return SASL_OK;
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
	struct client_connection *client;
	int socket_fd;

	if ( ! userdata ) {
		log_message(INFO, DEBUG_AREA_USER,
				"Unable to connect: client structure empty");
		return;
	}

	client = (struct client_connection *)userdata;
	socket_fd = client->socket;

	/* complete handshake */
	ret = tls_user_do_handshake(client, client->srv_context);
	if (ret != 0) {
		/* error, cleanup & exit */
		log_message(INFO, DEBUG_AREA_USER,
				"Handshake failed, exiting client %s\n",
				client->str_addr);
		nussl_session_destroy(client->nussl);
		g_free(client->str_addr);
		g_free(userdata);
		return;
	}

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
	g_free(client->str_addr);
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
		/* finish init phase */
		switch (c_session->proto_version) {
			case PROTO_VERSION_V20:
			case PROTO_VERSION_V22:
			case PROTO_VERSION_V22_1:
				debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
					  "Wait for OS");
				ret = wait_client_os(c_session);
				break;
			case PROTO_VERSION_V24:
				debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
					  "Finishing nego");
				ret = finish_nego(c_session);
				break;
			default:
				log_message(WARNING, DEBUG_AREA_AUTH,
					    "Bad user protocol");
		}

		if (ret != SASL_OK) {
			/* get rid of client */
			clean_session(c_session);
			break;
		}

		/* Tuning of user_session */
		ret = modules_user_session_modify(c_session);
		if (ret != SASL_OK) {
			/* get rid of client */
			clean_session(c_session);
			break;
		}

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

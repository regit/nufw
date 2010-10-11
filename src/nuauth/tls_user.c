/*
 ** Copyright(C) 2004-2009 INL
 ** Written by  Eric Leblond <regit@inl.fr>
 **             Vincent Deffontaines <gryzor@inl.fr>
 **             Pierre Chifflier <chifflier@inl.fr>
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
#include "tls.h"
#include <fcntl.h>

#include "nuauthconf.h"

/**
 * \ingroup TLS
 * \defgroup TLSUser TLS User server
 * @{
 */

/**
 * \brief Handle phase after authentication and till client is active. Defined in tls_sasl.c
 *
 * It also handle preclient list to be able to disconnect user if authentication take too long.
 */

extern struct nuauth_tls_t nuauth_tls;

/**
 * List of new clients which are in authentication state. This list is
 * feeded by tls_user_accept(), and read by pre_client_check() and
 * remove_socket_from_pre_client_list().
 *
 * Lock ::pre_client_list_mutex when you access to this list.
 */
GSList *pre_client_list;

/**
 * Mutex used to access ::pre_client_list.
 */
GStaticMutex pre_client_list_mutex;

struct pre_client_elt {
	int socket;
	time_t validity;
};

/**
 * Drop a client from the ::pre_client_list.
 */
gboolean remove_socket_from_pre_client_list(int socket)
{
	GSList *client_runner = NULL;
	g_static_mutex_lock(&pre_client_list_mutex);
	for (client_runner = pre_client_list; client_runner;
	     client_runner = client_runner->next) {
		/* if entry older than delay then close socket */
		if (client_runner->data) {
			if (((struct pre_client_elt *) (client_runner->
							data))->socket ==
			    socket) {
				g_free(client_runner->data);
				client_runner->data = NULL;
				pre_client_list =
				    g_slist_remove_all(pre_client_list,
						       NULL);
				g_static_mutex_unlock
				    (&pre_client_list_mutex);
				return TRUE;
			}
		}
	}
	g_static_mutex_unlock(&pre_client_list_mutex);
	return FALSE;
}

/**
 * Check pre client list to disconnect connections
 * that have been open for too long
 */
void* pre_client_check(GMutex *mutex)
{
	GSList *client_runner = NULL;
	time_t current_timestamp;

	while (g_mutex_trylock(mutex)) {
		g_mutex_unlock(mutex);

		current_timestamp = time(NULL);

		/* lock client list */
		g_static_mutex_lock(&pre_client_list_mutex);
		/* iter on pre_client_list */
		for (client_runner = pre_client_list; client_runner;
		     client_runner = client_runner->next) {
			/* if entry older than delay then close socket */
			if (client_runner->data) {
				if (((struct pre_client_elt
				      *) (client_runner->data))->validity <
				    current_timestamp) {
					log_message(INFO, DEBUG_AREA_USER,
						    "closing socket %d due to timeout",
						    ((struct pre_client_elt
						      *) (client_runner->
							  data))->socket);
					shutdown(((struct pre_client_elt
						   *) (client_runner->
						       data))->socket,
						 SHUT_RDWR);
					close(((struct pre_client_elt
						*) (client_runner->data))->
					      socket);
					g_free(client_runner->data);
					client_runner->data = NULL;
				}
			}
		}
		pre_client_list =
		    g_slist_remove_all(pre_client_list, NULL);
		/* unlock client list */
		g_static_mutex_unlock(&pre_client_list_mutex);
		/* sleep */
		sleep(1);
	}
	return NULL;
}

/**
 * get RX paquet from a TLS client connection and send it to user
 * authentication threads.
 *
 * \param c_session SSL RX packet
 * \param c_data pointer that will point to the parsed data
 * \return a nu_error_t::, NU_EXIT_CONTINUE if read done, NU_EXIT_OK if read complete, NU_EXIT_ERROR on error
 */
nu_error_t treat_user_request(user_session_t * c_session,
				     struct tls_buffer_read **c_data)
{
	int header_length;
	struct nu_header *header;
	struct tls_buffer_read *data;
	int i = 0, offset = 0, dgram_size;

	if (c_session == NULL)
		return NU_EXIT_ERROR;

	data = g_new0(struct tls_buffer_read, 1);
	if (data == NULL)
		return NU_EXIT_ERROR;
	data->socket = 0;
	data->ip_addr = c_session->addr;
	data->proto_version = c_session->proto_version;
	data->auth_quality = c_session->auth_quality;

	/* copy packet data */
	data->buffer = g_new0(char, CLASSIC_NUFW_PACKET_SIZE);
	if (data->buffer == NULL) {
		g_free(data);
		return NU_EXIT_ERROR;
	}

	/* read message header */

	data->buffer_len = nussl_read(c_session->nussl, data->buffer,
			       (int) sizeof(struct nu_header));

	if (data->buffer_len != (int) sizeof(struct nu_header)) {
		if (data->buffer_len < 0) {
			log_message(DEBUG, DEBUG_AREA_USER,
					"Received error from user %s (%s)",
					c_session->user_name, nussl_get_error(c_session->nussl));
			free_buffer_read(data);
			if (!strcmp("Resource temporarily unavailable",
						nussl_get_error(c_session->nussl))) {
				log_message(DEBUG, DEBUG_AREA_USER,
						"Read unavailable from %s (%s)",
						c_session->user_name, nussl_get_error(c_session->nussl));
				return NU_EXIT_CONTINUE;
			} else {
				return NU_EXIT_ERROR;
			}
		} else if (data->buffer_len == 0) {
			log_message(INFO, DEBUG_AREA_USER,
					"user disconnect at %s:%d",
					__FILE__,
					__LINE__);
			free_buffer_read(data);
			return NU_EXIT_ERROR;
		} else {
			/* incomplete read */
			log_message(INFO, DEBUG_AREA_USER,
					"user imcomplete read at %s:%d",
					__FILE__,
					__LINE__);
			free_buffer_read(data);
			return NU_EXIT_ERROR;
		}
	}

	/* get header to get how much data we have to read */
	header = (struct nu_header *) data->buffer;
	header_length = ntohs(header->length);

	if (header_length >= MAX_NUFW_PACKET_SIZE) {
		log_message(INFO, DEBUG_AREA_USER,
				    "User packet from \'%s\' with too big announced size (%d)",
				    c_session->user_name, header_length);
		free_buffer_read(data);
		return NU_EXIT_ERROR;
	}

	/* continue to read the content */
	if (header->proto == PROTO_VERSION
	    && header_length > data->buffer_len) {

		if (header_length > CLASSIC_NUFW_PACKET_SIZE) {
			data->buffer = g_realloc(data->buffer, header_length);
			header = (struct nu_header *) data->buffer;
		}

		debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
				  "tls user: reading %d", header_length);
		offset = sizeof(struct nu_header);
		i = 0;
		do {
			debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
					"user read pass %d", i);
			dgram_size = nussl_read(c_session->nussl,
					(char *) (data->buffer + offset),
					header_length - offset);
			if (dgram_size != header_length - offset) {
				if (dgram_size < 0) {
					log_message(INFO, DEBUG_AREA_USER,
							"user failure at %s:%d (%s)", __FILE__,
							__LINE__, nussl_get_error(c_session->nussl));
					free_buffer_read(data);
					return NU_EXIT_ERROR;
				} else if (dgram_size == 0) {
					log_message(INFO, DEBUG_AREA_USER,
							"user disconnect at %s:%d",
							__FILE__,
							__LINE__);
					free_buffer_read(data);
					return NU_EXIT_ERROR;
				} else {
					log_message(INFO, DEBUG_AREA_USER,
							"(pass %d) nufw incomplete read (%d vs %d) at %s:%d",
							i,
							dgram_size,
							header_length - offset,
							__FILE__,
							__LINE__);
					/* give one last chance ? */
					offset += dgram_size;
				}
			} else {
				break;
			}
			i++;
		} while (i < 3);

		if (i == 3) {
			log_message(INFO, DEBUG_AREA_USER,
					"user read impossible at %s:%d",
					__FILE__,
					__LINE__);
			free_buffer_read(data);
			return NU_EXIT_ERROR;
		}

		/* read is complete here */
		data->buffer_len = header_length;
	}

	/* looks like a regular user message attempt, update last_request */
	c_session->last_request = time(NULL);

	/* is it an "USER HELLO" message ? */
	if (header->proto == PROTO_VERSION
	    && header->msg_type == USER_HELLO) {
		debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
				  "tls user: HELLO from user \"%s\"",
				  c_session->user_name);
		c_session->last_request = time(NULL);
		free_buffer_read(data);
		return NU_EXIT_CONTINUE;
	}

	/* check authorization if we're facing a multi user packet */
	if (header->option == 0x0) {
		/* this is an authorized packet we fill the buffer_read structure */
		data->user_name = g_strdup(c_session->user_name);
		data->user_id = c_session->user_id;
		if (nuauthconf->use_groups_name) {
			data->groups = duplicate_str_list(c_session->groups);
		} else {
			data->groups = g_slist_copy(c_session->groups);
		}
		if (c_session->sysname) {
			data->os_sysname = g_strdup(c_session->sysname);
			if (data->os_sysname == NULL) {
				free_buffer_read(data);
				return NU_EXIT_ERROR;
			}
		}
		if (c_session->release) {
			data->os_release = g_strdup(c_session->release);
			if (data->os_release == NULL) {
				free_buffer_read(data);
				return NU_EXIT_ERROR;
			}
		}
		if (c_session->version) {
			data->os_version = g_strdup(c_session->version);
			if (data->os_version == NULL) {
				free_buffer_read(data);
				return NU_EXIT_ERROR;
			}
		}
	} else {
		log_message(INFO, DEBUG_AREA_USER,
			    "Bad packet, option of header is not set or unauthorized option from user \"%s\".",
			    c_session->user_name);
		free_buffer_read(data);
		return NU_EXIT_OK;
	}

	*c_data = data;
	return NU_EXIT_CONTINUE;
}

/**
 * Function called by client sasl thread, to complete TLS handshake
 *    - Call nussl_session_handshake()
 *    - Check client certificate
 *
 * \return If an error occurs returns 1, else returns 0.
 */
int tls_user_do_handshake(struct client_connection *current_client_conn, struct tls_user_context_t *context)
{
	int ret;
	char cipher[256];

	/* do not verify FQDN field from client */
	nussl_set_session_flag(current_client_conn->nussl,
		NUSSL_SESSFLAG_IGNORE_ID_MISMATCH,
		1
		);

	// XXX default value is 30s, should be a configuration value
	nussl_set_connect_timeout(current_client_conn->nussl, 30);

	ret = nussl_session_handshake(current_client_conn->nussl,context->nussl);
	if ( ret ) {
		log_message(WARNING, DEBUG_AREA_MAIN | DEBUG_AREA_USER,
			    "New client connection from %s failed during nussl_session_handshake(): %s",
			    current_client_conn->str_addr,
			    nussl_get_error(context->nussl));
		return 1;
	}

	nussl_session_get_cipher(current_client_conn->nussl, cipher, sizeof(cipher));
	log_message(INFO, DEBUG_AREA_MAIN | DEBUG_AREA_USER,
		    "TLS handshake with client %s succeeded, cipher is %s",
		    current_client_conn->str_addr, cipher);

	/* Check certificate hook */
	ret = modules_check_certificate(current_client_conn->nussl);
	if ( ret ) {
		log_message(WARNING, DEBUG_AREA_MAIN | DEBUG_AREA_USER,
			    "New client connection from %s failed during modules_check_certificate()",
			    current_client_conn->str_addr);
		return 1;
	}

	return 0;
}

/**
 * Function called on new client connection:
 *    - Call accept()
 *    - Drop client if there are to much clients or if NuAuth is in reload
 *    - Create a client_connection structure
 *    - Add client to ::pre_client_list
 *    - Add client to ::tls_sasl_worker queue (see sasl_worker())
 *
 * \return If an error occurs returns 1, else returns 0.
 */
int tls_user_accept(struct tls_user_context_t *context)
{
	struct sockaddr_storage sockaddr;
	struct sockaddr_in *sockaddr4 = (struct sockaddr_in *) &sockaddr;
	struct sockaddr_in6 *sockaddr6 = (struct sockaddr_in6 *) &sockaddr;
	struct in6_addr addr;
	unsigned int len_inet = sizeof sockaddr;
	struct client_connection *current_client_conn;
	struct pre_client_elt *new_pre_client;
	int socket;
	gint option_value;
	unsigned short sport;
	char address[INET6_ADDRSTRLEN];

	current_client_conn = g_new0(struct client_connection, 1);

	current_client_conn->nussl = nussl_session_accept(context->nussl);
	if ( ! current_client_conn->nussl ) {
		/* can be triggered by EAGAIN on non blocking accept socket */
		g_free(current_client_conn);
		return 1;
	}

	if (nussl_session_getpeer(current_client_conn->nussl, (struct sockaddr *) &sockaddr, &len_inet) != NUSSL_OK)
	{
		log_message(WARNING, DEBUG_AREA_MAIN | DEBUG_AREA_USER,
			    "New client connection failed during nussl_session_getpeer(): %s", nussl_get_error(context->nussl));
		g_free(current_client_conn);
		return 1;
	}

	socket = nussl_session_get_fd(current_client_conn->nussl);

	/* if system is in reload: drop new client */
	if (nuauthdatas->need_reload) {
		shutdown(socket, SHUT_RDWR);
		close(socket);
		return 0;
	}

	/* Extract client address (convert it to IPv6 if it's IPv4) */
	/* if (sockaddr.ss_family == AF_INET) { -> same as tls_nufw.c */
	if (sockaddr6->sin6_family == AF_INET) {
		ipv4_to_ipv6(sockaddr4->sin_addr, &addr);
		sport = ntohs(sockaddr4->sin_port);
	} else {
		addr = sockaddr6->sin6_addr;
		sport = ntohs(sockaddr6->sin6_port);
	}

	format_ipv6(&addr, address, sizeof(address), NULL);
	log_message(DEBUG, DEBUG_AREA_MAIN | DEBUG_AREA_USER,
			"nuauth: user connection attempt from %s\n",
			address);

	if (get_number_of_clients() >= context->nuauth_tls_max_clients) {
		log_message(WARNING, DEBUG_AREA_MAIN | DEBUG_AREA_USER,
			    "too many clients (%d configured)",
			    context->nuauth_tls_max_clients);
		shutdown(socket, SHUT_RDWR);
		close(socket);
		return 1;
	}

	current_client_conn->socket = socket;
	current_client_conn->addr = addr;
	current_client_conn->sport = sport;
	current_client_conn->str_addr = g_strdup(address);
	current_client_conn->srv_context = context;

	/* Set KEEP ALIVE on connection */
	option_value = 1;
	setsockopt(socket,
		   SOL_SOCKET, SO_KEEPALIVE,
		   &option_value, sizeof(option_value));

	/* give the connection to a separate thread */
	/*  add element to pre_client
	   create pre_client_elt */
	new_pre_client = g_new0(struct pre_client_elt, 1);
	new_pre_client->socket = socket;
	new_pre_client->validity =
	    time(NULL) + context->nuauth_auth_nego_timeout;

	g_static_mutex_lock(&pre_client_list_mutex);
	pre_client_list = g_slist_prepend(pre_client_list, new_pre_client);
	g_static_mutex_unlock(&pre_client_list_mutex);

	thread_pool_push(nuauthdatas->tls_sasl_worker,
			   current_client_conn, NULL);
	return 0;
}

/**
 * Process client events:
 *    - Delete client if its session expired: delete_client_by_socket()
 *    - Call treat_user_request(). If it gets EOF, delete the client:
 *      send #FREE_MESSAGE to tls_push_queue (see push_worker()) if using
 *      PUSH mode (::nuauthconf->push), or call delete_client_by_socket().
 */
nu_error_t tls_user_check_activity(user_session_t *c_session)
{
	debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
			  "user activity on socket %d", c_session->socket);

	if (nuauthconf->session_duration && c_session->expire < time(NULL)) {
		return NU_EXIT_ERROR;
	}

	debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN | DEBUG_AREA_USER,
			  "user_checker starting");

	return user_check_and_decide(c_session);
}

void user_worker(gpointer psession, gpointer data)
{
	user_session_t *usersession = (user_session_t *) psession;
	struct msg_addr_set *gmsg;
	int ret;
	gboolean sess_ok = TRUE;


	if (g_mutex_trylock(usersession->rw_lock)) {
		while (sess_ok && (gmsg = g_async_queue_try_pop(usersession->workunits_queue))) {
			if (gmsg == GINT_TO_POINTER(0x1)) {
				debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
						"reading message from \"%s\"",
						usersession->user_name);
				ret = tls_user_check_activity(usersession);
				switch (ret) {
					case NU_EXIT_OK:
						break;
					case NU_EXIT_ERROR:
						log_message(INFO, DEBUG_AREA_USER,
							    "Problem reading message from \"%s\"",
							    usersession->user_name);
						usersession->pending_disconnect = TRUE;
						sess_ok = FALSE;
						break;
					case NU_EXIT_CONTINUE:
						/* send socket back to user select no message are waiting */
						g_async_queue_push(mx_queue, usersession);
						ev_async_send(usersession->srv_context->loop,
								&usersession->srv_context->client_injector_signal);

						g_mutex_unlock(usersession->rw_lock);
						return;
				}
			} else {
				debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
						"writing message to \"%s\"",
						usersession->user_name);

				/* send message */
				ret = nussl_write(usersession->nussl,
						(char*)gmsg->msg,
						ntohs(gmsg->msg->length));
				g_free(gmsg->msg);
				g_free(gmsg);
				if (ret < 0) {
					debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
							"client disconnect");
					usersession->pending_disconnect = TRUE;
					sess_ok = FALSE;
					break;
				}
			}
		}
		/* send socket back to user select no message are waiting */
		g_async_queue_push(mx_queue, usersession);
		ev_async_send(usersession->srv_context->loop,
				&usersession->srv_context->client_injector_signal);

		g_mutex_unlock(usersession->rw_lock);
	}
	return;
}

static void client_accept_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	struct tls_user_context_t *context = (struct tls_user_context_t *) w->data;
#ifdef DEBUG_ENABLE
	int i = 0;
#endif
	debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
				"Going to accept new user session");
	while(tls_user_accept(context) == 0) {
#ifdef DEBUG_ENABLE
		log_message(INFO, DEBUG_AREA_USER,
				"New client connection. (%d)",
				i);
		i++;
#endif
		continue;
	}
}

void client_activity_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	struct tls_user_context_t *context = (struct tls_user_context_t *) w->data;
	/* get_client_datas_by_socket acquire client datas lock if session is found */
	user_session_t *c_session = get_client_datas_by_socket(w->fd);

	if (! c_session) {
		log_message(WARNING, DEBUG_AREA_USER,
				"Unable to find session for %d", w->fd);
		return;
	}

	debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
				"User activity for \"%s\" (in cb)",
				c_session->user_name);

	if (c_session->activated) {
		c_session->activated = FALSE;
	}

	ev_io_stop(context->loop, w);

	if (revents & EV_ERROR) {
		log_message(INFO, DEBUG_AREA_USER,
				"Error on socket %d", w->fd);
		delete_locked_client_by_socket(w->fd);
		unlock_client_datas();
		return;
	}
	if (revents & EV_READ) {
		debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
				"Reading needed for user \"%s\"(in cb)",
				c_session->user_name);
		g_async_queue_push(c_session->workunits_queue, GINT_TO_POINTER(0x1));
		thread_pool_push(nuauthdatas->user_workers, c_session, NULL);
		unlock_client_datas();
		return;
	}
	/* we should not reach this point */
	log_message(WARNING, DEBUG_AREA_USER, "Surprising event from libev: %d",
		    revents);
	/* disconnecting session to be sure */
	if (g_mutex_trylock(c_session->rw_lock)) {
		delete_rw_locked_client(c_session);
	} else {
		c_session->pending_disconnect = TRUE;
	}
	unlock_client_datas();
}



static void __client_writer_cb(struct ev_loop *loop, struct tls_user_context_t *context, int revents)
{
	user_session_t *session;
	int fd;
#if DEBUG_ENABLE
	int i = 0;
#endif
	while ((fd = GPOINTER_TO_INT(g_async_queue_try_pop(writer_queue)))) {
		session = get_client_datas_by_socket(fd);
		if (session == NULL) {
			continue;
		}
		if (g_mutex_trylock(session->rw_lock)) {
			ev_io_stop(session->srv_context->loop,
					&session->client_watcher);
			debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
					  "sending session to user_workers (%d)",
					  i);
			g_mutex_unlock(session->rw_lock);
			thread_pool_push(nuauthdatas->user_workers, session, NULL);
		}
#if DEBUG_ENABLE
		i++;
#endif
		unlock_client_datas();
	}
}

static void client_writer_cb(struct ev_loop *loop, ev_async *w, int revents)
{
	struct tls_user_context_t *context = (struct tls_user_context_t *) w->data;
	debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER, "entering writer callback");
	__client_writer_cb(loop, context, revents);
}


static void __client_injector_cb(struct ev_loop *loop, struct tls_user_context_t *context, int revents)
{
	user_session_t * session;
#if DEBUG_ENABLE
	int i = 0;
#endif

	lock_client_datas();
	while ((session = (user_session_t *) g_async_queue_try_pop(mx_queue))) {
		if (session == NULL)
			continue;
		if (session->pending_disconnect) {
			log_message(INFO,
					  DEBUG_AREA_USER,
					  "disconnecting \'%s\' %d"
#if DEBUG_ENABLE
					  "(%d)"
#endif
					  , session->user_name,
					  session->socket
#if DEBUG_ENABLE
					  , i
#endif
					  );
			delete_locked_client_by_socket(session->socket);
			continue;
		}
		debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER, "reinjecting %d (%d)",
				  session->socket, i);
		ev_io_start(session->srv_context->loop, &session->client_watcher);
		session->activated = TRUE;
#if DEBUG_ENABLE
		i++;
#endif
	}
	unlock_client_datas();

}
static void client_injector_cb(struct ev_loop *loop, ev_async *w, int revents)
{
	struct tls_user_context_t *context = (struct tls_user_context_t *) w->data;
	__client_injector_cb(loop, context, revents);
}

static void client_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	struct tls_user_context_t *context = (struct tls_user_context_t *) w->data;
	__client_writer_cb(loop, context, revents);
	__client_injector_cb(loop, context, revents);
}



/*
 * execute client destruction task
 */
static void client_destructor_cb(struct ev_loop *loop, ev_async *w, int revents)
{
	struct tls_user_context_t *context = (struct tls_user_context_t *) w->data;
	disconnect_user_msg_t *disconnect_msg;
	user_session_t *session;

	disconnect_msg = g_async_queue_pop(context->cmd_queue);

	if (disconnect_msg->socket == -1) {
		disconnect_msg->result = kill_all_clients();
	} else {
		session = get_client_datas_by_socket(disconnect_msg->socket);
		if (session == NULL) {
			g_mutex_lock(disconnect_msg->mutex);
			disconnect_msg->result = NU_EXIT_ERROR;
			g_cond_signal(disconnect_msg->cond);
			g_mutex_unlock(disconnect_msg->mutex);
			unlock_client_datas();
			return;
		}
		if (g_mutex_trylock(session->rw_lock)) {
			ev_io_stop(session->srv_context->loop,
					&session->client_watcher);
			disconnect_msg->result = delete_rw_locked_client(session);
		} else {
			session->pending_disconnect = TRUE;
			disconnect_msg->result = NU_EXIT_OK;
		}
		unlock_client_datas();
	}
	g_mutex_lock(disconnect_msg->mutex);
	g_cond_signal(disconnect_msg->cond);
	g_mutex_unlock(disconnect_msg->mutex);
}

/* this is a global destructor for all event loop */
static void loop_destructor_cb(struct ev_loop *loop, ev_async *w, int revents)
{
	ev_unloop(loop, EVUNLOOP_ALL);
}


/**
 * Wait for new client connection or client event using ::mx_queue
 * and select().
 *
 * It calls tls_user_accept() on new client connection, and
 * tls_user_check_activity() on user event.
 */
void tls_user_main_loop(struct tls_user_context_t *context, GMutex * mutex)
{
	ev_io client_watcher;
	ev_timer timer;

	context->loop = ev_loop_new(0);
	/* register injector cb */
	ev_async_init(&context->client_injector_signal, client_injector_cb);
	ev_async_start(context->loop, &context->client_injector_signal);
	context->client_injector_signal.data = context;

	/* register writer cb */
	ev_async_init(&context->client_writer_signal, client_writer_cb);
	ev_async_start(context->loop, &context->client_writer_signal);
	context->client_writer_signal.data = context;

	ev_timer_init (&timer, client_timeout_cb, 0, 0.200);
	ev_timer_start (context->loop, &timer);

	/* register destructor cb */
	ev_async_init(&context->client_destructor_signal, client_destructor_cb);
	ev_async_start(context->loop, &context->client_destructor_signal);
	context->client_destructor_signal.data = context;


	/* register destructor cb */
	ev_async_init(&context->loop_fini_signal, loop_destructor_cb);
	ev_async_start(context->loop, &context->loop_fini_signal);
	context->loop_fini_signal.data = context;

	/* register accept cb */
	fcntl(context->sck_inet,F_SETFL,(fcntl(context->sck_inet,F_GETFL)|O_NONBLOCK));
	ev_io_init(&client_watcher, client_accept_cb, context->sck_inet, EV_READ);
	ev_io_start(context->loop, &client_watcher);
	client_watcher.data = context;

	log_message(INFO, DEBUG_AREA_USER,
			"[+] NuAuth is waiting for client connections.");
	ev_loop(context->loop, 0);

	ev_loop_destroy(context->loop);

	close(context->sck_inet);
}

void tls_user_servers_init()
{
	/* init sasl stuff */
	my_sasl_init();

	init_client_struct();

	/* pre client list */
	pre_client_list = NULL;

	thread_new(&nuauthdatas->pre_client_thread,
		   "pre client thread", pre_client_check);

	/* create tls sasl worker thread pool */
	nuauthdatas->tls_sasl_worker =
	    g_thread_pool_new((GFunc) tls_sasl_connect, NULL,
			      nuauthconf->nb_auth_checkers, FALSE,
			      NULL);
}

/**
 * Set request_cert and auth_by_cert params depending on the configuration
 */
int tls_user_setcert_auth_params(int requestcert, int authcert)
{
	int disable_request_warning;

	disable_request_warning = nuauth_config_table_get_or_default_int("nuauth_tls_disable_request_warning", FALSE);

	nuauth_tls.auth_by_cert = authcert;

	if (NUSSL_VALID_REQ_TYPE(requestcert)) {
		nuauth_tls.request_cert = requestcert;
	} else {
		log_message(INFO, DEBUG_AREA_AUTH | DEBUG_AREA_USER,
				"config: Invalid nuauth_tls_auth_by_cert value: %d",
				authcert);
		return 0;
	}

	if ((nuauth_tls.auth_by_cert == MANDATORY_AUTH_BY_CERT)
	&& (nuauth_tls.request_cert != NUSSL_CERT_REQUIRE)) {
		log_message(INFO, DEBUG_AREA_AUTH | DEBUG_AREA_USER,
			    "Mandatory certificate authentication asked, asking certificate");
		nuauth_tls.request_cert = NUSSL_CERT_REQUIRE;
	}

	/* always ask for certificates - but don't error if none were sent */
	if (nuauth_tls.request_cert == 0)
		nuauth_tls.request_cert = 1;

	log_message(INFO, DEBUG_AREA_AUTH | DEBUG_AREA_USER,"request_cert = %i", nuauth_tls.request_cert);
	log_message(INFO, DEBUG_AREA_AUTH | DEBUG_AREA_USER,"auth_by_cert = %i", nuauth_tls.auth_by_cert);

	if (!disable_request_warning) {
		if (nuauth_tls.request_cert != 2) {
			g_warning ("nuauth: client certificates are not required\n"
				"nuauth will *NOT* check client certificates.\n"
				"Set nuauth_tls_request_cert=2 to request certificates.\n");
		} else {
			log_message(INFO, DEBUG_AREA_AUTH | DEBUG_AREA_USER,
				    "Client certificates are required.");
		}
	}

	return 1;
}

/**
 * Create TLS user context.
 */
int tls_user_init(struct tls_user_context_t *context)
{
	char *errmsg;
	int result;

	int ret;

	/*const unsigned int nb_params = sizeof(nuauth_tls_vars) / sizeof(confparams_t);*/
	int int_authcert;
	int int_requestcert;
	char *dh_params_file;

	context->sck_inet = nuauth_bind(&errmsg, context->addr, context->port, "user");
	if (context->sck_inet < 0) {
		log_message(FATAL, DEBUG_AREA_MAIN | DEBUG_AREA_USER,
			    "FATAL ERROR: User bind error: %s", errmsg);
		log_message(FATAL, DEBUG_AREA_MAIN | DEBUG_AREA_USER,
			    "Check that nuauth is not running twice. nuauth exiting!");
		exit(EXIT_FAILURE);
	}

	fcntl(context->sck_inet,F_SETFL,(fcntl(context->sck_inet,F_GETFL)|O_NONBLOCK));

	context->cmd_queue = g_async_queue_new();

	/* listen */
	result = listen(context->sck_inet, 20);
	if (result == -1) {
		log_message(FATAL, DEBUG_AREA_MAIN,
			    "user listen() failed, exiting");
		exit(EXIT_FAILURE);
	}

	/* FIXME this *has* to be context dependant */
	mx_queue = g_async_queue_new();
	writer_queue = g_async_queue_new();

	/* Init ssl session */
	/* TODO: make sure request_cert | auth_by_cert is for user and change to nufw if required */
	context->nuauth_tls_max_clients = nuauth_config_table_get_or_default_int("nuauth_tls_max_clients", NUAUTH_TLS_MAX_CLIENTS);
	context->nuauth_auth_nego_timeout = nuauth_config_table_get_or_default_int("nuauth_auth_nego_timeout", NUAUTH_TLS_MAX_CLIENTS);
	/* ssl related conf */
	int_requestcert = nuauth_config_table_get_or_default_int("nuauth_tls_request_cert", 2);
	int_authcert = nuauth_config_table_get_or_default_int("nuauth_tls_auth_by_cert", FALSE);
	dh_params_file = nuauth_config_table_get("nuauth_tls_dh_params");

	if (!tls_user_setcert_auth_params(int_requestcert, int_authcert)) {
		log_message(FATAL, DEBUG_AREA_MAIN,
			    "Invalid request_cert or auth_by_cert option");
		exit(EXIT_FAILURE);
	}

	/* We add the crl file function check every second only if we have a crl */
	if ( nuauth_tls.crl_file ) {
		cleanup_func_push(refresh_crl_file);
	}

	context->nussl = nussl_session_create_with_fd(context->sck_inet,
						      nuauth_tls.request_cert);
	if (!context->nussl ) {
		log_message(FATAL, DEBUG_AREA_MAIN,
			    "Cannot create session from fd!");
		exit(EXIT_FAILURE);
	}

	ret = nussl_ssl_set_keypair(context->nussl, nuauth_tls.cert, nuauth_tls.key);
	if ( ret != NUSSL_OK ) {
		log_message(FATAL, DEBUG_AREA_MAIN,
			    "Failed to load user key/certificate: %s",
			    nussl_get_error(context->nussl));
		exit(EXIT_FAILURE);
	}

	ret = nussl_ssl_trust_cert_file(context->nussl, nuauth_tls.ca);
	if ( ret != NUSSL_OK ) {
		log_message(FATAL, DEBUG_AREA_MAIN,
			    "Failed to load user certificate authority: %s",
			    nussl_get_error(context->nussl));
		exit(EXIT_FAILURE);
	}

	if (nuauth_tls.capath) {
		ret = nussl_ssl_trust_dir(context->nussl, nuauth_tls.capath);
		if ( ret != NUSSL_OK ) {
			log_message(FATAL, DEBUG_AREA_MAIN,
					"Failed to load user certificate authority directory: %s",
					nussl_get_error(context->nussl));
			exit(EXIT_FAILURE);
		}
	}

	if (nuauth_tls.crl_file) {
		ret = nussl_ssl_set_crl_file(context->nussl, nuauth_tls.crl_file, nuauth_tls.ca);
		if ( ret != NUSSL_OK ) {
			log_message(FATAL, DEBUG_AREA_MAIN,
					"Failed to load certificate revocation list (CRL): %s",
					nussl_get_error(context->nussl));
			exit(EXIT_FAILURE);
		}
	}

	ret = NUSSL_ERROR;
	if (dh_params_file) {
		ret = nussl_session_set_dh_file(context->nussl, dh_params_file);
	}
	if (ret != NUSSL_OK &&
	    nussl_session_set_dh_bits(context->nussl, DH_BITS) != NUSSL_OK) {
		log_message(FATAL, DEBUG_AREA_MAIN,
			    "Unable to initialize Diffie Hellman params.");
		exit(EXIT_FAILURE);
	}

	if (nuauth_tls.ciphers) {
		nussl_session_set_ciphers(context->nussl, nuauth_tls.ciphers);
	}

	return 1;
}

/**
 * Thread which process addresses on tls push queue (tls_push_queue member
 * of ::nuauthdatas) which need an authentication.
 *
 * Lock is only needed when modifications are done, because when this thread
 * work (push mode) it's the only one who can modify the hash.
 *
 * Use a switch:
 *   - #WARN_MESSAGE: call warn_clients() (and may call ip_authentication_workers())
 *   - #INSERT_MESSAGE: call add_client()
 */
void *push_worker(GMutex * mutex)
{
	struct msg_addr_set *global_msg = g_new0(struct msg_addr_set, 1);
	struct nu_srv_message *msg = g_new0(struct nu_srv_message, 1);
	struct internal_message *message;
	GTimeVal tv;

	msg->type = SRV_REQUIRED_PACKET;
	msg->option = 0;
	msg->length = htons(4);
	global_msg->msg = msg;

	g_async_queue_ref(nuauthdatas->tls_push_queue);

	/* wait for message */
	while (g_mutex_trylock(mutex)) {
		g_mutex_unlock(mutex);

		/* wait a message during POP_DELAY */
		g_get_current_time(&tv);
		g_time_val_add(&tv, POP_DELAY);
		message =
		    g_async_queue_timed_pop(nuauthdatas->tls_push_queue,
					    &tv);
		if (message == NULL)
			continue;

		switch (message->type) {
		case WARN_MESSAGE:
			global_msg->addr =
			    (((auth_pckt_t *) message->datas)->header).saddr;
			global_msg->found = FALSE;
			/* search in client array */
			warn_clients(global_msg, NULL, NULL);
			/* do we have found something */
			if (!ipv6_equal(&global_msg->addr, &in6addr_any)) {
				if (global_msg->found == FALSE) {
					/* if we do ip authentication send request to pool */
					if (nuauthconf->
					    do_ip_authentication) {
						thread_pool_push
						    (nuauthdatas->
						     ip_authentication_workers,
						     message->datas, NULL);
					} else {
						g_free(message->datas);
					}
				} else {
					/* free header */
					g_free(message->datas);
				}
			}
			break;

		case INSERT_MESSAGE:
			{
				struct tls_insert_data *data = message->datas;
				if (data->data) {
					add_client(data->socket,
						   data->data);
				}
				g_free(data);
			}
			break;
		default:
			g_message("lost");
		}
		g_free(message);
	}

	g_free(msg);
	g_free(global_msg);
	g_async_queue_unref(nuauthdatas->tls_push_queue);
	return NULL;
}



/**
 * TLS user packet server.
 * Thread function serving user connection.
 *
 * \return NULL
 */
void *tls_user_authsrv(struct nuauth_thread_t *thread)
{
	struct tls_user_context_t *context = thread->data;
	int ok = 0;

	ok = tls_user_init(context);

	if (ok) {
		tls_user_main_loop(context, thread->mutex);
	} else {
		nuauth_ask_exit();
	}
	return NULL;
}

void tls_user_start_servers(GSList *servers)
{
	char **user_servers;
	int i;
	nuauthdatas->tls_auth_servers = NULL;

	tls_user_servers_init();

	/* get raw string from configuration */
	user_servers = g_strsplit(nuauthconf->client_srv, " ", 0);
	for (i=0; user_servers[i]; i++) {
		/** \todo free context at program exit */
		struct tls_user_context_t *context =
			g_new0(struct tls_user_context_t, 1);
		struct nuauth_thread_t *srv_thread =
			g_new0(struct nuauth_thread_t, 1);
		if (!parse_addr_port(user_servers[i], nuauthconf->userpckt_port, &context->addr, &context->port)) {
			log_message(FATAL, DEBUG_AREA_MAIN | DEBUG_AREA_USER,
					"Address parsing error at %s:%d (\"%s\")", __FILE__,
					__LINE__, user_servers[i]);
			nuauth_ask_exit();
		}
		log_message(INFO, DEBUG_AREA_MAIN | DEBUG_AREA_USER,
			"Creating user socket %s:%s", context->addr, context->port);

		thread_new_wdata(srv_thread,
				 "tls auth server",
				 (gpointer) context,
				 tls_user_authsrv);
		/* Append newly created server to list */
		nuauthdatas->tls_auth_servers = g_slist_prepend(nuauthdatas->tls_auth_servers,
								srv_thread);
	}
	g_strfreev(user_servers);
}

/**
 * Refresh crl in the user contexts
 *
 */

void tls_crl_update_user_session(GSList *session)
{

	GSList *listrunner = session;
	int ret;

	while ( listrunner ) {
		struct nuauth_thread_t *nuauth_thread = listrunner->data;

		struct tls_user_context_t *context = nuauth_thread->data;

		// Don't update the CRL when nufw is not yet connected
		if (context->nussl == NULL) {
			listrunner = g_slist_next(listrunner);
			continue;
		}

		g_mutex_lock(nuauth_thread->mutex);
		ret = nussl_ssl_set_crl_file(context->nussl, nuauth_tls.crl_file, nuauth_tls.ca);

		if (ret != NUSSL_OK) {
			log_area_printf(DEBUG_AREA_USER, DEBUG_LEVEL_CRITICAL,
					"User TLS: CRL file reloading failed (%s)",
					nussl_get_error(context->nussl));
		}
		g_mutex_unlock(nuauth_thread->mutex);

		listrunner = g_slist_next(listrunner);

	}
	g_slist_free(listrunner);

}


/**
 * @}
 */

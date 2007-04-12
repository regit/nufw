/*
 ** Copyright(C) 2004-2006 INL
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

/**
 * \ingroup TLS
 * \defgroup TLSUser TLS User server
 * @{
 */

/** \file tls_user.c
 *  \brief Manage clients connections and messages.
 *
 * The thread tls_user_authsrv() wait for clients in tls_user_main_loop().
 */

extern int nuauth_tls_auth_by_cert;
struct tls_user_context_t tls_user_context;

/**
 * List of new clients which are in authentification state. This list is
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
 * Check pre client list to disconnect connection
 * that are open since too long
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
 * \return a nu_error_t::, NU_EXIT_CONTINUE if read done, NU_EXIT_OK if read complete, NU_EXIT_ERROR on error
 */
static nu_error_t treat_user_request(user_session_t * c_session)
{
	struct tls_buffer_read *datas;
	int header_length;
	struct nu_header *header;

	if (c_session == NULL)
		return NU_EXIT_ERROR;

	datas = g_new0(struct tls_buffer_read, 1);
	if (datas == NULL)
		return NU_EXIT_ERROR;
	datas->socket = 0;
	datas->tls = c_session->tls;
	datas->ip_addr = c_session->addr;
	datas->client_version = c_session->client_version;

	/* copy packet datas */
	datas->buffer = g_new0(char, CLASSIC_NUFW_PACKET_SIZE);
	if (datas->buffer == NULL) {
		g_free(datas);
		return NU_EXIT_ERROR;
	}
	g_mutex_lock(c_session->tls_lock);
	datas->buffer_len =
	    gnutls_record_recv(*(c_session->tls), datas->buffer,
			       CLASSIC_NUFW_PACKET_SIZE);
	g_mutex_unlock(c_session->tls_lock);
	if (datas->buffer_len < (int) sizeof(struct nu_header)) {
#ifdef DEBUG_ENABLE
		if (datas->buffer_len < 0)
			log_message(DEBUG, DEBUG_AREA_USER,
				    "Received error from user %s",
				    c_session->user_name);
#endif
		free_buffer_read(datas);
		return NU_EXIT_OK;
	}

	/* get header to check if we need to get more datas */
	header = (struct nu_header *) datas->buffer;
	header_length = ntohs(header->length);

	/* is it an "USER HELLO" message ? */
	if (header->proto == PROTO_VERSION
	    && header->msg_type == USER_HELLO) {
		debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
				  "tls user: HELLO from %s",
				  c_session->user_name);
		free_buffer_read(datas);
		return NU_EXIT_CONTINUE;
	}

	/* if message content is bigger than CLASSIC_NUFW_PACKET_SIZE, */
	/* continue to read the content */
	if (header->proto == PROTO_VERSION
	    && header_length > datas->buffer_len
	    && header_length < MAX_NUFW_PACKET_SIZE) {
		int tmp_len;

		/* we realloc and get what we miss */
		datas->buffer = g_realloc(datas->buffer, header_length);
		header = (struct nu_header *) datas->buffer;

		g_mutex_lock(c_session->tls_lock);
		tmp_len =
		    gnutls_record_recv(*(c_session->tls),
				       datas->buffer +
				       CLASSIC_NUFW_PACKET_SIZE,
				       header_length - datas->buffer_len);
		g_mutex_unlock(c_session->tls_lock);
		if (tmp_len < 0) {
			free_buffer_read(datas);
			return NU_EXIT_ERROR;
		}
		datas->buffer_len += tmp_len;
	}

	/* check message type because USER_HELLO has to be ignored */
	if (header->msg_type == USER_HELLO) {
		return NU_EXIT_CONTINUE;
	}

	/* check authorization if we're facing a multi user packet */
	if (header->option == 0x0) {
		/* this is an authorized packet we fill the buffer_read structure */
		datas->user_name = g_strdup(c_session->user_name);
		datas->user_id = c_session->user_id;
		datas->groups = g_slist_copy(c_session->groups);
		if (c_session->sysname) {
			datas->os_sysname = g_strdup(c_session->sysname);
			if (datas->os_sysname == NULL) {
				free_buffer_read(datas);
				return NU_EXIT_ERROR;
			}
		}
		if (c_session->release) {
			datas->os_release = g_strdup(c_session->release);
			if (datas->os_release == NULL) {
				free_buffer_read(datas);
				return NU_EXIT_ERROR;
			}
		}
		if (c_session->version) {
			datas->os_version = g_strdup(c_session->version);
			if (datas->os_version == NULL) {
				free_buffer_read(datas);
				return NU_EXIT_ERROR;
			}
		}

		debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN | DEBUG_AREA_USER,
				  "Pushing packet to user_checker");
		thread_pool_push(nuauthdatas->user_checkers, datas,
				   NULL);
	} else {
		log_message(INFO, DEBUG_AREA_USER,
			    "Bad packet, option of header is not set or unauthorized option from user %s.",
			    c_session->user_name);
		free_buffer_read(datas);
		return NU_EXIT_OK;
	}
	return NU_EXIT_CONTINUE;
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

	/* Wait for a connect */
	socket = accept(context->sck_inet,
			(struct sockaddr *) &sockaddr, &len_inet);
	if (socket == -1) {
		log_message(WARNING, DEBUG_AREA_USER, "accept");
	}

	/* if system is in reload: drop new client */
	if (nuauthdatas->need_reload) {
		shutdown(socket, SHUT_RDWR);
		close(socket);
		return 0;
	}

	if (get_number_of_clients() >= context->nuauth_tls_max_clients) {
		log_message(WARNING, DEBUG_AREA_MAIN | DEBUG_AREA_USER,
			    "too many clients (%d configured)",
			    context->nuauth_tls_max_clients);
		shutdown(socket, SHUT_RDWR);
		close(socket);
		return 1;
	}

	/* Extract client address (convert it to IPv6 if it's IPv4) */
	if (sockaddr.ss_family == AF_INET) {
		addr.s6_addr32[0] = 0;
		addr.s6_addr32[1] = 0;
		addr.s6_addr32[2] = 0xffff0000;
		addr.s6_addr32[3] = sockaddr4->sin_addr.s_addr;
		sport = ntohs(sockaddr4->sin_port);
	} else {
		addr = sockaddr6->sin6_addr;
		sport = ntohs(sockaddr6->sin6_port);
	}

	current_client_conn = g_new0(struct client_connection, 1);
	current_client_conn->socket = socket;
	current_client_conn->addr = addr;
	current_client_conn->sport = sport;

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
void tls_user_check_activity(struct tls_user_context_t *context,
			     int socket)
{
	user_session_t *c_session;
	int u_request;
	debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
			  "user activity on socket %d", socket);

	/* we lock here but can do other thing on hash as it is not destructive
	 * in push mode modification of hash are done in push_worker */
	c_session = get_client_datas_by_socket(socket);

	if (nuauthconf->session_duration && c_session->expire < time(NULL)) {
		delete_client_by_socket(socket);
		return;
	}

	u_request = treat_user_request(c_session);
	if (u_request == NU_EXIT_OK) {
		debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
				  "client disconnect on socket %d",
				  socket);
		/* clean client structure */
		delete_client_by_socket(socket);
	} else if (u_request != NU_EXIT_CONTINUE) {
#ifdef DEBUG_ENABLE
		log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
			    "treat_user_request() failure");
#endif
		/* better to disconnect: cleaning client structure */
		delete_client_by_socket(socket);
	}
}

/**
 * Fix this->mx value if needed (after changing this->tls_rx_set)
 *
 * This function has to be called when mutex is locked.
 */
void tls_user_update_mx(struct tls_user_context_t *this)
{
	int i;
	for (i = this->mx - 1;
			i >= 0 && !FD_ISSET(i, &this->tls_rx_set);
			i = this->mx - 1) {
		debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
				"setting mx to %d", i);
		this->mx = i;
	}
}

/**
 * Remove a client from rx set
 *
 * This function has to be called when mutex is locked.
 */
void tls_user_remove_client(struct tls_user_context_t *this, int sock)
{
	FD_CLR(sock, &this->tls_rx_set);
	tls_user_update_mx(this);
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
	gpointer c_pop;
	int i, nb_active_clients;
	fd_set wk_set;		/* working set */
	struct timeval tv;
	disconnect_user_msg_t *disconnect_msg;

	log_message(INFO, DEBUG_AREA_USER,
		    "[+] NuAuth is waiting for client connections.");
	while (g_mutex_trylock(mutex)) {
		g_mutex_unlock(mutex);

		/*
		 * Try to get new file descriptor to update set. Messages come from
		 * tls_sasl_connect_ok() and are send when a new user is connected.
		 */
		c_pop = g_async_queue_try_pop(mx_queue);
		while (c_pop != NULL) {
			int socket = GPOINTER_TO_INT(c_pop);

			debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
					  "checking mx against %d",
					  socket);
			if (socket + 1 > context->mx)
				context->mx = socket + 1;
			/*
			 * change FD_SET
			 */
			FD_SET(socket, &context->tls_rx_set);
			activate_client_by_socket(socket);
			c_pop = g_async_queue_try_pop(mx_queue);
		}

		/*
		 * execute client destruction task
		 */
		while ((disconnect_msg = g_async_queue_try_pop(context->cmd_queue)) != NULL){
			if (disconnect_msg->socket == -1) {
				disconnect_msg->result = kill_all_clients();
			} else {
				disconnect_msg->result = delete_client_by_socket(disconnect_msg->socket);
			}
			g_mutex_unlock(disconnect_msg->mutex);
		}

		/* wait new events during 1 second */
		FD_ZERO(&wk_set);
		for (i = 0; i < context->mx; ++i) {
			if (FD_ISSET(i, &context->tls_rx_set))
				FD_SET(i, &wk_set);
		}
		tv.tv_sec = 0;
		tv.tv_usec = 250000;
		nb_active_clients =
		    select(context->mx, &wk_set, NULL, NULL, &tv);

		/* catch select() error */
		if (nb_active_clients == -1) {
			/* Signal was catched: just ignore it */
			if (errno == EINTR) {
				log_message(CRITICAL, DEBUG_AREA_USER,
					    "Warning: tls user select() failed: signal was catched.");
				continue;
			}

			log_message(FATAL, DEBUG_AREA_MAIN | DEBUG_AREA_USER,
				    "select() %s:%d failure: %s",
				    __FILE__, __LINE__, g_strerror(errno));
			nuauth_ask_exit();
			break;
		} else if (nb_active_clients > 0) {
			/*
			 * Check if a connect has occured
			 */
			if (FD_ISSET(context->sck_inet, &wk_set)) {
				if (tls_user_accept(context) != 0)
					continue;
			}

			/*
			 * check for client activity
			 */
			for (i = 0; i < context->mx; ++i) {
				if (i == context->sck_inet)
					continue;
				if (FD_ISSET(i, &wk_set))
					tls_user_check_activity(context, i);
			}
		}
		tls_user_update_mx(context);
	}

	close(context->sck_inet);
}

/**
 * Bind TLS user socket
 */
int tls_user_bind(char **errmsg)
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
	ecode =
	    getaddrinfo(nuauthconf->client_srv, nuauthconf->userpckt_port,
			&hints, &res);
	if (ecode != 0) {
		*errmsg =
		    g_strdup_printf
		    ("Invalid clients listening address %s:%s, error: %s",
		     nuauthconf->client_srv, nuauthconf->userpckt_port,
		     gai_strerror(ecode));
		return -1;
	}

	/* open the socket */
	if (res->ai_family == PF_INET)
		log_message(DEBUG, DEBUG_AREA_USER | DEBUG_AREA_MAIN,
			    "Create user server IPv4 socket");
	else if (res->ai_family == PF_INET6)
		log_message(DEBUG, DEBUG_AREA_USER | DEBUG_AREA_MAIN,
			    "Create user server IPv6 socket");

		log_message(DEBUG, DEBUG_AREA_USER | DEBUG_AREA_MAIN,
			    "Create user server (any) socket");
	sck_inet =
	    socket(res->ai_family, res->ai_socktype, res->ai_protocol);
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
		*errmsg = g_strdup_printf("Unable to bind %s:%s.",
					  nuauthconf->client_srv,
					  nuauthconf->userpckt_port);
		close(sck_inet);
		return -1;
	}
	freeaddrinfo(res);
	return sck_inet;
}

/**
 * Create TLS user context.
 */
int tls_user_init(struct tls_user_context_t *context)
{
	confparams_t nuauth_tls_vars[] = {
		{"nuauth_tls_max_clients", G_TOKEN_INT,
		 NUAUTH_TLS_MAX_CLIENTS, NULL},
		{"nuauth_number_authcheckers", G_TOKEN_INT, NB_AUTHCHECK,
		 NULL},
		{"nuauth_auth_nego_timeout", G_TOKEN_INT,
		 AUTH_NEGO_TIMEOUT, NULL}
	};
	char *errmsg;
	int result;

	context->sck_inet = tls_user_bind(&errmsg);
	if (context->sck_inet < 0) {
		log_message(FATAL, DEBUG_AREA_MAIN | DEBUG_AREA_USER,
			    "FATAL ERROR: User bind error: %s", errmsg);
		log_message(FATAL, DEBUG_AREA_MAIN | DEBUG_AREA_USER,
			    "Check that nuauth is not running twice. Exit nuauth!");
		return 0;
	}

	/* get config file setup */
	/* parse conf file */
	parse_conffile(DEFAULT_CONF_FILE,
		       sizeof(nuauth_tls_vars) / sizeof(confparams_t),
		       nuauth_tls_vars);

#define READ_CONF(KEY) \
	get_confvar_value(nuauth_tls_vars, sizeof(nuauth_tls_vars)/sizeof(confparams_t), KEY)

	context->nuauth_tls_max_clients =
	    *(unsigned int *) READ_CONF("nuauth_tls_max_clients");
	context->nuauth_number_authcheckers =
	    *(int *) READ_CONF("nuauth_number_authcheckers");
	context->nuauth_auth_nego_timeout =
	    *(int *) READ_CONF("nuauth_auth_nego_timeout");
#undef READ_CONF

	/* free config struct */
	free_confparams(nuauth_tls_vars,
			sizeof(nuauth_tls_vars) / sizeof(confparams_t));

	context->cmd_queue =  g_async_queue_new();
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
			      context->nuauth_number_authcheckers, TRUE,
			      NULL);

	/* listen */
	result = listen(context->sck_inet, 20);
	if (result == -1) {
		g_error("user listen() failed, exiting");
		return 0;
	}

	/* init fd_set */
	FD_ZERO(&context->tls_rx_set);
	FD_SET(context->sck_inet, &context->tls_rx_set);
	context->mx = context->sck_inet + 1;
	mx_queue = g_async_queue_new();
	return 1;
}

/**
 * Thread which process addresses on tls push queue (tls_push_queue member
 * of ::nuauthdatas) which need an authentification.
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

		/* wait a message during 1000ms */
		g_get_current_time(&tv);
		g_time_val_add(&tv, 1000);
		message =
		    g_async_queue_timed_pop(nuauthdatas->tls_push_queue,
					    &tv);
		if (message == NULL)
			continue;

		switch (message->type) {
		case WARN_MESSAGE:
			global_msg->addr =
			    ((tracking_t *) message->datas)->saddr;
			global_msg->found = FALSE;
			/* search in client array */
			warn_clients(global_msg);
			/* do we have found something */
			if (memcmp
			    (&global_msg->addr, &in6addr_any,
			     sizeof(in6addr_any)) != 0) {
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
				struct tls_insert_data *datas =
				    message->datas;
				if (datas->data) {
					add_client(datas->socket,
						   datas->data);
				}
				g_free(datas);
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
void *tls_user_authsrv(GMutex * mutex)
{
	int ok = tls_user_init(&tls_user_context);
	if (ok) {
		tls_user_main_loop(&tls_user_context, mutex);
	} else {
		nuauth_ask_exit();
	}
	return NULL;
}


/**
 * @}
 */

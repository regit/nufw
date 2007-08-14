/*
 ** Copyright(C) 2004-2007 INL
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
 * \defgroup TLSNufw TLS Nufw server
 * @{
 */

/** \file tls_nufw.c
 * \brief Manage NuFW firewall connections and messages.
 *
 * The main thread is tls_nufw_authsrv() which call tls_nufw_main_loop().
 */


struct tls_nufw_context_t {
	int mx;
	int sck_inet;
	fd_set tls_rx_set;	/* read set */
};

/**
 * Get RX paquet from a TLS client connection and send it to user
 * authentication threads:
 *   - nuauthdatas->localid_auth_queue (see ::localid_auth()), if connection
 *     state is #AUTH_STATE_HELLOMODE
 *   - nuauthdatas->connections_queue (see search_and_fill()), otherwise
 *
 * \param c_session SSL RX packet
 * \return Returns 1 if read is done, EOF if read is completed
 */
static int treat_nufw_request(nufw_session_t * c_session)
{
	unsigned char cdgram[CLASSIC_NUFW_PACKET_SIZE];
	unsigned char *dgram = cdgram;
	int dgram_size;
	connection_t *current_conn;
	int ret;

	if (c_session == NULL)
		return NU_EXIT_OK;

	/* read data from nufw */
	g_mutex_lock(c_session->tls_lock);
	dgram_size =
	    gnutls_record_recv(*(c_session->tls), dgram,
			       CLASSIC_NUFW_PACKET_SIZE);
	g_mutex_unlock(c_session->tls_lock);
	if (dgram_size < 0) {
		log_message(INFO, DEBUG_AREA_GW,
			    "nufw failure at %s:%d (%s)", __FILE__,
			    __LINE__,gnutls_strerror(dgram_size));
		return NU_EXIT_ERROR;
	} else if (dgram_size == 0) {
		log_message(INFO, DEBUG_AREA_GW,
			    "nufw disconnect at %s:%d",
			    __FILE__,
			    __LINE__);
		return NU_EXIT_ERROR;
	}
	/* Bad luck, this is first packet, we have to test nufw proto version */
	if (c_session->proto_version == PROTO_UNKNOWN) {
		c_session->proto_version =
		    get_proto_version_from_packet(dgram,
						  (size_t) dgram_size);
		if (!c_session->proto_version) {
			return NU_EXIT_ERROR;
		}
	}
	/* decode data */
	do {
		ret =
		    authpckt_decode(&dgram, (unsigned int *) &dgram_size,
				    &current_conn);
		switch (ret) {
		case NU_EXIT_ERROR:
			return NU_EXIT_ERROR;
		case NU_EXIT_OK:
			if (current_conn != NULL) {
				current_conn->socket = 0;
				/* session will be used by created element */
				increase_nufw_session_usage(c_session);
				current_conn->tls = c_session;

				/* gonna feed the birds */
				if (current_conn->state ==
				    AUTH_STATE_HELLOMODE) {
					debug_log_message(DEBUG, DEBUG_AREA_GW,
							  "(*) NuFW auth request (hello mode): packetid=%u",
							  (uint32_t)
							  GPOINTER_TO_UINT
							  (current_conn->
							   packet_id->
							   data));
					struct internal_message *message =
					    g_new0(struct internal_message,
						   1);
					message->type = INSERT_MESSAGE;
					message->datas = current_conn;
					current_conn->state =
					    AUTH_STATE_AUTHREQ;
					g_async_queue_push(nuauthdatas->
							   localid_auth_queue,
							   message);
				} else {
					debug_log_message(DEBUG, DEBUG_AREA_GW,
							  "(*) NuFW auth request (nufw mode): packetid=%u",
							  (uint32_t)
							  GPOINTER_TO_UINT
							  (current_conn->
							   packet_id->
							   data));
					g_async_queue_push(nuauthdatas->
							   connections_queue,
							   current_conn);
				}
			}
			break;
		case NU_EXIT_NO_RETURN:
			debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_GW,
				"Nufw gateway send control message");
			break;
		}
#if 0
		g_message("dgram_size at %d: %d", __LINE__, dgram_size);
#endif
	} while (dgram_size > 0);

	return NU_EXIT_OK;
}



/**
 * Function called on new NuFW connection: create a new TLS session using
 * tls_connect().
 *
 * \return If an error occurs returns 1, else returns 0.
 */
int tls_nufw_accept(struct tls_nufw_context_t *context)
{
	int conn_fd;
	struct sockaddr_storage sockaddr;
	struct sockaddr_in *sockaddr4 = (struct sockaddr_in *) &sockaddr;
	struct sockaddr_in6 *sockaddr6 = (struct sockaddr_in6 *) &sockaddr;
	struct in6_addr addr;
	char addr_ascii[INET6_ADDRSTRLEN];
	unsigned int len_inet;
	nufw_session_t *nu_session;

	/* Accept the connection */
	len_inet = sizeof sockaddr;
	conn_fd = accept(context->sck_inet,
			 (struct sockaddr *) &sockaddr, &len_inet);
	if (conn_fd == -1) {
		log_message(WARNING, DEBUG_AREA_GW, "accept");
	}

	/* Extract client address (convert it to IPv6 if it's IPv4) */
	if (sockaddr6->sin6_family == AF_INET) {
		ipv4_to_ipv6(sockaddr4->sin_addr, &addr);
	} else {
		addr = sockaddr6->sin6_addr;
	}

	/* test if server is in the list of authorized servers */
	if (!check_inaddr_in_array(&addr, nuauthconf->authorized_servers)) {
		if (inet_ntop
		    (AF_INET6, &addr, addr_ascii,
		     sizeof(addr_ascii)) != NULL)
			log_message(WARNING, DEBUG_AREA_GW,
				    "unwanted nufw server (%s)",
				    addr_ascii);
		close(conn_fd);
		return 1;
	}
#if 0
	if (conn_fd >= nuauth_tls_max_servers) {
		log_message(WARNING, DEBUG_AREA_GW,
			    "too much servers (%d configured)",
			    nuauth_tls_max_servers);
		close(conn_fd);
		continue;
	}
#endif

	/* initialize TLS */
	nu_session = g_new0(nufw_session_t, 1);
	nu_session->connect_timestamp = time(NULL);
	nu_session->usage = 1;
	nu_session->alive = TRUE;
	nu_session->peername = addr;
	nu_session->socket = conn_fd;
	/* We have to wait the first packet */
	nu_session->proto_version = PROTO_UNKNOWN;
	if (tls_connect(conn_fd, &(nu_session->tls)) == SASL_OK) {
		nu_session->tls_lock = g_mutex_new();
		add_nufw_server(conn_fd, nu_session);
		FD_SET(conn_fd, &context->tls_rx_set);
		if (conn_fd + 1 > context->mx)
			context->mx = conn_fd + 1;
		g_message("[+] NuFW: new client connected on socket %d",
			  conn_fd);
	} else {
		g_free(nu_session);
	}
	return 0;
}

/**
 * NuFW TLS thread main loop:
 *   - Wait events (message/new connection) using select() with a timeout
 *     of one second
 *   - Accept new connections: call tls_nufw_accept()
 *   - Read and process new packets using treat_nufw_request()
 */
void tls_nufw_main_loop(struct tls_nufw_context_t *context, GMutex * mutex)
{
	int n, c, z;
	fd_set wk_set;		/* working set */
	struct timeval tv;

	log_message(INFO, DEBUG_AREA_GW,
		    "[+] NuAuth is waiting for NuFW connections.");
	while (g_mutex_trylock(mutex)) {
		g_mutex_unlock(mutex);

		/* copy rx set to working set */
		FD_ZERO(&wk_set);
		for (z = 0; z < context->mx; ++z) {
			if (FD_ISSET(z, &context->tls_rx_set))
				FD_SET(z, &wk_set);
		}

		/* wait new events during 1 second */
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		n = select(context->mx, &wk_set, NULL, NULL, &tv);
		if (n == -1) {
			/* Signal was catched: just ignore it */
			if (errno == EINTR) {
				log_message(CRITICAL, DEBUG_AREA_GW,
					    "Warning: tls nufw select() failed: signal was catched.");
				continue;
			}

			log_message(FATAL, DEBUG_AREA_MAIN | DEBUG_AREA_GW,
				    "select() %s:%u failure: %s",
				    __FILE__, __LINE__, g_strerror(errno));
			nuauth_ask_exit();
			break;
		} else if (!n) {
			continue;
		}

		/* Check if a connect has occured */
		if (FD_ISSET(context->sck_inet, &wk_set)) {
			if (tls_nufw_accept(context)) {
				continue;
			}
		}

		/* check for server activity */
		for (c = 0; c < context->mx; ++c) {
			if (c == context->sck_inet)
				continue;

			if (FD_ISSET(c, &wk_set)) {
				nufw_session_t *c_session;
				debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_GW,
						  "nufw activity on socket %d",
						  c);
				c_session =
					acquire_nufw_session_by_socket(c);
				g_assert(c_session);
				if (treat_nufw_request(c_session) ==
				    NU_EXIT_ERROR) {
					/* get session link with c */
					debug_log_message(DEBUG, DEBUG_AREA_GW,
							  "nufw server disconnect on %d",
							  c);
					FD_CLR(c, &context->tls_rx_set);
					declare_dead_nufw_session(c_session);
				}
				release_nufw_session(c_session);
			}
		}

		for (c = context->mx - 1;
		     c >= 0 && !FD_ISSET(c, &context->tls_rx_set);
		     c = context->mx - 1) {
			context->mx = c;
		}
	}
	close(context->sck_inet);
}

int tls_nufw_bind(char **errmsg)
{
	return nuauth_bind(errmsg, nuauthconf->nufw_srv, nuauthconf->authreq_port, "user") ;
}

/**
 * Initialize the NuFW TLS servers thread
 */
int tls_nufw_init(struct tls_nufw_context_t *context)
{
	int socket_fd;
	char *errmsg;

	context->sck_inet = tls_nufw_bind(&errmsg);
	if (context->sck_inet < 0) {
		log_message(FATAL, DEBUG_AREA_GW | DEBUG_AREA_MAIN,
			    "FATAL ERROR: NuFW bind error: %s", errmsg);
		log_message(FATAL, DEBUG_AREA_GW | DEBUG_AREA_MAIN,
			    "Check that nuauth is not running twice. Exit nuauth!");
		return 0;
	}
#if 0
	struct sigaction action;

	char *configfile = DEFAULT_CONF_FILE;
	gpointer vpointer;
	confparams_t nuauth_tls_vars[] = {
		{"nuauth_tls_max_servers", G_TOKEN_INT,
		 NUAUTH_TLS_MAX_SERVERS, NULL}
	};
	int nuauth_tls_max_servers = NUAUTH_TLS_MAX_SERVERS;
	/* get config file setup */
	/* parse conf file */
	parse_conffile(configfile,
		       sizeof(nuauth_tls_vars) / sizeof(confparams_t),
		       nuauth_tls_vars);
	/* set variable value from config file */
	vpointer =
	    get_confvar_value(nuauth_tls_vars,
			      sizeof(nuauth_tls_vars) / sizeof(confparams_t),
			      "nuauth_tls_max_servers");
	nuauth_tls_max_servers =
	    *(int *) (vpointer ? vpointer : &nuauth_tls_max_servers);
#endif

	/* Listen ! */
	socket_fd = listen(context->sck_inet, 20);
	if (socket_fd == -1) {
		g_error("nufw listen() failed, exiting");
		return 0;
	}

	/* build servers hash */
	init_nufw_servers();

	/* init fd_set */
	context->mx = context->sck_inet + 1;

	FD_ZERO(&context->tls_rx_set);
	FD_SET(context->sck_inet, &context->tls_rx_set);
	return 1;
}

/**
 * TLS nufw packet server thread: call tls_nufw_init() and then live
 * in tls_nufw_main_loop().
 *
 * \return NULL
 */
void *tls_nufw_authsrv(GMutex * mutex)
{
	struct tls_nufw_context_t context;
	int ok;
	ok = tls_nufw_init(&context);
	if (ok) {
		tls_nufw_main_loop(&context, mutex);
	} else {
		nuauth_ask_exit();
	}
	return NULL;
}

/**
 * @}
 */

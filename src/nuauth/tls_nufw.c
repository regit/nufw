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

#include <nubase.h>
#include <nussl.h>

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

int nuauth_tls_max_servers = NUAUTH_TLS_MAX_SERVERS;
static int nufw_servers_connected = 0;

extern struct nuauth_tls_t nuauth_tls;


struct tls_nufw_context_t {
	char *addr;
	char *port;
	int mx;
	int sck_inet;
	fd_set tls_rx_set;	/* read set */
	GMutex *mutex;

	nussl_session *server;
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
/*	g_mutex_lock(c_session->tls_lock); */
	dgram_size = nussl_read(c_session->nufw_client, (char *)dgram, CLASSIC_NUFW_PACKET_SIZE);
/*	g_mutex_unlock(c_session->tls_lock);*/
	if (dgram_size < 0) {
		log_message(INFO, DEBUG_AREA_GW,
			    "nufw failure at %s:%d (%s)", __FILE__,
			    __LINE__, nussl_get_error(c_session->nufw_client));
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
		ret = authpckt_decode(&dgram, (unsigned int *) &dgram_size,
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
#if 0
	struct in6_addr addr;
	char addr_ascii[INET6_ADDRSTRLEN];
#endif
	socklen_t len_inet;

	nufw_session_t *nu_session;

#if 0 /* XXX: nuauthconf->authorized_servers is always set as NULL */
	/* test if server is in the list of authorized servers */
	if (!check_inaddr_in_array(&addr, nuauthconf->authorized_servers)) {
		FORMAT_IPV6(&addr, addr_ascii);
		log_message(WARNING, DEBUG_AREA_GW,
				"unwanted nufw server (%s)", addr_ascii);
		close(conn_fd);
		return 1;
	}
#endif

	/* Check number of connected servers */
	if ( nufw_servers_connected >= nuauth_tls_max_servers ) {
		log_area_printf(DEBUG_AREA_GW, DEBUG_LEVEL_WARNING,
				"too many servers (%d configured)",
				nuauth_tls_max_servers);
		return 1;
	}

	/* initialize TLS */
	nu_session = g_new0(nufw_session_t, 1);

	nu_session->connect_timestamp = time(NULL);
	nu_session->usage = 1;
	nu_session->alive = TRUE;

	/* We have to wait the first packet */
	nu_session->proto_version = PROTO_UNKNOWN;

	nu_session->nufw_client = nussl_session_accept(context->server);
	if ( ! nu_session->nufw_client ) {
		g_free(nu_session);
		log_area_printf(DEBUG_AREA_GW, DEBUG_LEVEL_WARNING,
				"Unable to allocate nufw server connection : %s",
				nussl_get_error(context->server));
		return 1;
	}

	nufw_servers_connected++;

	if (nussl_session_getpeer(nu_session->nufw_client, (struct sockaddr *) &sockaddr, &len_inet) != NUSSL_OK)
	{
		log_area_printf(DEBUG_AREA_GW, DEBUG_LEVEL_WARNING,
				"Unable to get peername of NuFW dameon : %s",
				nussl_get_error(nu_session->nufw_client));
		g_free(nu_session);
		nussl_session_destroy(nu_session->nufw_client);
		return 1;
	}

	/* Extract client address (convert it to IPv6 if it's IPv4) */
	if (sockaddr6->sin6_family == AF_INET) {
		ipv4_to_ipv6(sockaddr4->sin_addr, &nu_session->peername);
	} else {
		nu_session->peername = sockaddr6->sin6_addr;
	}

	conn_fd = nussl_session_get_fd(nu_session->nufw_client);

	nu_session->tls_lock = g_mutex_new();
	add_nufw_server(conn_fd, nu_session);
	FD_SET(conn_fd, &context->tls_rx_set);
	if (conn_fd + 1 > context->mx)
		context->mx = conn_fd + 1;
	g_message("[+] NuFW: new client connected on socket %d",
		  conn_fd);

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

/* XXX: TODO: BUZZWORD: Destroy the nussl session */
			if (errno == EBADF) {
				int i;
				/* A client disconnects between FD_SET and select.
				 * Will try to find it */
				for (i=0; i<context->mx; ++i){
					struct stat s;
					if (FD_ISSET(i, &context->tls_rx_set)){
						if (fstat(i, &s)<0) {
							log_message(CRITICAL, DEBUG_AREA_USER,
									"Warning: %d is a bad file descriptor.", i);
							FD_CLR(i, &context->tls_rx_set);
						}
					}
				}
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

/**
 * Initialize the NuFW TLS servers thread
 * 0 if error, 1 on success
 */
int tls_nufw_init(struct tls_nufw_context_t *context)
{
	int socket_fd;
	char *errmsg;

/* config init */
	char *nuauth_tls_key = NULL;
	char *nuauth_tls_cert = NULL;
	char *nuauth_tls_cacert = NULL;
	char *nuauth_tls_key_passwd = NULL;
	char *nuauth_tls_crl = NULL;
	char *configfile = DEFAULT_CONF_FILE;
	int ret;
	/* TODO: read values specific to nufw connection */
	confparams_t nuauth_tls_vars[] = {
		{"nuauth_tls_key", G_TOKEN_STRING, 0,
		 g_strdup(NUAUTH_KEYFILE)},
		{"nuauth_tls_cert", G_TOKEN_STRING, 0,
		 g_strdup(NUAUTH_CERTFILE)},
		{"nuauth_tls_cacert", G_TOKEN_STRING, 0,
		 g_strdup(NUAUTH_CACERTFILE)},
		{"nuauth_tls_crl", G_TOKEN_STRING, 0, NULL},
		{"nuauth_tls_crl_refresh", G_TOKEN_INT,
		 DEFAULT_REFRESH_CRL_INTERVAL, NULL},
		{"nuauth_tls_key_passwd", G_TOKEN_STRING, 0, NULL},
		{"nuauth_tls_request_cert", G_TOKEN_INT, FALSE, NULL},
		{"nuauth_tls_auth_by_cert", G_TOKEN_INT, FALSE, NULL},
		{"nuauth_tls_max_servers", G_TOKEN_INT, NUAUTH_TLS_MAX_SERVERS, NULL}
	};
	const unsigned int nb_params = sizeof(nuauth_tls_vars) / sizeof(confparams_t);
	int int_requestcert;

	context->sck_inet = nuauth_bind(&errmsg, context->addr, context->port, "nufw");
	if (context->sck_inet < 0) {
		log_message(FATAL, DEBUG_AREA_GW | DEBUG_AREA_MAIN,
			    "FATAL ERROR: NuFW bind error: %s", errmsg);
		log_message(FATAL, DEBUG_AREA_GW | DEBUG_AREA_MAIN,
			    "Check that nuauth is not running twice. Exit nuauth!");
		return 0;
	}
#if 0 /* XXX: Already commented in 2.2 */
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
	if(!parse_conffile(configfile,
		       sizeof(nuauth_tls_vars) / sizeof(confparams_t),
		       nuauth_tls_vars))
	{
	        log_message(FATAL, DEBUG_AREA_MAIN, "Failed to load config file %s", configfile);
		return 0;
	}

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


	/* init fd_set */
	context->mx = context->sck_inet + 1;

	FD_ZERO(&context->tls_rx_set);
	FD_SET(context->sck_inet, &context->tls_rx_set);

	if(!parse_conffile(configfile, nb_params, nuauth_tls_vars))
	{
	        log_message(FATAL, DEBUG_AREA_MAIN, "Failed to load config file %s", configfile);
		return 0;
	}
#define READ_CONF(KEY) \
	get_confvar_value(nuauth_tls_vars, nb_params, KEY)
	nuauth_tls_key = (char *) READ_CONF("nuauth_tls_key");
	nuauth_tls_cert = (char *) READ_CONF("nuauth_tls_cert");
	nuauth_tls_cacert = (char *) READ_CONF("nuauth_tls_cacert");
	nuauth_tls_crl = (char *) READ_CONF("nuauth_tls_crl");
	nuauth_tls_key_passwd = (char *) READ_CONF("nuauth_tls_key_passwd");
	nuauth_tls_max_servers = *(int *) READ_CONF("nuauth_tls_max_servers");
	int_requestcert = *(int *) READ_CONF("nuauth_tls_request_cert");
#if 0
	nuauth_tls.crl_refresh =
	    *(int *) READ_CONF("nuauth_tls_crl_refresh");
#endif
#undef READ_CONF

	/* free config struct */
	free_confparams(nuauth_tls_vars,
			sizeof(nuauth_tls_vars) / sizeof(confparams_t));

	g_free(nuauth_tls_crl);
	g_free(nuauth_tls_key_passwd);

	/* TODO: use a nufw specific value of request_cert */
	context->server = nussl_session_create_with_fd(context->sck_inet, nuauth_tls.request_cert);
	if ( ! context->server ) {
		g_error("Cannot create session from fd!");
		return 0;
	}

	ret = nussl_ssl_set_keypair(context->server, nuauth_tls_cert, nuauth_tls_key);
	if ( ret != NUSSL_OK ) {
		g_error("Failed to load nufw key/certificate: %s", nussl_get_error(context->server));
		g_free(nuauth_tls_key);
		g_free(nuauth_tls_cert);
		g_free(nuauth_tls_cacert);
		return 0;
	}
	g_free(nuauth_tls_key);
	g_free(nuauth_tls_cert);

	ret = nussl_ssl_trust_cert_file(context->server, nuauth_tls_cacert);
	if ( ret != NUSSL_OK ) {
		g_error("Failed to load nufw trust certificate: %s", nussl_get_error(context->server));
		g_free(nuauth_tls_cacert);
		return 0;
	}
	g_free(nuauth_tls_cacert);

	return 1;
}

/**
 * TLS nufw packet server thread: call tls_nufw_init() and then live
 * in tls_nufw_main_loop().
 *
 * \return NULL
 */
void *tls_nufw_authsrv(struct nuauth_thread_t *thread)
{
	struct tls_nufw_context_t *context = thread->data;
	int ok;
	ok = tls_nufw_init(context);
	if (ok) {
		tls_nufw_main_loop(context, thread->mutex);
	} else {
		nuauth_ask_exit();
	}
	return NULL;
}

void tls_nufw_start_servers(GSList *servers)
{
	char **nufw_servers;
	int i = 0;
	/* build servers hash */
	init_nufw_servers();
	nuauthdatas->tls_nufw_servers = NULL;
	/* get raw string from configuration */
	nufw_servers = g_strsplit(nuauthconf->nufw_srv, " ", 0);
	while (nufw_servers[i]) {
		/** \todo free context at program exit */
		struct tls_nufw_context_t *context =
			g_new0(struct tls_nufw_context_t, 1);
		struct nuauth_thread_t *srv_thread =
			g_new0(struct nuauth_thread_t, 1);
		char **context_datas = g_strsplit(nufw_servers[i], ":", 2);
		if (context_datas[0]) {
			context->addr = g_strdup(context_datas[0]);
		} else {
			log_message(FATAL, DEBUG_AREA_MAIN | DEBUG_AREA_GW,
			    "Address parsing error at %s:%d (%s)", __FILE__,
			    __LINE__, nufw_servers[i]);
			nuauth_ask_exit();
		}
		if (context_datas[1]) {
			context->port = g_strdup(context_datas[1]);
		} else {
			context->port = g_strdup(nuauthconf->authreq_port);
		}
		g_strfreev(context_datas);
		thread_new_wdata(srv_thread, "tls nufw server",
				 (gpointer) context,
				 tls_nufw_authsrv);
		/* Append newly created server to list */
		nuauthdatas->tls_nufw_servers = g_slist_prepend(nuauthdatas->tls_nufw_servers,
								srv_thread);
		i++;
	}
	g_strfreev(nufw_servers);
}



/**
 * @}
 */

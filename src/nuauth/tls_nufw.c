/*
 ** Copyright(C) 2004-2009 INL
 ** Written by  Eric Leblond <regit@inl.fr>
 **             Vincent Deffontaines <gryzor@inl.fr>
 **             Pierre Chifflier <chifflier@inl.fr>
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

#include <nubase.h>
#include <nussl.h>

#include <sys/socket.h>
#include <sys/un.h>

#include "nuauthconf.h"

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
	int sck_unix;
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

				/* if we absolutely want to log we've got to have a working pool thread */
				if (nuauthconf->drop_if_no_logging &&
						(nuauthdatas->loggers_pool_full == TRUE)) {
					current_conn->decision = DECISION_DROP;
					current_conn->state = AUTH_STATE_DONE;
					apply_decision(current_conn);
					free_connection(current_conn);
					return NU_EXIT_ERROR;
				}
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
				"Nufw gateway sending control message");
			break;
		}
#if 0
		g_message("dgram_size at %d: %d", __LINE__, dgram_size);
#endif
	} while (dgram_size > 0);

	return NU_EXIT_OK;
}


static int get_reverse_dns_info(struct sockaddr_storage *addr, char *buffer, size_t size)
{
	int ret;

	ret = getnameinfo((const struct sockaddr*)addr,
			sizeof(*addr),
			buffer,
			size,
			NULL,
			0,
			0);

	return ret;
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
	char address[INET6_ADDRSTRLEN];
	int ret;
	char peername[256];
	int port;
	socklen_t len_inet = sizeof(sockaddr);
	char cipher[256];

	nufw_session_t *nu_session;

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
	nu_session->usage = 0;
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

	if (nussl_session_getpeer(nu_session->nufw_client, (struct sockaddr *) &sockaddr, &len_inet) != NUSSL_OK)
	{
		log_area_printf(DEBUG_AREA_GW, DEBUG_LEVEL_WARNING,
				"Unable to get peername of NuFW dameon : %s",
				nussl_get_error(nu_session->nufw_client));
		nussl_session_destroy(nu_session->nufw_client);
		g_free(nu_session);
		return 1;
	}

	/* Extract client address (convert it to IPv6 if it's IPv4) */
	if (sockaddr6->sin6_family == AF_INET) {
		ipv4_to_ipv6(sockaddr4->sin_addr, &nu_session->peername);
		port = ntohs(sockaddr4->sin_port);
	} else {
		nu_session->peername = sockaddr6->sin6_addr;
		port = ntohs(sockaddr6->sin6_port);
	}

	format_ipv6(&nu_session->peername, address, sizeof(address), NULL);
	log_message(DEBUG, DEBUG_AREA_MAIN,
			"nuauth: nufw connection attempt from %s\n",
			address);

	/* get canonical (first) name and set it in ssl session, so that
	 * we can verify if peer name matches certificate CN entry
	 */
	ret = get_reverse_dns_info(&sockaddr, peername, sizeof(peername));
	nussl_set_hostinfo(nu_session->nufw_client, peername, port);

	/* copy verification flag from server session */
	nussl_set_session_flag(nu_session->nufw_client,
		NUSSL_SESSFLAG_IGNORE_ID_MISMATCH,
		nussl_get_session_flag(context->server, NUSSL_SESSFLAG_IGNORE_ID_MISMATCH)
		);

	// XXX default value is 30s, should be a configuration value
	nussl_set_connect_timeout(nu_session->nufw_client, 30);

	ret = nussl_session_handshake(nu_session->nufw_client, context->server);
	if ( ret ) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				"Error during TLS handshake with nufw server %s : %s",
				address,
				nussl_get_error(context->server));
		nussl_session_destroy(nu_session->nufw_client);
		g_free(nu_session);
		return 1;
	}

	nussl_session_get_cipher(nu_session->nufw_client, cipher, sizeof(cipher));
	log_message(INFO, DEBUG_AREA_MAIN | DEBUG_AREA_USER,
		    "TLS handshake with nufw server %s succeeded, cipher is %s",
		    address, cipher);

	/* Check certificate hook */
	ret = modules_check_certificate(nu_session->nufw_client);
	if ( ret ) {
		log_message(WARNING, DEBUG_AREA_MAIN,
				"New client connection from %s failed during modules_check_certificate()",
				address);
		nussl_session_destroy(nu_session->nufw_client);
		g_free(nu_session);
		return 1;
	}

	nufw_servers_connected++;

	conn_fd = nussl_session_get_fd(nu_session->nufw_client);

	nu_session->tls_lock = g_mutex_new();
	add_nufw_server(conn_fd, nu_session);
	FD_SET(conn_fd, &context->tls_rx_set);
	if (conn_fd + 1 > context->mx)
		context->mx = conn_fd + 1;
	g_message("[+] NuFW: new NuFW server (%s) connected on socket %d",
		  address, conn_fd);

	return 0;
}

int tls_nufw_accept_unix(struct tls_nufw_context_t *context)
{
	int conn_fd;
	struct sockaddr_un sockaddr;
	socklen_t len_unix = sizeof(sockaddr);

	nufw_session_t *nu_session;

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
	nu_session->usage = 0;
	nu_session->alive = TRUE;

	/* We have to wait the first packet */
	nu_session->proto_version = PROTO_UNKNOWN;

	nu_session->nufw_client = NULL;

	conn_fd = accept(context->sck_unix, (struct sockaddr*)&sockaddr, &len_unix);
	if ( conn_fd < 0 ) {
		g_free(nu_session);
		log_area_printf(DEBUG_AREA_GW, DEBUG_LEVEL_WARNING,
				"Error while accepting nufw server connection");
		return 1;
	}

	nu_session->nufw_client = nussl_session_create_with_fd(conn_fd, 0 /* verify */);
	if ( ! nu_session->nufw_client ) {
		g_free(nu_session);
		log_area_printf(DEBUG_AREA_GW, DEBUG_LEVEL_WARNING,
				"Unable to allocate nufw server connection : %s",
				nussl_get_error(context->server));
		return 1;
	}


	nufw_servers_connected++;

	nu_session->tls_lock = g_mutex_new();
	add_nufw_server(conn_fd, nu_session);
	FD_SET(conn_fd, &context->tls_rx_set);
	if (conn_fd + 1 > context->mx)
		context->mx = conn_fd + 1;
	g_message("[+] NuFW: new NuFW server connected on unix socket %d",
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
	char *unix_path;

	unix_path = nuauth_config_table_get("nuauth_client_listen_socket");
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

		/* Check if a connect has occured */
		if (context->sck_unix > 0 && FD_ISSET(context->sck_unix, &wk_set)) {
			if (tls_nufw_accept_unix(context)) {
				continue;
			}
		}

		/* check for server activity */
		for (c = 0; c < context->mx; ++c) {
			if (c == context->sck_inet)
				continue;
			if (c == context->sck_unix)
				continue;

			if (FD_ISSET(c, &wk_set)) {
				nufw_session_t *c_session;
				debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_GW,
						  "nufw activity on socket %d",
						  c);

				c_session = acquire_nufw_session_by_socket(c);
				if (! c_session) {
					FD_CLR(c, &context->tls_rx_set);
					continue;
				}
				if (treat_nufw_request(c_session) == NU_EXIT_ERROR) {
					/* get session link with c */
					debug_log_message(DEBUG, DEBUG_AREA_GW,
							  "nufw server disconnect on %d",
							  c);
					FD_CLR(c, &context->tls_rx_set);
					declare_dead_nufw_session(c_session);
				} else {
					release_nufw_session(c_session);
				}
			}
		}

		for (c = context->mx - 1;
		     c >= 0 && !FD_ISSET(c, &context->tls_rx_set);
		     c = context->mx - 1) {
			context->mx = c;
		}
	}
	close(context->sck_inet);
	close(context->sck_unix);
	if (unix_path)
		unlink(unix_path);
}

/**
 * Initialize the NuFW TLS servers thread
 * 0 if error, 1 on success
 */
int tls_nufw_init(struct tls_nufw_context_t *context)
{
	int socket_fd;
	int unix_socket_fd;
	char *errmsg;
	char *unix_path;

/* config init */
	int ret;
	int int_requestcert;
	int int_disable_fqdn_check;
	char *dh_params_file;

	context->sck_inet = nuauth_bind(&errmsg, context->addr, context->port, "nufw");
	if (context->sck_inet < 0) {
		log_message(FATAL, DEBUG_AREA_GW | DEBUG_AREA_MAIN,
			    "FATAL ERROR: NuFW bind error: %s", errmsg);
		log_message(FATAL, DEBUG_AREA_GW | DEBUG_AREA_MAIN,
			    "Check that nuauth is not running twice. Exiting nuauth!");
		return 0;
	}

	unix_path = nuauth_config_table_get("nuauth_client_listen_socket");
	if (unix_path) {
		context->sck_unix = nuauth_bind_unix(&errmsg, unix_path);
		if (context->sck_unix < 0) {
			log_message(FATAL, DEBUG_AREA_GW | DEBUG_AREA_MAIN,
					"FATAL ERROR: NuFW unix bind error: %s", errmsg);
			log_message(FATAL, DEBUG_AREA_GW | DEBUG_AREA_MAIN,
					"Check that nuauth is not running twice. Exiting nuauth!");
			return 0;
		}
	} else {
		context->sck_unix = -1;
	}

#if 0 /* XXX: Already commented in 2.2 */
	struct sigaction action;

	char *configfile = nuauthconf->configfile;
	gpointer vpointer;
	confparams_t nuauth_tls_vars[] = {
		{"nuauth_tls_max_servers", G_TOKEN_INT,
		 NUAUTH_TLS_MAX_SERVERS, NULL}
	};
	int nuauth_tls_max_servers = NUAUTH_TLS_MAX_SERVERS;
	/* get config file setup */
	/* parse conf file */
	if (!parse_conffile(configfile,
		       sizeof(nuauth_tls_vars) / sizeof(confparams_t),
		       nuauth_tls_vars)) {
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
		log_message(FATAL, DEBUG_AREA_MAIN,
			    "nufw listen() failed, exiting");
		exit(EXIT_FAILURE);
	}

	if (context->sck_unix >= 0) {
		unix_socket_fd = listen(context->sck_unix, 20);
		if (unix_socket_fd == -1) {
			log_message(FATAL, DEBUG_AREA_MAIN,
					"nufw unix_socket listen() failed, exiting");
			exit(EXIT_FAILURE);
		}
	}


	/* init fd_set */
	context->mx = context->sck_inet + 1;
	if (context->sck_unix > context->sck_inet)
		context->mx = context->sck_unix + 1;

	FD_ZERO(&context->tls_rx_set);
	FD_SET(context->sck_inet, &context->tls_rx_set);
	if (context->sck_unix >=0)
		FD_SET(context->sck_unix, &context->tls_rx_set);

	/* TODO: read values specific to nufw connection */
	nuauth_tls_max_servers = nuauth_config_table_get_or_default_int("nuauth_tls_max_servers", NUAUTH_TLS_MAX_SERVERS);
	int_requestcert = nuauth_config_table_get_or_default_int("nuauth_tls_request_cert", FALSE);
	dh_params_file = nuauth_config_table_get("nuauth_tls_dh_params");
	/* {"nuauth_tls_auth_by_cert", G_TOKEN_INT, FALSE, NULL}, */

	int_disable_fqdn_check = nuauth_config_table_get_or_default_int("nuauth_tls_disable_nufw_fqdn_check", FALSE);

	/* TODO: use a nufw specific value of request_cert */
	context->server = nussl_session_create_with_fd(context->sck_inet, nuauth_tls.request_cert);
	if ( ! context->server ) {
		log_message(FATAL, DEBUG_AREA_MAIN,
			    "Cannot create NuSSL session!");
		exit(EXIT_FAILURE);
	}

	ret = NUSSL_ERROR;
	if (dh_params_file) {
		ret = nussl_session_set_dh_file(context->server, dh_params_file);
	}
	if (ret != NUSSL_OK &&
		nussl_session_set_dh_bits(context->server, DH_BITS) != NUSSL_OK) {
		log_message(FATAL, DEBUG_AREA_MAIN,
			    "Unable to initialize Diffie Hellman params.");
		exit(EXIT_FAILURE);
	}

	ret = nussl_ssl_set_keypair(context->server, nuauth_tls.cert, nuauth_tls.key);
	if ( ret != NUSSL_OK ) {
		log_message(FATAL, DEBUG_AREA_MAIN,
			    "Failed to load nufw key/certificate: %s",
			    nussl_get_error(context->server));
		exit(EXIT_FAILURE);
	}

	ret = nussl_ssl_trust_cert_file(context->server, nuauth_tls.ca);
	if ( ret != NUSSL_OK ) {
		log_message(FATAL, DEBUG_AREA_MAIN,
			    "Failed to load nufw certificate authority (nuauth_tls_cacert): %s",
			    nussl_get_error(context->server));
		exit(EXIT_FAILURE);
	}

	if (nuauth_tls.capath) {
		ret = nussl_ssl_trust_dir(context->server, nuauth_tls.capath);
		if ( ret != NUSSL_OK ) {
			log_message(FATAL, DEBUG_AREA_MAIN,
					"Failed to load user certificate authority directory: %s",
					nussl_get_error(context->server));
			exit(EXIT_FAILURE);
		}
	}

	if (nuauth_tls.crl_file) {
		ret = nussl_ssl_set_crl_file(context->server, nuauth_tls.crl_file, nuauth_tls.ca);
		if ( ret != NUSSL_OK ) {
			log_message(FATAL, DEBUG_AREA_MAIN,
					"Failed to load certificate revocation list (CRL): %s",
					nussl_get_error(context->server));
			exit(EXIT_FAILURE);
		}
	}

	if (nuauth_tls.ciphers) {
		nussl_session_set_ciphers(context->server, nuauth_tls.ciphers);
	}

	if (int_disable_fqdn_check)
		nussl_set_session_flag(context->server, NUSSL_SESSFLAG_IGNORE_ID_MISMATCH, 1);

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
	int i;
	/* build servers hash */
	init_nufw_servers();
	nuauthdatas->tls_nufw_servers = NULL;
	/* get raw string from configuration */
	nufw_servers = g_strsplit(nuauthconf->nufw_srv, " ", 0);
	for (i=0; nufw_servers[i]; i++) {
		/** \todo free context at program exit */
		struct tls_nufw_context_t *context =
			g_new0(struct tls_nufw_context_t, 1);
		struct nuauth_thread_t *srv_thread =
			g_new0(struct nuauth_thread_t, 1);
		if (!parse_addr_port(nufw_servers[i], nuauthconf->authreq_port, &context->addr, &context->port)) {
			log_message(FATAL, DEBUG_AREA_MAIN | DEBUG_AREA_GW,
			    "Address parsing error at %s:%d (\"%s\")", __FILE__,
			    __LINE__, nufw_servers[i]);
			nuauth_ask_exit();
		}
		thread_new_wdata(srv_thread, "tls nufw server",
				 (gpointer) context,
				 tls_nufw_authsrv);
		/* Append newly created server to list */
		nuauthdatas->tls_nufw_servers = g_slist_prepend(nuauthdatas->tls_nufw_servers,
								srv_thread);
	}
	g_strfreev(nufw_servers);
}



/**
 * @}
 */

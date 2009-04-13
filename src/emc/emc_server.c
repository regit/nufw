/*
 ** Copyright(C) 2009 INL
 ** Written by Pierre Chifflier <chifflier@inl.fr>
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

#include <config.h>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif

#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <ev.h>

#include <errno.h>

#include <nussl.h>

#include <nubase.h>

#include "emc_server.h"
#include "emc_tls.h"

static int _emc_create_socket(const char *addr, const char *port)
{
	struct addrinfo *res;
	struct addrinfo hints;
	int ecode;
	int option_value;
	int sock;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = PF_UNSPEC;

	ecode = getaddrinfo(addr, port,
			&hints, &res);
	if (ecode != 0) {
		log_printf(DEBUG_LEVEL_FATAL, "Invalid server listening address %s:%s, error: %s",
		     addr, port,
		     gai_strerror(ecode));
		return -1;
	}

	sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sock == -1) {
		log_printf(DEBUG_LEVEL_FATAL,"Socket creation failed.");
		return -1;
	}

	/* set socket reuse and keep alive option */
	option_value = 1;
	setsockopt(sock,
		   SOL_SOCKET,
		   SO_REUSEADDR, &option_value, sizeof(option_value));
	setsockopt(sock,
		   SOL_SOCKET,
		   SO_KEEPALIVE, &option_value, sizeof(option_value));

	if (res->ai_family == PF_INET6) {
		setsockopt(sock,
				IPPROTO_IPV6,
				IPV6_V6ONLY,
				(char *)&option_value,
				sizeof (option_value));
	}

	/* bind */
	ecode = bind(sock, res->ai_addr, res->ai_addrlen);
	if (ecode < 0) {
		log_printf(DEBUG_LEVEL_FATAL, "Unable to bind server socket %s:%s.",
					  addr,
					  port);
		close(sock);
		return -1;
	}
	freeaddrinfo(res);

	return sock;
}

static void emc_client_cb (struct ev_loop *loop, ev_io *w, int revents)
{
	struct emc_client_context *client_ctx = w->data;
	char buffer[4096];
	int len;

	buffer[0] = '\0';

	if (revents & EV_READ) {
		len = nussl_read(client_ctx->nussl, buffer, sizeof(buffer));
log_printf(DEBUG_LEVEL_DEBUG, "\tnussl_read: %d  [%s]", len, buffer);
		if (len < 0) {
			log_printf(DEBUG_LEVEL_WARNING, "nussl_error, removing connection [%s]\n", nussl_get_error(client_ctx->nussl));
			ev_io_stop(loop, w);
			nussl_session_destroy(client_ctx->nussl);
			free(client_ctx);
			free(w);
			return;
		}
	}
	if (revents & EV_WRITE) {
log_printf(DEBUG_LEVEL_DEBUG, "will write");
	}
}

static void emc_server_accept_cb (struct ev_loop *loop, ev_io *w, int revents)
{
	struct emc_server_context *ctx;
	struct sockaddr_storage sockaddr;
	struct sockaddr_in *sockaddr4 = (struct sockaddr_in *) &sockaddr;
	struct sockaddr_in6 *sockaddr6 = (struct sockaddr_in6 *) &sockaddr;
	struct in6_addr addr;
	unsigned int len_inet = sizeof sockaddr;
	int ret;
	nussl_session *nussl_sess;
	int socket;
	int sport;
	char address[INET6_ADDRSTRLEN];
	char cipher[256];
	ev_io *client_watcher = NULL;
	struct emc_client_context *client_ctx = NULL;

	ctx = w->data;

	nussl_sess = nussl_session_accept(ctx->nussl);
	if (nussl_sess == NULL) {
		log_printf(DEBUG_LEVEL_WARNING, "Error while accepting new connection: %s",
				nussl_get_error(ctx->nussl));
		return;
	}

	if (nussl_session_getpeer(nussl_sess, (struct sockaddr *) &sockaddr, &len_inet) != NUSSL_OK)
	{
		log_printf(DEBUG_LEVEL_WARNING, "WARNING New client connection failed during nussl_session_getpeer(): %s", nussl_get_error(ctx->nussl));
		free(nussl_sess);
		return;
	}

	socket = nussl_session_get_fd(nussl_sess);

	/* Extract client address (convert it to IPv6 if it's IPv4) */
	if (sockaddr6->sin6_family == AF_INET) {
		ipv4_to_ipv6(sockaddr4->sin_addr, &addr);
		sport = ntohs(sockaddr4->sin_port);
	} else {
		addr = sockaddr6->sin6_addr;
		sport = ntohs(sockaddr6->sin6_port);
	}

	format_ipv6(&addr, address, sizeof(address), NULL);
	log_printf(DEBUG_LEVEL_DEBUG, "DEBUG emc: user connection attempt from %s",
			address);

	/* do not verify FQDN field from client */
	nussl_set_session_flag(nussl_sess,
		NUSSL_SESSFLAG_IGNORE_ID_MISMATCH,
		1
		);

	// XXX set timeout ?
	// nussl_session_handshake is a blocking operation
	ret = nussl_session_handshake(nussl_sess,ctx->nussl);
	if ( ret ) {
		log_printf(DEBUG_LEVEL_WARNING, "WARNING New client connection from %s failed during nussl_session_handshake(): %s",
			    address,
			    nussl_get_error(ctx->nussl));
		nussl_session_destroy(nussl_sess);
		return;
	}

	nussl_session_get_cipher(nussl_sess, cipher, sizeof(cipher));
	log_printf(DEBUG_LEVEL_INFO, "INFO TLS handshake with client %s succeeded, cipher is %s",
		    address, cipher);



	client_ctx = malloc(sizeof(struct emc_client_context));
	client_ctx->nussl = nussl_sess;

	/* push the connection to the list */
	client_watcher = malloc(sizeof(ev_io));
	client_watcher->data = client_ctx;


	ev_io_init(client_watcher, emc_client_cb, socket, EV_READ | EV_TIMEOUT | EV_ERROR);
	ev_io_start(loop, client_watcher);

log_printf(DEBUG_LEVEL_DEBUG, "DEBUG client connection added");
}

static void sigint_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
	struct emc_server_context *ctx = w->data;

log_printf(DEBUG_LEVEL_INFO, "INFO signal SIGINT caught, exiting");
	ctx->continue_processing = 0;
	ev_unloop (loop, EVUNLOOP_ALL);
}


int emc_start_server(struct emc_server_context *ctx)
{
	int server_sock;
	int result;
	struct ev_loop *loop;
	ev_io server_watcher;
	ev_signal signal_watcher;

	server_sock = _emc_create_socket("localhost", "4140");

	result = listen(server_sock, 20);
	if (result == -1) {
		close(server_sock);
		log_printf(DEBUG_LEVEL_FATAL, "Unable to listen() on socket, aborting");
		return -1;
	}

	ctx->server_sock = server_sock;
	result = emc_init_tls(ctx);
	if (result != 0) {
		close(server_sock);
		log_printf(DEBUG_LEVEL_FATAL, "Unable to initialize TLS, aborting");
		return -1;
	}

	loop = ev_default_loop(0);

	ev_io_init(&server_watcher, emc_server_accept_cb, ctx->server_sock, EV_READ);
	ev_io_start(loop, &server_watcher);

	ev_signal_init(&signal_watcher, sigint_cb, SIGINT);
	ev_signal_start(loop, &signal_watcher);

	ctx->continue_processing = 1;
	server_watcher.data = ctx;
	signal_watcher.data = ctx;

	while (ctx->continue_processing)
		ev_loop(loop, EVLOOP_NONBLOCK);

	nussl_session_destroy(ctx->nussl);
	ctx->nussl = NULL;

	return 0;
}

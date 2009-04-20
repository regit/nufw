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
#include "emc_worker.h"

ev_async client_ready_signal;

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

static void emc_client_ready_cb (struct ev_loop *loop, ev_async *w, int revents)
{
	struct emc_server_context *ctx = (struct emc_server_context*)w->data;
	ev_io *client_watcher;

fprintf(stderr, "[%s] : %lx\n", __func__, (long)pthread_self());

	client_watcher = (ev_io *)g_async_queue_pop(ctx->work_queue);

	ev_io_start(EV_DEFAULT_ client_watcher);
}

static void emc_server_accept_cb (struct ev_loop *loop, ev_io *w, int revents)
{
	struct emc_server_context *ctx;
	struct sockaddr_storage sockaddr;
	struct sockaddr_in *sockaddr4 = (struct sockaddr_in *) &sockaddr;
	struct sockaddr_in6 *sockaddr6 = (struct sockaddr_in6 *) &sockaddr;
	struct in6_addr addr;
	unsigned int len_inet = sizeof sockaddr;
	nussl_session *nussl_sess;
	int socket;
	int sport;
	char address[INET6_ADDRSTRLEN];
	struct emc_client_context *client_ctx = NULL;

fprintf(stderr, "[%s] : %lx\n", __func__, (long)pthread_self());
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

	client_ctx = malloc(sizeof(struct emc_client_context));
	client_ctx->nussl = nussl_sess;
	strncpy(client_ctx->address, address, sizeof(client_ctx->address));
	client_ctx->server_ctx = ctx;
	client_ctx->state = EMC_CLIENT_STATE_HANDSHAKE;

	g_thread_pool_push(ctx->pool_tls_handshake, client_ctx, NULL);

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
	int max_workers = 32; // XXX hardcoded value

	g_thread_init(NULL);

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

	ev_async_init(&client_ready_signal, emc_client_ready_cb);
	ev_async_start(loop, &client_ready_signal);

	ctx->continue_processing = 1;
	server_watcher.data = ctx;
	signal_watcher.data = ctx;
	client_ready_signal.data = ctx;

	g_thread_pool_set_max_unused_threads( (int)(max_workers/2) );

	ctx->pool_tls_handshake = g_thread_pool_new((GFunc)emc_worker_tls_handshake, NULL,
						    max_workers, FALSE,
						    NULL);
	ctx->pool_reader = g_thread_pool_new((GFunc)emc_worker_reader, NULL,
						    max_workers, FALSE,
						    NULL);

	ctx->work_queue = g_async_queue_new();

fprintf(stderr, "Max: %d\n", g_thread_pool_get_max_unused_threads());

	log_printf(DEBUG_LEVEL_INFO, "INFO EMC server ready");

	while (ctx->continue_processing)
		ev_loop(loop, 0 /* or: EVLOOP_NONBLOCK */ );

	log_printf(DEBUG_LEVEL_INFO, "INFO EMC server shutting down");

	g_thread_pool_free(ctx->pool_tls_handshake, TRUE, TRUE);
	g_thread_pool_free(ctx->pool_reader, TRUE, TRUE);
	g_async_queue_unref(ctx->work_queue);

	nussl_session_destroy(ctx->nussl);
	ctx->nussl = NULL;

	return 0;
}

/*
 ** Copyright(C) 2009 INL
 ** Written by Pierre Chifflier <chifflier@inl.fr>
 **     INL : http://www.inl.fr/
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

#include "emc_config.h"
#include "emc_server.h"
#include "emc_tls.h"
#include "emc_worker.h"

#include "emc_data_parser.h"

ev_async client_ready_signal;
ev_signal sigint_watcher, sigterm_watcher, sigusr1_watcher;
struct ev_loop *loop;


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
	struct emc_tls_server_context *ctx;
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
	client_ctx->tls_server_ctx = ctx;
	client_ctx->state = EMC_CLIENT_STATE_HANDSHAKE;

	g_thread_pool_push(server_ctx->pool_tls_handshake, client_ctx, NULL);

}

static void sigint_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
	struct emc_server_context *ctx = w->data;

log_printf(DEBUG_LEVEL_INFO, "INFO termination signal caught, exiting");
	ctx->continue_processing = 0;
	ev_unloop (loop, EVUNLOOP_ALL);
}

static void sigusr1_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
	struct emc_server_context *ctx = w->data;

log_printf(DEBUG_LEVEL_INFO, "INFO signal SIGUSR1 caught");
log_printf(DEBUG_LEVEL_INFO, "  TLS handshake threads : current %d / idle %d / max %d",
		g_thread_pool_get_num_threads(ctx->pool_tls_handshake),
		g_thread_pool_get_num_unused_threads(),
		g_thread_pool_get_max_threads(ctx->pool_tls_handshake) );
log_printf(DEBUG_LEVEL_INFO, "  TLS worker threads : current %d / idle %d / max %d",
		g_thread_pool_get_num_threads(ctx->pool_reader),
		g_thread_pool_get_num_unused_threads(),
		g_thread_pool_get_max_threads(ctx->pool_reader) );
}

static int emc_setup_servers(struct ev_loop *loop, struct emc_server_context *ctx)
{
	ev_io *server_watcher;
	char * bind_address_list;
	int server_sock;
	int result;
	char **addresses;
	int i;
	char *context_addr;
	char *context_port;
	struct emc_tls_server_context *tls_server_ctx;

	bind_address_list = emc_config_table_get("emc_bind_address");
	if (!bind_address_list) {
		log_printf(DEBUG_LEVEL_FATAL,
				"FATAL config value emc_bind_address is required");
		return -1;
	}

	addresses = g_strsplit(bind_address_list, " ", 0);

	for (i=0; addresses[i]; i++) {
		if (!parse_addr_port(addresses[i], EMC_DEFAULT_PORT, &context_addr, &context_port)) {
			log_printf(DEBUG_LEVEL_FATAL,
					"Address parsing error at %s:%d (\"%s\")", __FILE__,
					__LINE__, addresses[i]);
			return -1;
		}

		log_printf(DEBUG_LEVEL_INFO, "INFO adding server %s:%s",
			   context_addr, context_port);
		server_sock = _emc_create_socket(context_addr, context_port);

		result = listen(server_sock, 20);
		if (result == -1) {
			close(server_sock);
			log_printf(DEBUG_LEVEL_FATAL, "Unable to listen() on socket, aborting");
			return -1;
		}

		tls_server_ctx = g_malloc0(sizeof(struct emc_tls_server_context));
		tls_server_ctx->server_sock = server_sock;

		result = emc_init_tls(tls_server_ctx);
		if (result != 0) {
			close(server_sock);
			g_free(tls_server_ctx);
			log_printf(DEBUG_LEVEL_FATAL, "Unable to initialize TLS, aborting");
			return -1;
		}

		ctx->tls_server_list = g_list_append(ctx->tls_server_list, tls_server_ctx);
		server_watcher = malloc(sizeof(ev_io));

		ev_io_init(server_watcher, emc_server_accept_cb, tls_server_ctx->server_sock, EV_READ);
		ev_io_start(loop, server_watcher);

		server_watcher->data = tls_server_ctx;
	}

	return 0;
}

static void emc_close_servers(struct emc_server_context *ctx)
{
	struct emc_tls_server_context *tls_server_ctx;
	GList *it;

	for (it = g_list_first(ctx->tls_server_list); it != NULL; it = g_list_next (it)) {
		tls_server_ctx = it->data;

		nussl_session_destroy(tls_server_ctx->nussl);
		g_free(tls_server_ctx);
	}
}

int emc_init_server(struct emc_server_context *ctx)
{
	int result;
	int max_workers;
	char *emc_data_file;

	g_thread_init(NULL);

	max_workers = emc_config_table_get_or_default_int("emc_max_workers", EMC_DEFAULT_MAX_WORKERS);
	emc_data_file = emc_config_table_get("emc_data_file");

	result = emc_parse_datafile(ctx, emc_data_file);
	if (result < 0) {
		return -1;
	}

	loop = ev_default_loop(0);

	result = emc_setup_servers(loop, ctx);
	if (result < 0) {
		return -1;
	}

	ev_signal_init(&sigint_watcher, sigint_cb, SIGINT);
	ev_signal_start(loop, &sigint_watcher);

	ev_signal_init(&sigterm_watcher, sigint_cb, SIGTERM);
	ev_signal_start(loop, &sigterm_watcher);

	ev_signal_init(&sigusr1_watcher, sigusr1_cb, SIGUSR1);
	ev_signal_start(loop, &sigusr1_watcher);

	ev_async_init(&client_ready_signal, emc_client_ready_cb);
	ev_async_start(loop, &client_ready_signal);

	ctx->continue_processing = 1;
	sigint_watcher.data = ctx;
	sigterm_watcher.data = ctx;
	sigusr1_watcher.data = ctx;
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

	return 0;
}

int emc_start_server(struct emc_server_context *ctx)
{
	log_printf(DEBUG_LEVEL_INFO, "INFO EMC server ready");

	while (ctx->continue_processing)
		ev_loop(loop, 0 /* or: EVLOOP_NONBLOCK */ );

	log_printf(DEBUG_LEVEL_INFO, "INFO EMC server shutting down");

	g_thread_pool_free(ctx->pool_tls_handshake, TRUE, TRUE);
	g_thread_pool_free(ctx->pool_reader, TRUE, TRUE);
	g_async_queue_unref(ctx->work_queue);

	ev_default_destroy();

	emc_close_servers(ctx);

	return 0;
}

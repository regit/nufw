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

extern ev_async client_ready_signal;

void emc_client_cb (struct ev_loop *loop, ev_io *w, int revents)
{
	struct emc_client_context *client_ctx = w->data;
	char buffer[4096];

fprintf(stderr, "[%s] : %lx\n", __func__, (long)pthread_self());
	buffer[0] = '\0';

	if (revents & EV_READ) {
		/* stop reading io, to avoid duplicating events */
		ev_io_stop(loop, w);
		client_ctx->ev = w;
		g_thread_pool_push(server_ctx->pool_reader,
				   w, NULL);
	}
	if (revents & EV_WRITE) {
log_printf(DEBUG_LEVEL_DEBUG, "will write");
	}
}

void emc_worker_tls_handshake(gpointer userdata, gpointer data)
{
	struct emc_client_context *client_ctx = (struct emc_client_context *)userdata;
	nussl_session *nussl_sess;
	char cipher[256];
	ev_io *client_watcher = NULL;
	int socket;
	int ret;

fprintf(stderr, "[%s] : %lx\n", __func__, (long)pthread_self());
	nussl_sess = client_ctx->nussl;

	/* do not verify FQDN field from client */
	nussl_set_session_flag(nussl_sess,
		NUSSL_SESSFLAG_IGNORE_ID_MISMATCH,
		1
		);

	nussl_set_connect_timeout(nussl_sess, 30);

	ret = nussl_session_handshake(nussl_sess, client_ctx->tls_server_ctx->nussl);
	if ( ret ) {
		log_printf(DEBUG_LEVEL_WARNING, "WARNING New client connection from %s failed during nussl_session_handshake(): %s",
			    client_ctx->address,
			    nussl_get_error(client_ctx->tls_server_ctx->nussl));
		nussl_session_destroy(nussl_sess);
		return;
	}

	nussl_session_get_cipher(nussl_sess, cipher, sizeof(cipher));
	log_printf(DEBUG_LEVEL_INFO, "INFO TLS handshake with client %s succeeded, cipher is %s",
		    client_ctx->address, cipher);

	/* push the connection to the list */
	client_watcher = malloc(sizeof(ev_io));
	client_watcher->data = client_ctx;

	socket = nussl_session_get_fd(client_ctx->nussl);

	client_ctx->state = EMC_CLIENT_STATE_READY;

	ev_io_init(client_watcher, emc_client_cb, socket, EV_READ | EV_TIMEOUT | EV_ERROR);

	g_async_queue_push(server_ctx->work_queue, client_watcher);

	ev_async_send (EV_DEFAULT_ &client_ready_signal);

log_printf(DEBUG_LEVEL_DEBUG, "DEBUG client connection added");
}

void emc_worker_reader(gpointer userdata, gpointer data)
{
	ev_io *w = (ev_io*)userdata;
	struct emc_client_context *client_ctx;
	nussl_session *nussl_sess;
	char buffer[4096];
	int len;

fprintf(stderr, "[%s] : %lx\n", __func__, (long)pthread_self());
	client_ctx = (struct emc_client_context *)w->data;
	nussl_sess = client_ctx->nussl;

	len = nussl_read(client_ctx->nussl, buffer, sizeof(buffer));
	if (len < 0) {
		log_printf(DEBUG_LEVEL_WARNING, "nussl_error, removing connection [%s]\n", nussl_get_error(client_ctx->nussl));
		ev_io_stop(EV_DEFAULT_ w);
		nussl_session_destroy(client_ctx->nussl);
		free(client_ctx);
		free(w);
		return;
	}
	buffer[len] = '\0';
	while (strlen(buffer)>0 && buffer[strlen(buffer)-1] == '\n')
		buffer[strlen(buffer)-1] = '\0';
log_printf(DEBUG_LEVEL_DEBUG, "\tnussl_read: %d  [%s]", len, buffer);

	/* re-schedule reader */
	g_async_queue_push(server_ctx->work_queue, client_ctx->ev);
	client_ctx->ev = NULL;

	ev_async_send (EV_DEFAULT_ &client_ready_signal);
}

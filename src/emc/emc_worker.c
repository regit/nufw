/*
 ** Copyright(C) 2009 INL
 ** Written by Pierre Chifflier <chifflier@inl.fr>
 **     INL : http://www.inl.fr/
 **
 ** All rights reserved.
 **
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

#include <proto.h>
#include "emc_proto.h"
#include "emc_directory.h"

extern ev_async client_ready_signal;

void emc_client_cb (struct ev_loop *loop, ev_io *w, int revents)
{
	struct emc_client_context *client_ctx = w->data;
	char buffer[4096];

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

	ev_io_init(client_watcher, emc_client_cb, socket, EV_READ);

	g_mutex_lock(server_ctx->tls_client_list_mutex);
	server_ctx->tls_client_list = g_list_append(server_ctx->tls_client_list, client_ctx);
	g_mutex_unlock(server_ctx->tls_client_list_mutex);

	g_async_queue_push(server_ctx->work_queue, client_watcher);

	ev_async_send (EV_DEFAULT_ &client_ready_signal);
}

struct _emc_netmask_lookup_param_t {
	char hostname[512];
	char nuauth_name[512];
	char nuauth_port[512];

	struct nu_header *msg;
	char *buf;
	size_t bufsz;
};

static gboolean _emc_check_send_auth_request(gpointer key, gpointer value, gpointer data)
{
	struct emc_netmask_t *netmask = (struct emc_netmask_t*)value;
	struct _emc_netmask_lookup_param_t *lookup_param = (struct _emc_netmask_lookup_param_t*)data;
	int num_msg_sent = 0;

	if ( !emc_netmask_is_included(netmask, lookup_param->hostname) ) {
		return FALSE;
	}

	/* find if nuauth server is connected, and if yes forward request */
	g_mutex_lock(server_ctx->tls_client_list_mutex);
	/* XXX schedule write in another worker thread ?
	 * We should remove the file descriptors from the global list, else
	 * nussl_write may trigger bad things ..
	 */
	{
		GList *it;
		GList *list = server_ctx->tls_client_list;
		struct emc_client_context *ctx;
		struct nu_header *msg = lookup_param->msg;

		/* for each nuauth server, forward auth request */
		/* note: list iteration is protected by a mutex */
		for (it=g_list_first(list); it != NULL; it=g_list_next(it)) {
			ctx = (struct emc_client_context*)it->data;
			if (strcmp(ctx->address, netmask->nuauth_server)==0) {
				log_printf(DEBUG_LEVEL_DEBUG, "EMC: forwarding request to host: %s", ctx->address);
				num_msg_sent++;

				msg->length = htons(lookup_param->bufsz);
				nussl_write(ctx->nussl, (char*)msg, sizeof(struct nu_header));
				nussl_write(ctx->nussl, lookup_param->buf, lookup_param->bufsz);
			}
		}
	}
	g_mutex_unlock(server_ctx->tls_client_list_mutex);

	if (num_msg_sent == 0)
		log_printf(DEBUG_LEVEL_DEBUG, "EMC: ignoring request, nuauth server %s not found (not connected ?)", netmask->nuauth_server);
	return FALSE;
}

static int _emc_dispatch_auth_requests(struct emc_client_context *client_ctx,
		struct _emc_netmask_lookup_param_t *lookup_param)
{
	/* iterate through list of emc_netmask_t to find matching mask(s) => nuauth server */
	g_tree_foreach(server_ctx->nuauth_directory, _emc_check_send_auth_request, lookup_param);

	return 0;
}

static void _emc_handle_message(struct emc_client_context *client_ctx, struct nu_header *msg, char *buf, size_t bufsz)
{
	struct _emc_netmask_lookup_param_t lookup_param;

	buf[bufsz] = '\0';
	while (strlen(buf)>0 && buf[strlen(buf)-1] == '\n')
		buf[strlen(buf)-1] = '\0';

	switch (msg->msg_type) {
	case EMC_CLIENT_CONNECTION_REQUEST:
		log_printf(DEBUG_LEVEL_DEBUG, "\tconnection request");
		log_printf(DEBUG_LEVEL_DEBUG, "\tnussl_read: %zu [%s]", bufsz, buf);

		sscanf(buf, "%s %s %s", lookup_param.hostname, lookup_param.nuauth_name, lookup_param.nuauth_port);
		log_printf(DEBUG_LEVEL_DEBUG, "\thostname is: [%s]", lookup_param.hostname);
		log_printf(DEBUG_LEVEL_DEBUG, "\tnuauth is  : [%s]:[%s]", lookup_param.nuauth_name, lookup_param.nuauth_port);
		lookup_param.msg = msg;
		lookup_param.buf = buf;
		lookup_param.bufsz = bufsz;

		_emc_dispatch_auth_requests(client_ctx, &lookup_param);

		break;
	default:
		log_printf(DEBUG_LEVEL_DEBUG, "\tnussl_read: %zu [%s]", bufsz, buf);
	};
}

void emc_worker_reader(gpointer userdata, gpointer data)
{
	ev_io *w = (ev_io*)userdata;
	struct nu_header msg;
	struct emc_client_context *client_ctx;
	nussl_session *nussl_sess;
	char buffer[4096];
	int len;
	int msg_length;

	client_ctx = (struct emc_client_context *)w->data;
	nussl_sess = client_ctx->nussl;

	len = nussl_read(client_ctx->nussl, (char*)&msg, sizeof(msg));
	if (len < 0 || len != sizeof(msg)) {
		GList *it;
		log_printf(DEBUG_LEVEL_WARNING, "nussl_error, removing connection with %s [%s]", client_ctx->address, nussl_get_error(client_ctx->nussl));

		g_mutex_lock(server_ctx->tls_client_list_mutex);
		it = g_list_find(server_ctx->tls_client_list, client_ctx);
		if (it != NULL)
			server_ctx->tls_client_list = g_list_remove_link(server_ctx->tls_client_list, it);
		g_mutex_unlock(server_ctx->tls_client_list_mutex);

		ev_io_stop(EV_DEFAULT_ w);
		nussl_session_destroy(client_ctx->nussl);
		free(client_ctx);
		free(w);
		return;
	}

	msg_length = ntohs(msg.length);
log_printf(DEBUG_LEVEL_DEBUG, "Header: proto (%d) command (%d) option(%d) length (%d)", msg.proto, msg.msg_type, msg.option, msg_length);
	// XXX assert(msg_length < sizeof(buffer))

	len = nussl_read(client_ctx->nussl, buffer, msg_length);
	if (len < 0) {
		GList *it;
		log_printf(DEBUG_LEVEL_WARNING, "nussl_error, removing connection with %s [%s]", client_ctx->address, nussl_get_error(client_ctx->nussl));

		g_mutex_lock(server_ctx->tls_client_list_mutex);
		it = g_list_find(server_ctx->tls_client_list, client_ctx);
		if (it != NULL)
			server_ctx->tls_client_list = g_list_remove_link(server_ctx->tls_client_list, it);
		g_mutex_unlock(server_ctx->tls_client_list_mutex);

		ev_io_stop(EV_DEFAULT_ w);
		nussl_session_destroy(client_ctx->nussl);
		free(client_ctx);
		free(w);
		return;
	}

	_emc_handle_message(client_ctx, &msg, buffer, len);

	/* re-schedule reader */
	g_async_queue_push(server_ctx->work_queue, client_ctx->ev);
	client_ctx->ev = NULL;

	ev_async_send (EV_DEFAULT_ &client_ready_signal);
}

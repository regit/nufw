/*
 ** Copyright(C) 2009 INL
 ** Written by Pierre Chifflier <chifflier@inl.fr>
 **     INL : http://www.inl.fr/
 **
 ** All rights reserved.
 **
 */

#ifndef __EMC_SERVER_H__
#define __EMC_SERVER_H__

#include <config.h>

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

#include <glib.h>

#include <nussl.h>

#define EMC_MAX_ADDRESS	256

struct emc_tls_server_context {
	char address[256];

	int server_sock;

	nussl_session *nussl;
};

struct emc_server_context {
	int continue_processing;

	GList *tls_server_list;
	GTree *nuauth_directory; /**< list of emc_netmask_t elements */

	GList *tls_client_list;  /**< list of connected nuauth servers */
	GMutex *tls_client_list_mutex;

	GThreadPool *pool_tls_handshake;
	GThreadPool *pool_reader;
	GAsyncQueue *work_queue;
};

enum emc_client_state {
	EMC_CLIENT_STATE_NULL = 0,
	EMC_CLIENT_STATE_HANDSHAKE,
	EMC_CLIENT_STATE_READY,

	EMC_CLIENT_STATE_LAST
};

struct emc_client_context {
	enum emc_client_state state;

	nussl_session *nussl;

	char address[256];

	void *ev;
	struct emc_tls_server_context *tls_server_ctx;
};

int emc_init_server(struct emc_server_context *ctx);

int emc_start_server(struct emc_server_context *ctx);

extern struct emc_server_context *server_ctx;

#endif /* __EMC_SERVER_H__ */

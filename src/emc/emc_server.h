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

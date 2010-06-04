/*
 ** Copyright(C) 2007 INL
 ** Written by  Eric Leblond <regit@inl.fr>
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
#include <nussl.h>

/**
 * \ingroup TLSNufw
 * @{
 */

/** \file nufw_servers.c
 * \brief Manage nufw servers
 */

GHashTable *nufw_servers = NULL;
GStaticMutex nufw_servers_mutex = G_STATIC_MUTEX_INIT;

void init_nufw_servers()
{
	nufw_servers = g_hash_table_new_full(NULL,
					     NULL,
					     NULL,
					     (GDestroyNotify)
					     clean_nufw_session);
}

nu_error_t add_nufw_server(int conn_fd, nufw_session_t * nu_session)
{
	g_static_mutex_lock(&nufw_servers_mutex);
	g_hash_table_insert(nufw_servers, GINT_TO_POINTER(conn_fd),
			nu_session);
	g_static_mutex_unlock(&nufw_servers_mutex);

	return NU_EXIT_OK;
}

/**
 * Close the TLS NuFW servers
 */
void close_nufw_servers()
{
	g_static_mutex_lock(&nufw_servers_mutex);
	if (nufw_servers != NULL)
		g_hash_table_destroy(nufw_servers);
	nufw_servers = NULL;
	g_static_mutex_unlock(&nufw_servers_mutex);
}

/**
 * Suppress entry from nufw_servers hash when a
 * problem occurs
 */
static nu_error_t suppress_nufw_session(nufw_session_t * session)
{
	g_hash_table_steal(nufw_servers, GINT_TO_POINTER (nussl_session_get_fd(session->nufw_client)));
	return NU_EXIT_OK;
}

extern int nufw_servers_connected;
/**
 * Clean a NuFW TLS session: send "bye", deinit the connection
 * and free the memory.
 */
void clean_nufw_session(nufw_session_t * c_session)
{
	nussl_session_destroy(c_session->nufw_client);

	g_free(c_session);

	g_atomic_int_dec_and_test(&nufw_servers_connected);

	debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_GW, "close nufw session: done");
}



nu_error_t declare_dead_nufw_session(nufw_session_t * session)
{
	g_static_mutex_lock(&nufw_servers_mutex);

	/* session is dead, clean tls and remove session from nufw_servers
	 * hash */
	if (session->alive == TRUE) {
		suppress_nufw_session(session);
		nussl_session_destroy(session->nufw_client);
		session->nufw_client = NULL;
		session->alive = FALSE;
	}

	/* if no one is using nufw session, destroy it */
	if (g_atomic_int_dec_and_test(&(session->usage))) {
		clean_nufw_session(session);
	}
	g_static_mutex_unlock(&nufw_servers_mutex);
	return NU_EXIT_OK;
}

gboolean ghrfunc_true(gpointer key, gpointer value, gpointer user_data)
{
	if (((nufw_session_t *)value)->alive == TRUE)
		return TRUE;
	else
		return FALSE;
}

static gboolean get_nufw_server_by_addr(gpointer key, gpointer value,
					gpointer user_data)
{
	const nufw_session_t* session = value;
	const struct in6_addr *addr = user_data;
	if (ipv6_equal(&session->peername, addr)) {
		return TRUE;
	} else {
		return FALSE;
	}

}

/**
 * get first alive nufw_session_t::
 *
 * session need to be released with a call to release_nufw_session()
 */

nufw_session_t * get_nufw_session()
{
	nufw_session_t * value = NULL;
	g_static_mutex_lock(&nufw_servers_mutex);
	value = (nufw_session_t *) g_hash_table_find(nufw_servers, ghrfunc_true, NULL);
	if (value) {
		g_atomic_int_inc(&(value->usage));
	}
	g_static_mutex_unlock(&nufw_servers_mutex);
	return value;
}

nufw_session_t * acquire_nufw_session_by_socket(int c)
{
	nufw_session_t * c_session = NULL;
	g_static_mutex_lock(&nufw_servers_mutex);
	c_session =
		g_hash_table_lookup(nufw_servers,
				GINT_TO_POINTER
				(c));
	if (c_session) {
		g_atomic_int_inc(&(c_session->usage));
	}
	g_static_mutex_unlock(&nufw_servers_mutex);
	return c_session;
}

nufw_session_t * acquire_nufw_session_by_addr(struct  in6_addr * addr)
{
	nufw_session_t * session;
	g_static_mutex_lock(&nufw_servers_mutex);
	session = g_hash_table_find(nufw_servers,
				    get_nufw_server_by_addr,
				    addr);
	if (session) {
		g_atomic_int_inc(&(session->usage));
	}
	g_static_mutex_unlock(&nufw_servers_mutex);
	return session;
}

nu_error_t increase_nufw_session_usage(nufw_session_t * session)
{
	if (session) {
		g_atomic_int_inc(&(session->usage));
		return NU_EXIT_OK;
	}
	return NU_EXIT_ERROR;
}

void release_nufw_session(nufw_session_t * session)
{
	g_static_mutex_lock(&nufw_servers_mutex);
	if (g_atomic_int_dec_and_test(&(session->usage)) &&
		(session->alive == FALSE)) {
		clean_nufw_session(session);
	}
	g_static_mutex_unlock(&nufw_servers_mutex);
}

nu_error_t nufw_session_send(nufw_session_t * session, char * buffer, int length)
{
	struct nufw_message_t *nmsg;

	if (session->alive == FALSE)
		return NU_EXIT_ERROR;

	nmsg= g_new0(struct nufw_message_t, 1);
	nmsg->length = length;
	nmsg->msg = g_memdup(buffer, length);

	g_async_queue_push(session->queue, nmsg);
	ev_async_send(session->loop, &session->writer_signal);

	return NU_EXIT_OK;
}

/**
 * Iterate on each nufw using callback.
 */
void foreach_nufw_server(GHFunc callback, void * data)
{
	g_static_mutex_lock(&nufw_servers_mutex);
	g_hash_table_foreach(nufw_servers, callback, data);
	g_static_mutex_unlock(&nufw_servers_mutex);
}

/**
 * @}
 */

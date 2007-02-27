/*
 ** Copyright(C) 2005-2006 INL
 ** Written by  Eric Leblond <regit@inl.fr>
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

#include <auth_srv.h>
#define USE_JHASH2
#include <jhash.h>

/**
 * \addtogroup NuauthCore
 * @{
 */

/** \file client_mngr.c
 * \brief Manage client related structure
 *
 * Provide a set of functions that are used to interact with client related structure.
 * This aims to provide an abstraction to avoid change in other parts of the code.
 */

/** global lock for client hash. */
GMutex *client_mutex;
/** Client structure */
GHashTable *client_conn_hash = NULL;
GHashTable *client_ip_hash = NULL;

static uint32_t hash_ipv6(struct in6_addr *addr)
{
	return jhash2(addr->s6_addr32, sizeof(*addr) / 4, 0);
}

#define IPV6_TO_POINTER(addr) GUINT_TO_POINTER(hash_ipv6(addr))

void clean_session(user_session_t * c_session)
{
	if (c_session->tls) {
		gnutls_deinit(*(c_session->tls));
		g_free(c_session->tls);
	}
	g_free(c_session->user_name);
	g_slist_free(c_session->groups);

	g_free(c_session->sysname);
	g_free(c_session->release);
	g_free(c_session->version);

	g_mutex_free(c_session->tls_lock);

	if (c_session) {
		g_free(c_session);
	}
}

static void hash_clean_session(user_session_t * c_session)
{
	int socket = (int) gnutls_transport_get_ptr(*c_session->tls);
	clean_session(c_session);
	shutdown(socket, SHUT_RDWR);
	close(socket);
}


void init_client_struct()
{
	/* build client hash */
	client_conn_hash = g_hash_table_new_full(NULL, NULL, NULL,
						 (GDestroyNotify)
						 hash_clean_session);

	/* build client hash */
	client_ip_hash = g_hash_table_new(NULL, NULL);
	client_mutex = g_mutex_new();
}

void add_client(int socket, gpointer datas)
{
	user_session_t *c_session = (user_session_t *) datas;
	GSList *ipsockets;

	g_mutex_lock(client_mutex);

	g_hash_table_insert(client_conn_hash, GINT_TO_POINTER(socket),
			    datas);

	/* need to create entry in ip hash */
	ipsockets =
	    g_hash_table_lookup(client_ip_hash,
				IPV6_TO_POINTER(&c_session->addr));
	ipsockets = g_slist_prepend(ipsockets, c_session->tls);
	g_hash_table_replace(client_ip_hash,
			     IPV6_TO_POINTER(&c_session->addr), ipsockets);

	g_mutex_unlock(client_mutex);
}

static GSList *delete_ipsockets_from_hash(GSList *ipsockets, user_session_t *session)
{
	ipsockets = g_slist_remove(ipsockets, session);
	if (ipsockets != NULL) {
		g_hash_table_replace(client_ip_hash,
				IPV6_TO_POINTER(&session->
					addr),
				ipsockets);
	} else {
		g_hash_table_remove(client_ip_hash,
				IPV6_TO_POINTER(&session->
					addr));
	}
	/* remove entry from hash */
	g_hash_table_steal(client_conn_hash,
			GINT_TO_POINTER(session->socket));
	log_user_session(session, SESSION_CLOSE);
	return ipsockets;
}

nu_error_t delete_client_by_socket(int socket)
{
	GSList *ipsockets;
	user_session_t *session;

	g_mutex_lock(client_mutex);

	/* get addr of of client
	 *  get element
	 *  get addr field
	 */
	session =
	    (user_session_t
	     *) (g_hash_table_lookup(client_conn_hash,
				     GINT_TO_POINTER(socket)));
	if (session) {
		/* destroy entry in IP hash */
		ipsockets =
			g_hash_table_lookup(client_ip_hash,
					IPV6_TO_POINTER(&session->addr));
		delete_ipsockets_from_hash(ipsockets, session);
	} else {
		log_message(WARNING, AREA_USER,
				"Could not find user session in hash");
		g_mutex_unlock(client_mutex);
		return NU_EXIT_ERROR;
	}

	g_mutex_unlock(client_mutex);

	tls_user_remove_client(&tls_user_context, socket);
	shutdown(socket, SHUT_RDWR);
	close(socket);

	return NU_EXIT_OK;
}

inline user_session_t *get_client_datas_by_socket(int socket)
{
	void *ret;

	g_mutex_lock(client_mutex);
	ret =
	    g_hash_table_lookup(client_conn_hash, GINT_TO_POINTER(socket));
	g_mutex_unlock(client_mutex);
	return ret;
}

inline GSList *get_client_sockets_by_ip(struct in6_addr * ip)
{
	void *ret;

	g_mutex_lock(client_mutex);
	ret = g_hash_table_lookup(client_ip_hash, IPV6_TO_POINTER(ip));
	g_mutex_unlock(client_mutex);
	return ret;
}

inline guint get_number_of_clients()
{
	return g_hash_table_size(client_conn_hash);
}

static gboolean look_for_username_callback(gpointer key,
					   gpointer value,
					   gpointer user_data)
{
	if (strcmp(((user_session_t *) value)->user_name, user_data) != 0) {
		return TRUE;
	} else {
		return FALSE;
	}
}

inline user_session_t *look_for_username(const gchar * username)
{
	void *ret;
	g_mutex_lock(client_mutex);
	ret =
	    g_hash_table_find(client_conn_hash, look_for_username_callback,
			      (void *) username);
	g_mutex_unlock(client_mutex);
	return ret;
}

/**
 * Ask each client of global_msg address set to send their new connections
 * (connections in stage "SYN SENT").
 *
 * \param global_msg Address set of clients
 * \return Returns 0 on error, 1 otherwise
 */
char warn_clients(struct msg_addr_set *global_msg)
{
	GSList *start_ipsockets = NULL;
	GSList *ipsockets = NULL;
	GSList *badsockets = NULL;
#if DEBUG_ENABLE
	char addr_ascii[INET6_ADDRSTRLEN];

	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG, DEBUG_AREA_USER)
	    && inet_ntop(AF_INET6, &global_msg->addr, addr_ascii,
			 sizeof(addr_ascii)) != NULL) {
		g_message("Warn client(s) on IP %s", addr_ascii);
	}
#endif

	g_mutex_lock(client_mutex);
	start_ipsockets =
	    g_hash_table_lookup(client_ip_hash,
				IPV6_TO_POINTER(&global_msg->addr));
	if (start_ipsockets) {
		global_msg->found = TRUE;
		ipsockets = start_ipsockets;
		while (ipsockets) {
			int ret =
			    gnutls_record_send(*(gnutls_session *)
					       (ipsockets->data),
					       global_msg->msg,
					       ntohs(global_msg->msg->
						     length));
			if (ret < 0) {
				log_message(WARNING, AREA_USER,
					    "Fails to send warning to client(s).");
				badsockets = g_slist_prepend(badsockets, ipsockets->data);
			}
			ipsockets = ipsockets->next;
		}
		if (badsockets) {
			while (badsockets) {
				start_ipsockets = delete_ipsockets_from_hash(start_ipsockets,
							   badsockets->data);
				badsockets = badsockets->next;
			}
			g_slist_free(badsockets);
		}
		g_mutex_unlock(client_mutex);
		return 1;
	} else {
		g_mutex_unlock(client_mutex);
		return 0;
	}
}

gboolean hash_delete_client(gpointer key, gpointer value,
			    gpointer userdata)
{
	g_slist_free(value);
	return TRUE;
}

void close_clients(int signal)
{
	if (client_conn_hash != NULL)
		g_hash_table_destroy(client_conn_hash);
	if (client_ip_hash != NULL) {
		g_hash_table_foreach_remove(client_ip_hash,
					    hash_delete_client, NULL);
		g_hash_table_destroy(client_ip_hash);
	}
}

gboolean is_expired_client(gpointer key,
			   gpointer value, gpointer user_data)
{
	if (((user_session_t *) value)->expire < *((time_t *) user_data)) {
		return TRUE;
	} else {
		return FALSE;
	}
}

void kill_expired_clients_session()
{
	time_t current_time = time(NULL);
	g_hash_table_foreach_remove(client_conn_hash, is_expired_client,
				    &current_time);
}

void foreach_session(GHFunc callback, void *data)
{
	g_mutex_lock(client_mutex);
	g_hash_table_foreach(client_conn_hash, callback, data);
	g_mutex_unlock(client_mutex);
}

/** @} */

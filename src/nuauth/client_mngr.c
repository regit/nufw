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

	g_free(c_session);
}

/**
 * Destroy function for #client_conn_hash
 */

static void hash_clean_session(user_session_t * c_session)
{
	int socket = (int) gnutls_transport_get_ptr(*c_session->tls);
	log_user_session(c_session, SESSION_CLOSE);
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
	ipsockets = g_slist_prepend(ipsockets, c_session);
	g_hash_table_replace(client_ip_hash,
			     IPV6_TO_POINTER(&c_session->addr), ipsockets);

	g_mutex_unlock(client_mutex);
}

static GSList *delete_ipsockets_from_hash(GSList *ipsockets,
					  user_session_t *session,
					  int destroy)
{
	gpointer key;
	key = IPV6_TO_POINTER(&session->addr);
	ipsockets = g_slist_remove(ipsockets, session);
	if (ipsockets != NULL) {
		g_hash_table_replace(client_ip_hash,
				key, ipsockets);
	} else {
		g_hash_table_remove(client_ip_hash, key);
	}
	if (destroy) {
		/* remove entry from hash */
		key = GINT_TO_POINTER(session->socket);
		g_hash_table_steal(client_conn_hash, key);
		log_user_session(session, SESSION_CLOSE);
		clean_session(session);
	}
	return ipsockets;
}

nu_error_t delete_client_by_socket_ext(int socket, int use_lock)
{
	GSList *ipsockets;
	user_session_t *session;


	if (use_lock) {
		g_mutex_lock(client_mutex);
	}

	session =
	    (user_session_t
	     *) (g_hash_table_lookup(client_conn_hash,
				     GINT_TO_POINTER(socket)));
	if (!session) {
		log_message(WARNING, DEBUG_AREA_USER,
				"Could not find user session in hash");
		if (use_lock)
			g_mutex_unlock(client_mutex);
		return NU_EXIT_ERROR;
	}

	/* destroy entry in IP hash */
	ipsockets =
		g_hash_table_lookup(client_ip_hash,
				IPV6_TO_POINTER(&session->addr));
	delete_ipsockets_from_hash(ipsockets, session, use_lock);

	if (use_lock) {
		g_mutex_unlock(client_mutex);
	}

	tls_user_remove_client(&tls_user_context, socket);
	if (use_lock) {
		if (shutdown(socket, SHUT_RDWR) != 0)
			log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
					"Could not shutdown socket");
		if (close(socket) != 0)
			log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
					"Could not close socket");
	}

	return NU_EXIT_OK;
}

inline nu_error_t delete_client_by_socket(int socket)
{
	return delete_client_by_socket_ext(socket, 1);
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
	if (strcmp(((user_session_t *) value)->user_name, user_data) == 0) {
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

static gboolean count_username_callback(gpointer key,
					   gpointer value,
					   gpointer user_data)
{
	struct username_counter *count_user = (struct username_counter *) user_data;
	if (strcmp(((user_session_t *) value)->user_name, (gchar *)(count_user->name)) == 0) {
		count_user->counter++;
		if (count_user->counter >= count_user->max) {
			return TRUE;
		} else {
			return FALSE;
		}
	} else {
		return FALSE;
	}
}

gboolean test_username_count_vs_max(const gchar * username, int maxcount)
{
	struct username_counter *count_user;
	count_user = g_new0(struct username_counter, 1);
	count_user->name = username;
	count_user->max = maxcount;
	count_user->counter = 0;
	void *usersession;
	g_mutex_lock(client_mutex);
	usersession =
	    g_hash_table_find(client_conn_hash, count_username_callback,
			      (void *) count_user);
	g_mutex_unlock(client_mutex);
	g_free(count_user);
	if (usersession) {
		return FALSE;
	} else {
		return TRUE;
	}
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
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG, DEBUG_AREA_USER))
	{
		char addr_ascii[INET6_ADDRSTRLEN];
		FORMAT_IPV6(&global_msg->addr, addr_ascii);
		g_message("Warn client(s) on IP %s", addr_ascii);
	}
#endif

	g_mutex_lock(client_mutex);
	start_ipsockets =
	    g_hash_table_lookup(client_ip_hash,
				IPV6_TO_POINTER(&global_msg->addr));
	if (start_ipsockets) {
		global_msg->found = TRUE;
		for (ipsockets = start_ipsockets; ipsockets; ipsockets=ipsockets->next)
		{
			user_session_t *session = (user_session_t *)ipsockets->data;
			gnutls_session tls = *session->tls;
			int ret = gnutls_record_send(tls,
					global_msg->msg,
					ntohs(global_msg->msg->length));
			if (ret < 0) {
				log_message(WARNING, DEBUG_AREA_USER,
						"Fails to send warning to client(s).");
				badsockets = g_slist_prepend(badsockets, ipsockets->data);
			}
		}
		if (badsockets) {
			for (; badsockets; badsockets = badsockets->next) {
				start_ipsockets = delete_ipsockets_from_hash(start_ipsockets,
							   badsockets->data, 1);
			}
			g_slist_free(badsockets);
		}
		g_mutex_unlock(client_mutex);
		return 1;
	} else {
		global_msg->found = FALSE;
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

/**
 * Iterate on each client session using callback.
 */
void foreach_session(GHFunc callback, void *data)
{
	g_mutex_lock(client_mutex);
	g_hash_table_foreach(client_conn_hash, callback, data);
	g_mutex_unlock(client_mutex);
}

gboolean kill_all_clients_cb(gpointer sock, user_session_t* session, gpointer data)
{
	if (session->activated == FALSE)
		return FALSE;

	if (delete_client_by_socket_ext(GPOINTER_TO_INT(sock), 0) == NU_EXIT_OK)
		return TRUE;
	else
		return FALSE;
}

/**
 * Delete all client sessions in hash tables
 *
 * \return NU_EXIT_ERROR if tables were empty, NU_EXIT_OK otherwise.
 */
nu_error_t kill_all_clients()
{
	int count;
	g_mutex_lock(client_mutex);
	count = g_hash_table_foreach_remove(client_conn_hash, (GHRFunc)kill_all_clients_cb, NULL);
	g_mutex_unlock(client_mutex);
	if (count)
		return NU_EXIT_OK;
	else
		return NU_EXIT_ERROR;
}

nu_error_t activate_client_by_socket(int socket)
{
	g_mutex_lock(client_mutex);
	user_session_t *session =
	    (user_session_t
	     *) (g_hash_table_lookup(client_conn_hash,
				     GINT_TO_POINTER(socket)));
	if (session) {
		session->activated = TRUE;
		g_mutex_unlock(client_mutex);
		return NU_EXIT_OK;
	}
	g_mutex_unlock(client_mutex);
	return NU_EXIT_ERROR;
}

/** @} */

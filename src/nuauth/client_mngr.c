/*
 ** Copyright(C) 2005-2008 INL
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

typedef struct {
	GSList *sessions;
	int client_version;
	struct timeval last_message;
} ip_sessions_t;

static uint32_t hash_ipv6(struct in6_addr *addr)
{
	return jhash2(addr->s6_addr32, sizeof(*addr) / 4, 0);
}

void clean_session(user_session_t * c_session)
{
	log_user_session(c_session, SESSION_CLOSE);
	if (c_session->nussl)
		nussl_session_destroy(c_session->nussl);

	if(c_session->user_name)
		g_free(c_session->user_name);
	if(c_session->groups)
		g_slist_free(c_session->groups);

	if(c_session->sysname)
		g_free(c_session->sysname);
	if(c_session->release)
		g_free(c_session->release);
	if(c_session->version)
		g_free(c_session->version);

	g_mutex_free(c_session->tls_lock);

	g_free(c_session);
}

/**
 * Destroy function for #client_conn_hash
 */

static void hash_clean_session(user_session_t * c_session)
{
	log_user_session(c_session, SESSION_CLOSE);
	clean_session(c_session);
}


void init_client_struct()
{
	client_mutex = g_mutex_new();
	/* build client hash */
	client_conn_hash = g_hash_table_new_full(NULL, NULL, NULL,
						 (GDestroyNotify)
						 hash_clean_session);

	/* build client hash */
	client_ip_hash = g_hash_table_new_full((GHashFunc)hash_ipv6,
					  (GEqualFunc)ipv6_equal,
					  (GDestroyNotify) g_free,
					  (GDestroyNotify) g_free);
}

void add_client(int socket, gpointer datas)
{
	user_session_t *c_session = (user_session_t *) datas;
	ip_sessions_t *ipsessions;
	gpointer key;

	g_mutex_lock(client_mutex);

	g_hash_table_insert(client_conn_hash, GINT_TO_POINTER(socket),
			    datas);

	/* need to create entry in ip hash ? */
	ipsessions =
	    g_hash_table_lookup(client_ip_hash,
				&c_session->addr);
	if (ipsessions == NULL) {
		ipsessions = g_new0(ip_sessions_t, 1);
		ipsessions->client_version = c_session->client_version;
		ipsessions->sessions = NULL;
		key = g_memdup(&c_session->addr, sizeof(c_session->addr));
		g_hash_table_replace(client_ip_hash, key, ipsessions);
	}
	/* let's assume backward compatibility, older client wins */
	/** \fixme Add a configuration variable for this choice */
	if (c_session->client_version < ipsessions->client_version) {
		char buffer[256];
		format_ipv6(&c_session->addr, buffer, 256, NULL);
		ipsessions->client_version = c_session->client_version;
		log_message(WARNING, DEBUG_AREA_USER,
			    "User %s on %s uses older version of client",
			    c_session->user_name,
			    buffer);
	}
	if (c_session->client_version > ipsessions->client_version) {
		char buffer[256];
		format_ipv6(&c_session->addr, buffer, 256, NULL);
		log_message(WARNING, DEBUG_AREA_USER,
				"User %s on %s uses newer version of client",
				c_session->user_name,
				buffer);
	}
	ipsessions->sessions = g_slist_prepend(ipsessions->sessions, c_session);
	g_mutex_unlock(client_mutex);
}

static ip_sessions_t *delete_session_from_hash(ip_sessions_t *ipsessions,
					  user_session_t *session,
					  int destroy)
{
	gpointer key;
	key = g_memdup(&session->addr, sizeof(session->addr));
	ipsessions->sessions = g_slist_remove(ipsessions->sessions, session);
	if (ipsessions->sessions == NULL) {
		g_hash_table_remove(client_ip_hash, key);
		g_free(key);
		ipsessions = NULL;
	}
	if (destroy) {
		/* remove entry from hash */
		key = GINT_TO_POINTER(session->socket);
		g_hash_table_steal(client_conn_hash, key);
		clean_session(session);
	}
	return ipsessions;
}

nu_error_t delete_client_by_socket_ext(int socket, int use_lock)
{
	ip_sessions_t *ipsessions;
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
	ipsessions =
		g_hash_table_lookup(client_ip_hash,
				    &session->addr);
	if (ipsessions) {
		delete_session_from_hash(ipsessions, session, 1);
	} else {
		log_message(CRITICAL, DEBUG_AREA_USER,
			    "Could not find entry in ip hash");
	}

	tls_user_remove_client(socket);
	if (use_lock) {
		if (shutdown(socket, SHUT_RDWR) != 0)
			log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
					"Could not shutdown socket");
		if (close(socket) != 0)
			log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
					"Could not close socket");
		g_mutex_unlock(client_mutex);
	}

	return NU_EXIT_OK;
}

nu_error_t delete_client_by_socket(int socket)
{
	return delete_client_by_socket_ext(socket, 1);
}

user_session_t *get_client_datas_by_socket(int socket)
{
	void *ret;

	g_mutex_lock(client_mutex);
	ret =
	    g_hash_table_lookup(client_conn_hash, GINT_TO_POINTER(socket));
	g_mutex_unlock(client_mutex);
	return ret;
}

GSList *get_client_sockets_by_ip(struct in6_addr * ip)
{
	void *ret;

	g_mutex_lock(client_mutex);
	ret = g_hash_table_lookup(client_ip_hash, ip);
	g_mutex_unlock(client_mutex);
	return ret;
}

guint get_number_of_clients()
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

user_session_t *look_for_username(const gchar * username)
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
					user_session_t *value,
					struct username_counter *count_user)
{
	if (strcmp(value->user_name, count_user->name) == 0) {
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
	    g_hash_table_find(client_conn_hash, (GHRFunc)count_username_callback, count_user);
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
	ip_sessions_t *ipsessions = NULL;
	GSList *ipsockets = NULL;
	GSList *badsockets = NULL;
	struct timeval timestamp;
	struct timeval interval;
#if DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG, DEBUG_AREA_USER)) {
		char addr_ascii[INET6_ADDRSTRLEN];
		format_ipv6(&global_msg->addr, addr_ascii, INET6_ADDRSTRLEN, NULL);
		g_message("Warn client(s) on IP %s", addr_ascii);
	}
#endif

	g_mutex_lock(client_mutex);
	ipsessions = g_hash_table_lookup(client_ip_hash, &global_msg->addr);
	if (ipsessions) {
		global_msg->found = TRUE;
		gettimeofday(&timestamp, NULL);

		if (ipsessions->client_version >= PROTO_VERSION_V22_1) {
			timeval_substract(&interval, &timestamp, &(ipsessions->last_message));
			if (interval.tv_sec || (interval.tv_usec < nuauthconf->push_delay)) {
				return 1;
			} else {
				ipsessions->last_message.tv_sec = timestamp.tv_sec;
				ipsessions->last_message.tv_usec = timestamp.tv_usec;
			}
		}

		for (ipsockets = ipsessions->sessions; ipsockets; ipsockets = ipsockets->next) {
			user_session_t *session = (user_session_t *)ipsockets->data;
			int ret;

			ret = nussl_write(session->nussl,
					(char*)global_msg->msg,
					ntohs(global_msg->msg->length));
			if (ret < 0) {
				log_message(WARNING, DEBUG_AREA_USER,
						"Failed to send warning to client(s): %s", nussl_get_error(session->nussl));
				badsockets = g_slist_prepend(badsockets, GINT_TO_POINTER(ipsockets->data));
			}
		}
		if (badsockets) {
			for (; badsockets; badsockets = badsockets->next) {
				int sockno = GPOINTER_TO_INT(badsockets->data);
				nu_error_t ret = delete_client_by_socket_ext(sockno, 0);
				if (ret != NU_EXIT_OK) {
					log_message(WARNING, DEBUG_AREA_USER,
						"Fails to destroy socket in hash.");
				}
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
	ip_sessions_t *ipsessions = (ip_sessions_t *) value;
	if (ipsessions->sessions) {
		g_slist_free(ipsessions->sessions);
	}
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
	g_mutex_lock(client_mutex);
	g_hash_table_foreach_remove(client_conn_hash, is_expired_client,
				    &current_time);
	g_mutex_unlock(client_mutex);
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

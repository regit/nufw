/*
 ** Copyright(C) 2005-2009 INL
 ** Written by  Eric Leblond <regit@inl.fr>
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
	int proto_version;
	struct timeval last_message;
} ip_sessions_t;

static uint32_t hash_ipv6(struct in6_addr *addr)
{
	return jhash2(addr->s6_addr32, sizeof(*addr) / 4, 0);
}

/**
 * Log and free structure relative to a user_session_t
 *
 * Used as destroy function for #client_conn_hash
 */
void log_clean_session(user_session_t * c_session)
{
	log_user_session(c_session, SESSION_CLOSE);
	clean_session(c_session);
}

void clean_session(user_session_t * c_session)
{
	if (c_session->nussl)
		nussl_session_destroy(c_session->nussl);

	if (c_session->user_name)
		g_free(c_session->user_name);
	if (c_session->groups)
		g_slist_free(c_session->groups);

	if (c_session->sysname)
		g_free(c_session->sysname);
	if (c_session->release)
		g_free(c_session->release);
	if (c_session->version)
		g_free(c_session->version);

	g_mutex_free(c_session->tls_lock);

	g_free(c_session);
}

void init_client_struct()
{
	client_mutex = g_mutex_new();
	/* build client hash */
	client_conn_hash = g_hash_table_new_full(NULL, NULL, NULL,
						 (GDestroyNotify)
						 log_clean_session);

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
		ipsessions->proto_version = c_session->proto_version;
		ipsessions->sessions = NULL;
		key = g_memdup(&c_session->addr, sizeof(c_session->addr));
		g_hash_table_replace(client_ip_hash, key, ipsessions);
	}
	/* let's assume backward compatibility, older client wins */
	/* TODO: Add a configuration variable for this choice */
	if (c_session->proto_version < ipsessions->proto_version) {
		char buffer[256];
		format_ipv6(&c_session->addr, buffer, 256, NULL);
		ipsessions->proto_version = c_session->proto_version;
		log_message(WARNING, DEBUG_AREA_USER,
			    "User %s on %s uses older version of client",
			    c_session->user_name,
			    buffer);
	}
	if (c_session->proto_version > ipsessions->proto_version) {
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
		g_hash_table_remove(client_conn_hash, key);
	}
	return ipsessions;
}


static nu_error_t cleanup_session(user_session_t * session)
{
	ip_sessions_t *ipsessions;
	/* destroy entry in IP hash */
	ipsessions =
		g_hash_table_lookup(client_ip_hash,
				    &session->addr);
	if (ipsessions) {
		delete_session_from_hash(ipsessions, session, 0);
	} else {
		log_message(CRITICAL, DEBUG_AREA_USER,
			    "Could not find entry in ip hash");
		return NU_EXIT_ERROR;
	}

	return NU_EXIT_OK;
}

static nu_error_t delete_client_by_session(user_session_t * session)
{
	nu_error_t ret;

	ret = cleanup_session(session);

	if (ret != NU_EXIT_OK) {
		return ret;
	}

	return NU_EXIT_OK;
}

nu_error_t delete_client_by_socket_ext(int socket, int use_lock)
{
	gpointer key;
	user_session_t *session;
	nu_error_t ret;


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


	ret = cleanup_session(session);

	if (ret != NU_EXIT_OK) {
		if (use_lock)
			g_mutex_unlock(client_mutex);
		return ret;
	}

	if (shutdown(socket, SHUT_RDWR) != 0) {
		log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
				"Could not shutdown socket: %s", strerror(errno));
	}
	if (close(socket) != 0) {
		log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
				"Could not close socket: %s", strerror(errno));
	}


	key = GINT_TO_POINTER(session->socket);
	g_hash_table_remove(client_conn_hash, key);

	if (use_lock) {
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
	ip_sessions_t *session;
	GSList *ret = NULL;

	g_mutex_lock(client_mutex);
	session = g_hash_table_lookup(client_ip_hash, ip);
	if (session)
		ret = session->sessions;
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
 * Property check
 */

gboolean check_property_clients(struct in6_addr *addr, user_session_check_t *scheck, int mode, gpointer data)
{
	gboolean cst = FALSE;
	ip_sessions_t *ipsessions = NULL;
	GSList *ipsockets = NULL;

	g_mutex_lock(client_mutex);
	ipsessions = g_hash_table_lookup(client_ip_hash, addr);
	if (ipsessions) {
		for (ipsockets = ipsessions->sessions; ipsockets; ipsockets = ipsockets->next) {
			user_session_t *session = (user_session_t *)ipsockets->data;
			cst = scheck(session, data);
			if (mode) {
				if (cst == TRUE) {
					g_mutex_unlock(client_mutex);
					return TRUE;
				}
			}
		}
		g_mutex_unlock(client_mutex);
		return cst;
	} else {
		g_mutex_unlock(client_mutex);
		return FALSE;
	}
	g_mutex_unlock(client_mutex);
	return FALSE;
}

/**
 * Ask each client of global_msg address set to send their new connections
 * (connections in stage "SYN SENT").
 *
 * \param global_msg Address set of clients
 * \return Returns 0 on error, 1 otherwise
 */
char warn_clients(struct msg_addr_set *global_msg,
		  user_session_check_t *scheck,
		  gpointer data)
{
	ip_sessions_t *ipsessions = NULL;
	GSList *ipsockets = NULL;
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

		if ((!(data || scheck)) && ipsessions->proto_version >= PROTO_VERSION_V22_1) {
			gettimeofday(&timestamp, NULL);
			timeval_substract(&interval, &timestamp, &(ipsessions->last_message));
			if ((interval.tv_sec == 0) && ((unsigned)interval.tv_usec < nuauthconf->push_delay)) {
				g_mutex_unlock(client_mutex);
				return 1;
			} else {
				ipsessions->last_message.tv_sec = timestamp.tv_sec;
				ipsessions->last_message.tv_usec = timestamp.tv_usec;
			}
		}
		for (ipsockets = ipsessions->sessions; ipsockets; ipsockets = ipsockets->next) {
			user_session_t *session = (user_session_t *)ipsockets->data;

			if ((!scheck) || scheck(session, data)) {
				tls_workunit_t *workunit = g_new0(tls_workunit_t, 1);
				workunit->global_msg = g_memdup(global_msg, sizeof(*global_msg));
				workunit->global_msg->msg = g_memdup(global_msg->msg,
								     ntohs(global_msg->msg->length));
				workunit->user_session = session;
#if DEBUG_ENABLE
				if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG, DEBUG_AREA_USER)) {
					char addr_ascii[INET6_ADDRSTRLEN];
					format_ipv6(&global_msg->addr, addr_ascii, INET6_ADDRSTRLEN, NULL);
					g_message("Queuing message for %s (%d)",
						  addr_ascii,
						  session->socket);
				}
#endif
				g_async_queue_push(writer_queue, workunit);
				ev_async_send(session->srv_context->loop, &session->srv_context->client_writer_signal);
			}
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
	if (((user_session_t *) value)->expire == -1) {
		return FALSE;
	}
	if (((user_session_t *) value)->expire < *((time_t *) user_data)) {
		return TRUE;
	} else {
		return FALSE;
	}
}

void clean_client_session_bycallback(GHRFunc cb, gpointer data)
{
	g_mutex_lock(client_mutex);
	g_hash_table_foreach_remove(client_conn_hash, cb, data);
	g_mutex_unlock(client_mutex);
}

void kill_expired_clients_session()
{
	time_t current_time = time(NULL);
	clean_client_session_bycallback(is_expired_client, &current_time);
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

	if (delete_client_by_session(session) == NU_EXIT_OK)
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

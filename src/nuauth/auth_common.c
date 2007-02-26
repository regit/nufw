/*
 ** Copyright(C) 2003-2007 INL
 ** Written by Eric Leblond <regit@inl.fr>
 **            Vincent Deffontaines <vincent@gryzor.com>
 **     INL : http://www.inl.fr/
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
 */

#include "auth_srv.h"
#include <netinet/ip.h>
#include <netinet/ip6.h>

/**
 * \ingroup Nuauth
 * \defgroup NuauthCore Nuauth Core
 * \brief This is the main part of nuauth, real core is search_and_fill().
 * \author Éric Leblond
 *
 * The main functions are :
 *  - search_and_fill() : used to aggregate dates coming from nufw and clients
 *  - take_decision() : decide on packet based on policy coming from module
 *
 * @{
 *
 */

/** \file auth_common.c
 *  \brief Core functions of NuAuth, contain search_and_fill() .
 */

#ifdef PERF_DISPLAY_ENABLE
/* Subtract the `struct timeval' values X and Y,
 *         storing the result in RESULT.
 *                 Return 1 if the difference is negative, otherwise 0.  */

int timeval_substract(struct timeval *result, struct timeval *x,
		      struct timeval *y)
{
	/* Perform the carry for the later subtraction by updating y. */
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	 *           tv_usec is certainly positive. */
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;

	/* Return 1 if result is negative. */
	return x->tv_sec < y->tv_sec;
}
#endif

/**
 * Display connection parameters using g_message(): IP+TCP/UDP headers,
 * OS name, OS release and OS version, and application name.
 *
 * Only display the connection if ::debug_level is #DEBUG_LEVEL_VERBOSE_DEBUG
 * or greater.
 *
 * \return Returns -1 if an error occurs, 1 else.
 */
gint print_connection(gpointer data, gpointer userdata)
{
	connection_t *conn = (connection_t *) data;
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG, DEBUG_AREA_MAIN)) {
		char src_ascii[INET6_ADDRSTRLEN];
		char dst_ascii[INET6_ADDRSTRLEN];

		if (inet_ntop
		    (AF_INET6, &conn->tracking.saddr, src_ascii,
		     sizeof(src_ascii)) == NULL)
			return -1;
		if (inet_ntop
		    (AF_INET6, &conn->tracking.daddr, dst_ascii,
		     sizeof(dst_ascii)) == NULL)
			return -1;

		g_message("Connection: src=%s dst=%s proto=%u",
			  src_ascii, dst_ascii, conn->tracking.protocol);
		if (conn->tracking.protocol == IPPROTO_TCP) {
			g_message("sport=%d dport=%d",
				  conn->tracking.source,
				  conn->tracking.dest);
		}
		g_message("IN=%s OUT=%s", conn->iface_nfo.indev,
			  conn->iface_nfo.outdev);

		if (conn->packet_id) {
			g_message("packet id: %d",
				  GPOINTER_TO_UINT(conn->packet_id->data));
		}

		if (conn->os_sysname && conn->os_release
		    && conn->os_version) {
			g_message("OS: %s %s %s", conn->os_sysname,
				  conn->os_release, conn->os_version);
		}
		if (conn->app_name) {
			g_message("Application: %s", conn->app_name);
		}
	}
	return 1;
}

/**
 * Check if a IPv6 address is a IPv4 or not.
 *
 * \return 1 for IPv4 and 0 for IPv6
 */
int is_ipv4(struct in6_addr *addr)
{
	if (addr->s6_addr32[2] != 0xffff0000)
		return 0;
	if (addr->s6_addr32[0] != 0 || addr->s6_addr32[1] != 0)
		return 0;
	return 1;
}

void free_connection_callback(gpointer conn, gpointer unused)
{
	free_connection((connection_t *) conn);
}

void free_connection_list(GSList * list)
{
	if (list == NULL)
		return;
	g_slist_foreach(list, free_connection_callback, NULL);
	g_slist_free(list);
}

void free_iface_nfo_t(iface_nfo_t * track)
{
	g_free(track->indev);
	g_free(track->outdev);
	g_free(track->physindev);
	g_free(track->physoutdev);
}

/**
 * Delete a connection and free all the memory used.
 *
 * This is the output function for every connection_t::. It
 * \b must be called to destroy every connection.
 *
 * This includes:
 *  - Connection created after nufw and client request
 *  - Connection created after a call do duplicate_connection()
 *
 * May call log_user_packet() with ::TCP_STATE_DROP state if connection was
 * waiting for its authentification.
 *
 * \param conn Pointer to a connection
 * \return None
 */

void free_connection(connection_t * conn)
{
	g_assert(conn != NULL);

	/* log if necessary (only state authreq) with user log module
	 * AUTH_STATE_COMPLETING is reached when no acl is found for packet */
	if (conn->state == AUTH_STATE_AUTHREQ) {
		/* copy message */
		log_user_packet(conn, TCP_STATE_DROP);
	}
	/*
	 * tell cache we don't use the ressource anymore
	 */
	if (conn->acl_groups) {
		if (nuauthconf->acl_cache) {
			struct cache_message *message =
			    g_new0(struct cache_message, 1);
			debug_log_message(VERBOSE_DEBUG, AREA_MAIN,
					  "Sending free to acl cache");
			message->key = acl_create_and_alloc_key(conn);
			message->type = FREE_MESSAGE;
			message->datas = conn->acl_groups;
			g_async_queue_push(nuauthdatas->acl_cache->queue,
					   message);
		} else {
			free_acl_groups(conn->acl_groups, NULL);
		}
	}
	/* free user group */
	if (conn->cacheduserdatas) {
		if (conn->username) {
			struct cache_message *message =
			    g_new0(struct cache_message, 1);
			if (!message) {
				log_message(CRITICAL, AREA_MAIN,
					    "Could not g_new0(). No more memory?");
				/* GRYZOR should we do something special here? */
			} else {
				debug_log_message(VERBOSE_DEBUG, AREA_MAIN,
						  "Sending free to user cache");
				message->key = g_strdup(conn->username);
				message->type = FREE_MESSAGE;
				message->datas = conn->cacheduserdatas;
				g_async_queue_push(nuauthdatas->
						   user_cache->queue,
						   message);
			}
		} else {
			debug_log_message(VERBOSE_DEBUG, AREA_MAIN,
					  "Can not free user cache, username is null");
		}
	} else {
		g_free(conn->username);
	}
	g_slist_free(conn->packet_id);
	g_slist_free(conn->user_groups);
	g_free(conn->app_name);
	g_free(conn->app_md5);
	g_free(conn->os_sysname);
	g_free(conn->os_release);
	g_free(conn->os_version);
	g_free(conn->log_prefix);

	free_iface_nfo_t(&(conn->iface_nfo));

	g_free(conn);
}

#define COPY_IFACE_NAME(copy, orig, iface) \
    do { if (orig->iface) \
            { copy->iface = g_strndup(orig->iface,IFNAMSIZ); }  \
        else { copy->iface = NULL; } \
    } while (0)

/** Duplicate an iface_nfo
 *
 * Do a copy of field \b only if it is not NULL
 *
 * \param copy pointer to the target ::iface_nfo_t (MUST be allocated before)
 * \param orig pointer to the ::iface_nfo_t to copy
 */

void duplicate_iface_nfo(iface_nfo_t * copy, iface_nfo_t * orig)
{
	COPY_IFACE_NAME(copy, orig, indev);
	COPY_IFACE_NAME(copy, orig, outdev);
	COPY_IFACE_NAME(copy, orig, physindev);
	COPY_IFACE_NAME(copy, orig, physoutdev);
}

#undef COPY_IFACE_NAME

/** Used for logging purpose \b only.
 *
 * It <b>does not</b> duplicate internal data. This includes all
 * cache datas used to take the decision
 *  - connection_t::acl_groups
 *  - connection_t::user_groups
 *  - ...
 *
 * connection_t::state is switched to ::AUTH_STATE_DONE as the
 * connection will be used for logging only.
 *
 * We call duplicate_iface_nfo() because the copy will be
 * sent to free_connection() like the original.
 *
 * \param element a pointer to a connection_t
 * \return the duplicated connection_t
 */

connection_t *duplicate_connection(connection_t * element)
{
	connection_t *conn_copy = g_memdup(element, sizeof(*element));
	if (conn_copy == NULL) {
		log_message(WARNING, AREA_MAIN,
			    "memory duplication failed");
		return NULL;
	}
	conn_copy->username = g_strdup(element->username);
	conn_copy->app_name = g_strdup(element->app_name);
	conn_copy->app_md5 = g_strdup(element->app_md5);
	conn_copy->os_sysname = g_strdup(element->os_sysname);
	conn_copy->os_release = g_strdup(element->os_release);
	conn_copy->os_version = g_strdup(element->os_version);

	conn_copy->log_prefix = g_strdup(element->log_prefix);
	conn_copy->flags = element->flags;

	duplicate_iface_nfo(&(conn_copy->iface_nfo),
			    &(element->iface_nfo));

	/* Nullify needed internal field */
	conn_copy->acl_groups = NULL;
	conn_copy->user_groups = NULL;
	conn_copy->packet_id = NULL;
	conn_copy->cacheduserdatas = NULL;
	conn_copy->state = AUTH_STATE_DONE;
	return conn_copy;
}



/**
 * Remove element from hash table
 *
 * It only steal the ::connection_t from the connection
 * hash ::conn_list
 *
 * \param conn a pointer to a ::connection_t
 * \return Returns 1 if success, 0 if it fails
 */

inline int conn_cl_remove(gconstpointer conn)
{
	if (!g_hash_table_steal(conn_list,
				&(((connection_t *) conn)->tracking))) {
		log_message(WARNING, AREA_MAIN,
			    "Removal of conn in hash failed\n");
		return 0;
	}
	return 1;
}

/**
 * Remove a connection from the connection hash table (::conn_list)
 * and free its memory using free_connection().
 *
 * \param conn A ::connection_t
 * \return Returns 1 if succeeded, 0 otherwise
 */

int conn_cl_delete(gconstpointer conn)
{
	g_assert(conn != NULL);

	if (conn_cl_remove(conn) == 0) {
		return 0;
	}

	/* free isolated structure */
	free_connection((connection_t *) conn);
	return 1;
}

/**
 * \brief This function is used by clean_connections_list() to check if a
 * connection is 'old' (outdated) or not.
 *
 * It checks timeout with current
 * timestamp (see member packet_timeout of ::nuauthconf) and skip connection
 * in state ::AUTH_STATE_COMPLETING (because of an evil hack in
 * search_and_fill_complete_of_userpckt() :-)).
 * It is needed as we can't suppress an entry which is not currently
 * proceeded by the search_and_fill() thread and its associates.
 *
 * \param key Key in hash of the connection (not used in the function)
 * \param value Pointer to a ::connection_t
 * \param user_data Current timestamp (get by time(NULL))
 * \return TRUE if the connection is old, FALSE else
 */
gboolean get_old_conn(gpointer key, gpointer value, gpointer user_data)
{
	long current_timestamp = GPOINTER_TO_INT(user_data);

	/* Don't remove connection in state AUTH_STATE_COMPLETING because of
	 * an evil hack in search_and_fill_complete_of_userpckt() :-)
	 */
	if ((current_timestamp - ((connection_t *) value)->timestamp >
	     nuauthconf->packet_timeout)
	    && (((connection_t *) value)->state != AUTH_STATE_COMPLETING)
	    ) {
		return TRUE;
	}
	return FALSE;
}

void clean_connection_list_callback(gpointer key, gpointer value,
				    gpointer data)
{
	GSList **list_ptr = (GSList **) data;
	time_t current_timestamp = time(NULL);
	if (get_old_conn(key, value, GINT_TO_POINTER(current_timestamp))) {
		*list_ptr = g_slist_prepend(*list_ptr, key);
	}
}

/**
 * \brief Find old connection and delete them.
 *
 * This function is called periodically by main thread to
 * clean the connection table ::conn_list.
 *
 * It uses get_old_conn() to check if a connection is 'old' or not.
 */
void clean_connections_list()
{
	GSList *old_keyconn_list = NULL;
	GSList *old_conn_list = NULL;
	GSList *iterator;
	int nb_deleted;

	/* extract the list of old connections */
	g_static_mutex_lock(&insert_mutex);

	g_hash_table_foreach(conn_list, clean_connection_list_callback,
			     &old_keyconn_list);

	/* remove old connections from connection list */
	nb_deleted = 0;
	for (iterator = old_keyconn_list; iterator != NULL;) {
		gpointer key = iterator->data;
		gpointer value = g_hash_table_lookup(conn_list, key);
		if (value != NULL) {
			g_hash_table_steal(conn_list, key);
			old_conn_list =
			    g_slist_prepend(old_conn_list, value);
			nb_deleted += 1;
		} else {
			log_message(WARNING, AREA_MAIN,
				    "Clean connection: no entry found in hash ");
		}
		iterator = iterator->next;
	}
	g_static_mutex_unlock(&insert_mutex);
	g_slist_free(old_keyconn_list);

	/* reject all old connections */
	for (iterator = old_conn_list; iterator != NULL;) {
		connection_t *element = iterator->data;
		iterator = iterator->next;
		if (nuauthconf->reject_after_timeout != 0)
			element->decision = DECISION_REJECT;
		else
			element->decision = DECISION_DROP;
		if (element->state == AUTH_STATE_AUTHREQ) {
			apply_decision(element);
		}
		free_connection(element);
	}
	g_slist_free(old_conn_list);

	/* display number of deleted elements */
	if (0 < nb_deleted) {
		log_message(INFO, AREA_MAIN,
			    "Clean connection list: %d connection(s) suppressed",
			    nb_deleted);
	}
}

/**
 * Suppress domain from "user\@domain" string (returns "user").
 *
 * \return Username which need to be freeded
 */
char *get_rid_of_domain(const char *user_domain)
{
	char *username = NULL;
	char **user_realm;
	user_realm = g_strsplit(user_domain, "@", 2);
	if (user_realm[0] != NULL) {
		username = g_strdup(user_realm[0]);
	} else {
		username = g_strdup(user_domain);
	}
	g_strfreev(user_realm);
	return username;
}

/**
 * Suppress domain from "DOMAIN\user" string (returns "user").
 *
 * \return Username which need to be freeded
 */
char *get_rid_of_prefix_domain(const char *user_domain)
{
	char *username = NULL;
	char **user_realm;
	user_realm = g_strsplit(user_domain, "\\", 2);
	if (user_realm[0] && user_realm[1]) {
		username = g_strdup(user_realm[1]);
	} else {
		username = g_strdup(user_domain);
	}
	g_strfreev(user_realm);
	return username;
}

/**
 * Free a ::tls_buffer_read buffer and all of its memory.
 */
void free_buffer_read(struct tls_buffer_read *datas)
{
	g_free(datas->os_sysname);
	g_free(datas->os_release);
	g_free(datas->os_version);
	g_free(datas->buffer);
	g_free(datas->user_name);
	if (datas->groups != NULL) {
		g_slist_free(datas->groups);
	}
	g_free(datas);
}

/**
 * Function snprintf() which check buffer overflow, and always write a '\\0'
 * to the end of the buffer.
 *
 * \param buffer Buffer where characters are written
 * \param buffer_size Buffer size (in bytes), usually equals to sizeof(buffer)
 * \param format Format string (see printf() documentation)
 * \return Returns FALSE if a buffer overflow occurs, TRUE is everything goes fine.
 */
gboolean secure_snprintf(char *buffer, unsigned int buffer_size,
			 char *format, ...)
{
	va_list args;
	int ret;
	va_start(args, format);
	ret = g_vsnprintf(buffer, buffer_size, format, args);
	va_end(args);
	buffer[buffer_size - 1] = '\0';
	if (0 <= ret && ret <= ((int) buffer_size - 1))
		return TRUE;
	else
		return FALSE;
}

/**
 * Check Protocol version agains supported one
 *
 * \param version A integer coding protocol version to test
 * \return a ::nu_error_t
 */

nu_error_t check_protocol_version(int version)
{
	if ((version != PROTO_VERSION) && (version != PROTO_VERSION_V20)) {
		return NU_EXIT_ERROR;
	} else {
		return NU_EXIT_OK;
	}
}

/**
 * Convert a string to integer number (value in INT_MIN..INT_MAX).
 * Return 0 on error, 1 otherwise.
 */
int str_to_int(const char *text, int *value)
{
	char *err = NULL;
	long longvalue = strtol(text, &err, 10);
	if (err == NULL || *err != 0)
		return 0;
	if (longvalue < INT_MIN || INT_MAX < longvalue)
		return 0;
	*value = (int)longvalue;
	return 1;
}

/** @} */

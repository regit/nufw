/*
** Copyright(C) 2005,2006,2007 Eric Leblond <regit@inl.fr>
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

#ifndef CONNECTIONS_H
#define CONNECTIONS_H

#include "packet_parser.h"	/* tracking_t structure and packet parsing functions */

/**
 * \addtogroup NuauthCore
 * @{
 */

/**
 * State of a connection (type ::connection_t) in the authentication server.
 * See field state of a structure ::connection_t and function
 * change_state().
 */
typedef enum {
	AUTH_STATE_NONE = 0,	/*!< Unknow state (when a connection is created) */
	AUTH_STATE_AUTHREQ = 1,	/*!< Waiting for authentication */
	AUTH_STATE_USERPCKT,	/*!< Connection received from an user: see user_request() */
	AUTH_STATE_READY,	/*!< (see search_and_fill_completing()) */

    /**
     * State used when a connection is send to acl_checkers queue: read ACLs
     * from cache or external source. See acl_check_and_decide().
     */
	AUTH_STATE_COMPLETING,
	AUTH_STATE_DONE,	/*!< This state is set when the connection will be only used for logging purpose */
	AUTH_STATE_HELLOMODE,	/*!< This connection is treated by the HELLO authentication mode */
	AUTH_STATE_SPOOFING,	/*!< This connection is a spoofed one */
} auth_state_t;

typedef enum {
	ACL_FLAGS_NONE = 0,
	/* This ACL wants asynchronous logging */
	ACL_FLAGS_ASYNC_BIT = 0,
	ACL_FLAGS_ASYNC = (1 << ACL_FLAGS_ASYNC_BIT),
	/* This ACL don't want to log */
	ACL_FLAGS_NOLOG_BIT = 1,
	ACL_FLAGS_NOLOG = (1 << ACL_FLAGS_NOLOG_BIT),
	/* This ACL wants synchronous logging */
	ACL_FLAGS_SYNC_BIT = 2,
	ACL_FLAGS_SYNC = (1 << ACL_FLAGS_SYNC_BIT),
	/* This ACL wants strict logging */
	ACL_FLAGS_STRICT_BIT = 3,
	ACL_FLAGS_STRICT = (1 << ACL_FLAGS_STRICT_BIT),
} acl_flags_t;


#define IPHDR_REJECT_LENGTH 20
#define IP6HDR_REJECT_LENGTH 40
/**
 * this is IPHDR_REJECT_LENGTH / 4
 */
#define IPHDR_REJECT_LENGTH_BWORD 5

typedef enum {
	AUTHQ_BYIP,
	AUTHQ_SASL,
	AUTHQ_SSL,
} auth_quality_t;

/**
 * Used to store the acl that apply for a packet
 */
struct acl_group {
	GSList *users;		/*!< List of users ID on which the acl apply */
	GSList *groups;		/*!< List of users groups on which the acl apply */
	decision_t answer;	/*!< Answer relative to the acl */
	gchar *period;		/*!< Period linked to the acl */
	gchar *log_prefix;	/*!< Log prefix used for the acl */
	gint flags;		/*!< flags used to set some acl properties */
	gint auth_quality;	/*!< Minimum authentication quality required for a match */
};

typedef struct {
	char indev[IFNAMSIZ];		/*!< Input device set to "\0" if not available */
	char physindev[IFNAMSIZ];	/*!< Input physical device set to "\0" if not available */
	char outdev[IFNAMSIZ];		/*!< Output device set to "\0" if not available */
	char physoutdev[IFNAMSIZ];	/*!< Output physical device set to "\0" if not available */
} iface_nfo_t;


/**
 * \brief Size of payload we keep for parsing (must be > headers)
 */
#define STORED_PAYLOAD_SIZE	128

/**
 * This is a packet blocked by NuFW and waiting for an authentication
 * of NuAuth. They are created in authpckt_new_connection().
 *
 * It contains all datas relative to a packet
 */
typedef struct {
	GSList *packet_id;	/*!< Netfilter unique identifier */
	time_t timestamp;	/*!< Packet arrival time (seconds) */
	int socket;		/*!< Socket (file descriptor) from which NuFW request is coming */
	nufw_session_t *tls;	/*!< TLS connection to NuFW from which comes the packet */

	tracking_t tracking;	/*!< IPv4 connection tracking (headers) */

	iface_nfo_t iface_nfo;	/*!< Information about network interfaces */

	uint32_t user_id;	/*!< User identifier (32-bit) */
	uint32_t mark;		/*!< Number used for marking set to user numeric identity at start */
	char *username;		/*!< User name */

 /**
  * ACL related groups.
  *
  * Contains the list of acl corresponding to the IPv4 header
  */
	GSList *acl_groups;	/*!< ACL group list (of type ::acl_group) */
	GSList *user_groups;	/*!< User groups */
	struct user_cached_datas *cacheduserdatas;	/* Pointer to cache */

	gchar *os_sysname;	/*!< Operating system name */
	gchar *os_release;	/*!< Operating system release */
	gchar *os_version;	/*!< Operating system version */
	gchar *app_name;	/*!< Application name (full path) */

	auth_state_t state;	/*!< State of the packet */

	decision_t decision;	/*!< Decision on packet. */
	gchar *log_prefix;	/*!< Log prefix. */
	gint flags;		/*!< Flags used to store some properties */

	time_t expire;		/*!< Expire time (never: -1) */


	int nufw_version;	/*!< Store the version of the nufw server which has sent the request */
	int proto_version;	/*!< Store protocol version of the client which has sent the packet */

	int auth_quality;

#ifdef PERF_DISPLAY_ENABLE
	struct timeval arrival_time;	/*!< Performance datas */
#endif

	unsigned char payload[STORED_PAYLOAD_SIZE];
	unsigned int payload_len;

} connection_t;

guint hash_connection(gconstpointer conn_p);
/** hash table containing the connections. */
GHashTable *conn_list;
/** global lock for the conn list. */
GStaticMutex insert_mutex;


void duplicate_iface_nfo(iface_nfo_t * copy, iface_nfo_t * orig);
nu_error_t compare_iface_nfo_t(iface_nfo_t *a, iface_nfo_t *b);

gboolean get_old_conn(gpointer key, gpointer value, gpointer user_data);
int conn_cl_remove(gconstpointer conn);
int conn_cl_delete(gconstpointer conn);
nu_error_t print_tracking_t(tracking_t *tracking);
gint print_connection(gpointer data, gpointer userdata);
void free_connection_list(GSList * list);
connection_t *duplicate_connection(connection_t * element);
void free_connection(connection_t * conn);
int lock_and_free_connection(connection_t * conn);
void clean_connections_list();

/** @} */

#endif

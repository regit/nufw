/*
 ** Copyright(C) 2005-2007 INL
 ** Written by Eric Leblond <regit@inl.fr>
 ** INL http://www.inl.fr/
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

#ifndef USERS_H
#define USERS_H

#include <nussl.h>
#include "cache.h"

int init_user_cache();

void get_users_from_cache(connection_t * conn_elt);
gpointer user_duplicate_key(gpointer datas);

struct user_cached_datas {
	uint32_t uid;
	GSList *groups;
};

/**
 * \brief Stores all information relative to a TLS user session.
 *
 * We don't want to have this information in all authentication packet.
 * Thus, once a user has managed to authenticate and has given
 * all the informations nuauth needs, we store it in this structure for
 * later use.
 *
 * When an authentication packet is received from the socket link to the user,
 * we add the informations contained in this strucuture to the just created
 * ::connection_t (see user_request()).
 *
 * An "user" is a person authentified with a NuFW client.
 */
typedef struct {
	struct in6_addr addr;	/*!< \brief IPv6 address of the client */
	struct in6_addr server_addr;	/*!< \brief IPv6 address of the server */
	unsigned short sport;   /*!< \brief source port */
	/** \brief socket used by tls session.
	* It identify the client and it is used as the key
	*/
	int socket;
	/* tls should be removed by ssl */
	nussl_session *nussl;	/*!< \brief SSL session opened with tls_connect() */
	GMutex *tls_lock;	/*!< \brief Mutex to lock use of TLS */
	char *user_name;	/*!< \brief User name */
	uint32_t user_id;	/*!< \brief User identifier */
	GSList *groups;		/*!< \brief List of groups the user belongs to */
	gchar *sysname;		/*!< \brief OS system name (eg. "Linux") */
	gchar *release;		/*!< \brief OS release (eg. "2.6.12") */
	gchar *version;		/*!< \brief OS full version */
	time_t expire;		/*!< \brief Timeout of the session (-1 means unlimited) */
	int client_version;	/*!< \brief Client protocol version */
	time_t connect_timestamp;
	gboolean activated;	/*!< \brief TRUE if user server listen for event for this session */
} user_session_t;

#endif

/*
 ** Copyright(C) 2004 INL
 ** Written by Eric Leblond <regit@inl.fr>
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


#include <auth_srv.h>

/**
 * check given ip for ip authentication.
 *
 * Use module to check if we can found the user logged on ip.
 *
 * Algorithm :
 *  - Send request to module provided function
 *  - if a username is returned
 *    - get groups for user
 *    - build corresponding connection structure
 *    - feed search_and_fill with it
 *  - else free header (userdata)
 *
 */
void external_ip_auth(gpointer userdata, gpointer data)
{
	char *username = NULL;

	username = modules_ip_auth(userdata);
	if (username) {
		GSList *groups = NULL;
		uint32_t uid;
	    /**
             * \todo set a cache for such query
             */

		uid = modules_get_user_id(username);
		groups = modules_get_user_groups(username);
		/* if search succeed process to packet transmission */
		if (groups) {
			connection_t *connection = g_new0(connection_t, 1);
			connection->state = AUTH_STATE_USERPCKT;
			connection->decision = DECISION_NODECIDE;
			connection->user_groups = groups;
			connection->user_id = uid;
			connection->username = username;
			connection->os_sysname = NULL;
			connection->app_name = NULL;
			connection->flags = ACL_FLAGS_NONE;
			connection->auth_quality = AUTHQ_BYIP;
			/* copy ipv4 header */
			memcpy(&(connection->tracking),
			       (tracking_t *) userdata,
			       sizeof(tracking_t));
			g_async_queue_push(nuauthdatas->connections_queue,
					   connection);
		}
	}
	g_free(userdata);
}

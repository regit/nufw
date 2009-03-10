/*
 ** Copyright(C) 2006-2008 INL
 ** Written by Eric Leblond <regit@inl.fr>
 **            Victor Stinner <haypo@inl.fr>
 **     INL : http://www.inl.fr/
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


#include "auth_srv.h"
#define USE_JHASH2
#include <jhash.h>

/**
 * \addtogroup NuauthCore
 * @{
 */

/** \file auth_hash.c
 * \brief Connections hash handling
 */

/* should never be called !!! */
void search_and_fill_catchall(connection_t * new, connection_t * packet)
{
	if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING, DEBUG_AREA_MAIN)) {
		g_message
		    ("state of new packet: %d, state of existing packet: %d",
		     new->state, packet->state);
	}
}

#define SEARCH_AND_FILL_CATCHALL(new,packet) g_warning \
		    ("%s:%d Should not have this. Please email Nufw developpers!", \
		     __FILE__, __LINE__); \
	search_and_fill_catchall(new, packet);

/**
 * Compute the key (hash) of a connection tracking.
 *
 * \param data IPv4 tracking headers (of type tracking_t) of a connection
 * \return Computed hash
 */
guint32 hash_connection(gconstpointer data)
{
	tracking_t *tracking = (tracking_t *) data;
	return jhash2((uint32_t *)&(tracking->saddr), 4,
		      tracking->source);
}

/**
 * Check if two connections are equal.
 *
 * \param trck1 Tracking headers compared with trck2
 * \param trck2 Tracking headers compared with trck1
 * \return TRUE is they are equal, FALSE otherwise
 */
gboolean tracking_equal(const tracking_t *trck1, const tracking_t *trck2)
{
	/* compare proto */
	if (trck1->protocol != trck2->protocol)
		return FALSE;

	/* compare proto headers */
	switch (trck1->protocol) {
	case IPPROTO_TCP:
		if (trck1->source == trck2->source
		    && trck1->dest == trck2->dest
		    && ipv6_equal(&trck1->daddr, &trck2->daddr)
		    && ipv6_equal(&trck1->saddr, &trck2->saddr))
			return TRUE;
		else
			return FALSE;

	case IPPROTO_UDP:
		if (trck1->source == trck2->source
		    && trck1->dest == trck2->dest
		    && ipv6_equal(&trck1->daddr, &trck2->daddr)
		    && ipv6_equal(&trck1->saddr, &trck2->saddr))
			return TRUE;
		else
			return FALSE;

	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		if (trck1->type == trck2->type
		    && trck1->code == trck2->code
		    && ipv6_equal(&trck1->daddr, &trck2->daddr)
		    && ipv6_equal(&trck1->saddr, &trck2->saddr))
			return TRUE;
		else
			return FALSE;

	default:
		return FALSE;
	}
}

/**
 * Send the a #WARN_MESSAGE to nuauthdatas->tls_push_queue (see ::push_worker()).
 */
void search_and_push(connection_t * new)
{
	/* push data to sender */
	struct internal_message *message =
	    g_new0(struct internal_message, 1);
	if (!message) {
		log_message(CRITICAL, DEBUG_AREA_USER,
			    "search&push: Couldn't g_new0(). No more memory?");
		return;
	}
	debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
			  "search&push: need to warn client");

	/* duplicate tracking */
	message->type = WARN_MESSAGE;
	message->datas = g_memdup(&(new->tracking), sizeof(tracking_t));
	if (message->datas) {
		g_async_queue_push(nuauthdatas->tls_push_queue, message);
	} else {
		g_free(message);
		log_message(CRITICAL, DEBUG_AREA_USER,
			    "search&push: g_memdup returned NULL");
	}
}

void search_and_fill_complete_of_authreq(connection_t * new,
						connection_t * packet)
{

	switch (new->state) {
	case AUTH_STATE_AUTHREQ:
		debug_log_message(DEBUG, DEBUG_AREA_PACKET,
				  "Complete authreq: Adding a packet_id to a connection (id=%u)",
				  GPOINTER_TO_UINT((new->packet_id)->data)
				  );
		packet->packet_id =
		    g_slist_prepend(packet->packet_id,
				    GUINT_TO_POINTER((new->packet_id)->
						    data));
		new->state = AUTH_STATE_DONE;
		break;

	case AUTH_STATE_USERPCKT:
		debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
				  "Complete authreq: Filling user data for %s",
				  new->username);
		new->state = AUTH_STATE_COMPLETING;
		packet->state = AUTH_STATE_COMPLETING;

		packet->user_groups = new->user_groups;
		new->user_groups = NULL;
		packet->user_id = new->user_id;
		packet->username = new->username;
		/* application */
		packet->app_name = new->app_name;
		/* system */
		packet->os_sysname = new->os_sysname;
		packet->os_release = new->os_release;
		packet->os_version = new->os_version;
		packet->proto_version = new->proto_version;
		packet->auth_quality = new->auth_quality;
		/* user cache system */
		packet->cacheduserdatas = new->cacheduserdatas;

		/* Add interfaces information needed for ACLs checking */
		duplicate_iface_nfo(&new->iface_nfo, &packet->iface_nfo);

		thread_pool_push(nuauthdatas->acl_checkers, new, NULL);
		return;		/* don't free new connection */

	default:
		SEARCH_AND_FILL_CATCHALL(new, packet);
	}
	free_connection(new);
}

/**
 * An user tells that he is the owner of a connection:
 *  - #AUTH_STATE_AUTHREQ: push a copy of the connection 'new' to nuauthdatas->acl_checkers
 *  - #AUTH_STATE_USERPCKT: that's a duplicate
 *  - other: error!
 */
void search_and_fill_complete_of_userpckt(connection_t * new,
						 connection_t * packet)
{

	switch (new->state) {
	case AUTH_STATE_AUTHREQ:
		packet->state = AUTH_STATE_COMPLETING;

		/* Copy packet members needed by ACL checker into new.
		 * We don't use strdup/free because it's slow.
		 * So clean_connections_list() don't remove connection
		 * in state AUTH_STATE_COMPLETING :-)
		 */
		new->state = AUTH_STATE_COMPLETING;
		/* application */
		new->app_name = packet->app_name;
		/* system */
		new->os_sysname = packet->os_sysname;
		new->os_release = packet->os_release;
		new->os_version = packet->os_version;
		new->proto_version = packet->proto_version;
		new->auth_quality = packet->auth_quality;
		/* copy iface info */
		duplicate_iface_nfo(&(packet->iface_nfo), &(new->iface_nfo));

		packet->packet_id = new->packet_id;
		new->packet_id = NULL;
		packet->mark = new->mark;
		packet->socket = new->socket;
		/* transfert nufw tls session to initial packet */
		packet->tls = new->tls;
		packet->nufw_version = new->nufw_version;
		new->tls = NULL;

		thread_pool_push(nuauthdatas->acl_checkers, new, NULL);
		return;		/* don't free connection */

	case AUTH_STATE_USERPCKT:
		debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
				  "Complete user packet: Found a duplicate user packet");
		break;

	default:
		SEARCH_AND_FILL_CATCHALL(new, packet);
	}
	free_connection(new);
}

void search_and_fill_done(connection_t * new, connection_t * packet)
{
	/* if new is a nufw request respond with correct decision */
	switch (new->state) {
	case AUTH_STATE_AUTHREQ:
		g_slist_foreach(new->packet_id,
				(GFunc) send_auth_response, packet);
		break;

	case AUTH_STATE_USERPCKT:
		break;

	default:
		SEARCH_AND_FILL_CATCHALL(new, packet);
	}
	free_connection(new);
}

void search_and_fill_completing(connection_t * new,
				       connection_t * packet)
{
	switch (new->state) {
	case AUTH_STATE_COMPLETING:
		/* fill acl this is a return from acl search */
		packet->acl_groups = new->acl_groups;
		g_free(new);
		packet->state = AUTH_STATE_READY;
		take_decision(packet, PACKET_IN_HASH);
		return;

	case AUTH_STATE_AUTHREQ:
		debug_log_message(DEBUG, DEBUG_AREA_GW,
				  "Completing (auth): Adding a packet_id to a completing connection (id=%u)",
				  GPOINTER_TO_UINT((new->packet_id)->data)
				  );
		packet->packet_id =
		    g_slist_prepend(packet->packet_id,
				    GUINT_TO_POINTER((new->packet_id)->
						    data));
		new->state = AUTH_STATE_DONE;
		break;

	case AUTH_STATE_USERPCKT:
		log_message(DEBUG, DEBUG_AREA_USER,
			    "Completing (user): User packet in state completing");
		break;

	default:
		SEARCH_AND_FILL_CATCHALL(new, packet);
	}
	free_connection(new);
}

void search_and_fill_ready(connection_t * new,
				  connection_t * packet)
{
	debug_log_message(DEBUG, DEBUG_AREA_MAIN,
			  "search&fill ready: Element is in state %d but received packet has state %d",
			  packet->state, new->state);
	switch (new->state) {
	case AUTH_STATE_AUTHREQ:
		debug_log_message(DEBUG, DEBUG_AREA_GW,
				  "search&fill ready: Adding a packet_id to a connection (id=%u)",
				  GPOINTER_TO_UINT((new->packet_id)->data)
				  );
		packet->packet_id =
		    g_slist_prepend(packet->packet_id,
				    GUINT_TO_POINTER((new->packet_id)->data));
		new->state = AUTH_STATE_DONE;
		break;

	case AUTH_STATE_USERPCKT:
		debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
				  "search&fill ready: Need only cleaning");
		break;

	default:
		SEARCH_AND_FILL_CATCHALL(new, packet);
	}
	free_connection(new);
}

/**
 * Update an existing connection. Depending on connection state,
 * call function:
 * - #AUTH_STATE_AUTHREQ: search_and_fill_complete_of_authreq() ;
 * - #AUTH_STATE_USERPCKT: search_and_fill_complete_of_userpckt() ;
 * - #AUTH_STATE_COMPLETING: search_and_fill_completing() ;
 * - #AUTH_STATE_READY: search_and_fill_ready().
 */
void search_and_fill_update(connection_t * new, connection_t * packet)
{
	switch (packet->state) {
	case AUTH_STATE_AUTHREQ:
		search_and_fill_complete_of_authreq(new, packet);
		break;

	case AUTH_STATE_USERPCKT:
		search_and_fill_complete_of_userpckt(new, packet);
		break;

	case AUTH_STATE_DONE:
		search_and_fill_done(new, packet);
		break;

	case AUTH_STATE_COMPLETING:
		search_and_fill_completing(new, packet);
		break;

	case AUTH_STATE_READY:
		search_and_fill_ready(new, packet);
		break;

	default:
		SEARCH_AND_FILL_CATCHALL(new, packet);
		free_connection(new);
	}
}

/**
 * Thread created in ::init_nuauthdata().
 * Try to insert a connection in Struct.
 * Fetch datas in connections queue.
 *
 * Call search_and_fill_update() if the connection exists in ::conn_list,
 * else call search_and_push().
 */
void *search_and_fill(GMutex * mutex)
{
	connection_t *packet;
	connection_t *new;
	GTimeVal tv;

	g_async_queue_ref(nuauthdatas->connections_queue);
	g_async_queue_ref(nuauthdatas->tls_push_queue);

	/* wait for message */
	while (g_mutex_trylock(mutex)) {
		g_mutex_unlock(mutex);

		/* wait a message during POP_DELAY */
		g_get_current_time(&tv);
		g_time_val_add(&tv, POP_DELAY);
		new =
		    g_async_queue_timed_pop(nuauthdatas->connections_queue,
					    &tv);
		if (new == NULL)
			continue;

		/* search pckt */
		g_static_mutex_lock(&insert_mutex);
		debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
				  "Starting search and fill");
		packet =
		    (connection_t *) g_hash_table_lookup(conn_list,
							 &(new->tracking));
		if (packet == NULL) {
			debug_log_message(DEBUG, DEBUG_AREA_MAIN,
					  "Creating new packet");
			g_hash_table_insert(conn_list, &(new->tracking),
					    new);
			g_static_mutex_unlock(&insert_mutex);
			if (nuauthconf->push
			    && new->state == AUTH_STATE_AUTHREQ) {
				search_and_push(new);
			}
		} else {
			search_and_fill_update(new, packet);
			g_static_mutex_unlock(&insert_mutex);
		}
	}
	g_async_queue_unref(nuauthdatas->connections_queue);
	g_async_queue_unref(nuauthdatas->tls_push_queue);

	return NULL;
}

/* @} */

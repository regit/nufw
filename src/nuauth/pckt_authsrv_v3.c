/*
 ** Copyright(C) 2006, INL
 ** Written by Eric Leblond <regit@inl.fr>
 ** INL http://www.inl.fr/
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
#include <errno.h>

#include "pckt_authsrv_v3.h"

nu_error_t parse_dgram(connection_t * connection, unsigned char *dgram,
		       unsigned int dgram_size, connection_t ** conn,
		       nufw_message_t msg_type);

/**
 * Parse message content for message of type #AUTH_REQUEST or #AUTH_CONTROL
 * using structure ::nufw_to_nuauth_auth_message_t.
 *
 * \param dgram Pointer to packet datas
 * \param dgram_size Number of bytes in the packet
 * \param conn Pointer of pointer to the ::connection_t that we have to authenticate
 * \return A nu_error_t
 */
nu_error_t authpckt_new_connection_v3(unsigned char *dgram,
				      unsigned int dgram_size,
				      connection_t ** conn)
{
	nuv3_nufw_to_nuauth_auth_message_t *msg =
	    (nuv3_nufw_to_nuauth_auth_message_t *) dgram;
	connection_t *connection;
	nu_error_t ret;

	if (dgram_size < sizeof(nuv3_nufw_to_nuauth_auth_message_t)) {
		log_message(INFO, DEBUG_AREA_PACKET | DEBUG_AREA_GW,
			    "Undersized message from nufw server");
		return NU_EXIT_ERROR;
	}
	dgram += sizeof(nuv3_nufw_to_nuauth_auth_message_t);
	dgram_size -= sizeof(nuv3_nufw_to_nuauth_auth_message_t);

	/* allocate new connection */
	connection = g_new0(connection_t, 1);
	if (connection == NULL) {
		log_message(WARNING, DEBUG_AREA_PACKET,
			    "Can not allocate connection");
		return NU_EXIT_ERROR;
	}
#ifdef PERF_DISPLAY_ENABLE
	if (nuauthconf->debug_areas & DEBUG_AREA_PERF) {
		gettimeofday(&(connection->arrival_time), NULL);
	}
#endif
	connection->username = NULL;
	connection->acl_groups = NULL;
	connection->user_groups = NULL;
	connection->decision = DECISION_NODECIDE;
	connection->expire = -1;
	connection->flags = ACL_FLAGS_NONE;

	connection->packet_id =
	    g_slist_append(NULL, GUINT_TO_POINTER(ntohl(msg->packet_id)));
	debug_log_message(DEBUG, DEBUG_AREA_PACKET | DEBUG_AREA_GW,
			  "Auth pckt: Working on new connection (id=%u)",
			  (uint32_t) GPOINTER_TO_UINT(connection->
						      packet_id->data));

	/* timestamp */
	connection->timestamp = ntohl(msg->timestamp);
	if (connection->timestamp == 0)
		connection->timestamp = time(NULL);

	/* compat version: nufw is v2.0 */
	connection->nufw_version = PROTO_VERSION_NUFW_V20;

	ret =
	    parse_dgram(connection, dgram, dgram_size, conn,
			msg->msg_type);
	if (ret != NU_EXIT_CONTINUE) {
		return ret;
	}
#ifdef DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG, DEBUG_AREA_PACKET)) {
		print_connection(connection, "NuFW Packet");
	}
#endif
	*conn = connection;
	return NU_EXIT_OK;
}

/**
 * Parse message content for message of type #AUTH_CONN_DESTROY
 * or #AUTH_CONN_UPDATE using structure ::nu_conntrack_message_t structure.
 *
 * Send a message FREE_MESSAGE or UPDATE_MESSAGE to limited_connections_queue
 * (member of ::nuauthdatas).
 *
 * \param dgram Pointer to packet datas
 * \param dgram_size Number of bytes in the packet
 * \return a ::nu_error_t containing success or failure
 */
nu_error_t authpckt_conntrack_v3(unsigned char *dgram, unsigned int dgram_size)
{
	struct nuv3_conntrack_message_t *conntrack;
	struct accounted_connection *datas;
	struct internal_message *message;
	tcp_state_t pstate;

	debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_PACKET | DEBUG_AREA_GW,
			  "Auth conntrack: Working on new packet");

	/* Check message content size */
	if (dgram_size != sizeof(struct nuv4_conntrack_message_t)) {
		debug_log_message(WARNING, DEBUG_AREA_PACKET | DEBUG_AREA_GW,
				  "Auth conntrack: Improper length of packet");
		return NU_EXIT_ERROR;
	}

	/* Create a message for limited_connexions_queue */
	conntrack = (struct nuv3_conntrack_message_t *) dgram;
	datas = g_new0(struct accounted_connection, 1);
	message = g_new0(struct internal_message, 1);
	datas->tracking.protocol = conntrack->ipv4_protocol;

	uint32_to_ipv6(conntrack->ipv4_src, &datas->tracking.saddr);
	uint32_to_ipv6(conntrack->ipv4_dst, &datas->tracking.daddr);

	if (conntrack->ipv4_protocol == IPPROTO_ICMP) {
		datas->tracking.type = ntohs(conntrack->src_port);
		datas->tracking.code = ntohs(conntrack->dest_port);
	} else {
		datas->tracking.source = ntohs(conntrack->src_port);
		datas->tracking.dest = ntohs(conntrack->dest_port);
	}

	datas->packets_in = 0;
	datas->bytes_in = 0;
	datas->packets_out = 0;
	datas->bytes_out = 0;

	message->datas = datas;
	if (conntrack->msg_type == AUTH_CONN_DESTROY) {
		message->type = FREE_MESSAGE;
		debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_PACKET,
				  "Auth conntrack: Sending free message");
		pstate = TCP_STATE_CLOSE;
	} else {
		message->type = UPDATE_MESSAGE;
		debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_PACKET,
				  "Auth conntrack: Sending Update message");
		pstate = TCP_STATE_ESTABLISHED;
	}

	log_user_packet_from_accounted_connection(datas, pstate);
	g_async_queue_push(nuauthdatas->limited_connections_queue,
			   message);
	return NU_EXIT_OK;
}

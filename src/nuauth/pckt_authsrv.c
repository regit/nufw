/*
 ** Copyright(C) 2003-2009 INL
 ** Written by Eric Leblond <eleblond@inl.fr>
 ** INL http://www.inl.fr/
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

/** \file pckt_authsrv.c
 *  \brief Functions to parse a packet sent by NuFW
 *
 * Function authpckt_decode() parse a packet sent by NuFW. Depends on
 * message type (see ::nufw_message_t), send a message to
 * limited_connections_queue (member of ::nuauthdatas), may log packet
 * (log_user_packet()) and/or create a new connection
 * (of type ::connection_t).
 *
 * This function is called by treat_nufw_request()
 * which is called in the thread tls_nufw_authsrv().
 */

#include <auth_srv.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "pckt_authsrv_v3.h"

/**
 * Parse packet payload
 */

nu_error_t parse_dgram(connection_t * connection, unsigned char *dgram,
		       unsigned int dgram_size, connection_t ** conn,
		       nufw_message_t msg_type)
{
	unsigned char *orig_dgram = dgram;
	unsigned int ip_hdr_size;
	struct iphdr *ip = (struct iphdr *) dgram;
	/* get ip headers till tracking is filled */
	ip_hdr_size = get_ip_headers(&connection->tracking, dgram, dgram_size);

	if (ip_hdr_size == 0) {
		log_message(WARNING, DEBUG_AREA_PACKET | DEBUG_AREA_GW,
			    "Can't parse IP headers");
		free_connection(connection);
		return NU_EXIT_ERROR;
	}

	dgram += ip_hdr_size;
	dgram_size -= ip_hdr_size;


	/* get saddr and daddr */
	/* check if proto is in Hello mode list (when hello authentication is used) */
	if (nuauthconf->hello_authentication
	    && localid_authenticated_protocol(connection)) {
		connection->state = AUTH_STATE_HELLOMODE;
		connection->auth_quality = AUTHQ_HELLO;
		*conn = connection;
	} else {
		connection->state = AUTH_STATE_AUTHREQ;
	}
	switch (connection->tracking.protocol) {
	case IPPROTO_TCP:
		{
			tcp_state_t tcp_state = get_tcp_headers(&connection->tracking, dgram,
					    dgram_size);
			switch (tcp_state) {
			case TCP_STATE_OPEN:
				break;
			case TCP_STATE_CLOSE:
				if (msg_type == AUTH_CONTROL) {
					connection->state =
					    AUTH_STATE_DONE;
					log_message(WARNING, DEBUG_AREA_GW,
						    "nufw sends non SYN TCP packet, ignoring");
					free_connection(connection);
					return NU_EXIT_NO_RETURN;
				}
				break;
			case TCP_STATE_ESTABLISHED:
				if (msg_type == AUTH_CONTROL) {
					connection->state =
					    AUTH_STATE_DONE;
					log_message(WARNING, DEBUG_AREA_GW,
						    "nufw sends SYN ACK TCP packet, ignoring");
					free_connection(connection);
					return NU_EXIT_NO_RETURN;
				}
				break;
			default:
				log_message(WARNING, DEBUG_AREA_PACKET | DEBUG_AREA_GW,
					    "Non-SYN TCP headers, we should not have received this packet");
				connection->state = AUTH_STATE_DONE;
				free_connection(connection);
				return NU_EXIT_NO_RETURN;
			}
			break;
		}
		break;

	case IPPROTO_UDP:
		if (get_udp_headers
		    (&connection->tracking, dgram, dgram_size) < 0) {
			free_connection(connection);
			return NU_EXIT_OK;
		}
		break;

	case IPPROTO_ICMP:
		if (get_icmp_headers
		    (&connection->tracking, dgram, dgram_size) < 0) {
			free_connection(connection);
			return NU_EXIT_OK;
		}
		break;

	case IPPROTO_ICMPV6:
		if (get_icmpv6_headers
		    (&connection->tracking, dgram, dgram_size) < 0) {
			free_connection(connection);
			return NU_EXIT_OK;
		}
		break;

	default:
		if (connection->state != AUTH_STATE_HELLOMODE) {
			log_message(WARNING, DEBUG_AREA_PACKET | DEBUG_AREA_GW,
				    "Can't parse protocol %u",
				    connection->tracking.protocol);
			free_connection(connection);
			return NU_EXIT_ERROR;
		}
	}

	if (ntohs(ip->tot_len) > STORED_PAYLOAD_SIZE)
		connection->payload_len = STORED_PAYLOAD_SIZE;
	else
		connection->payload_len = ntohs(ip->tot_len);
	memcpy(connection->payload, orig_dgram, connection->payload_len);

	return NU_EXIT_CONTINUE;
}

#define GET_IFACE_FROM_MSG(conn, msg, iface) \
	do { if (msg->iface) \
		{ if (msg->iface[0] != '*') \
			memcpy(conn->iface_nfo.iface, msg->iface, IFNAMSIZ); }  \
		else { conn->iface_nfo.iface[0] = '\0'; } \
	} while (0)

/**
 * Parse fields of the message
 *
 * Add mark and interface information to the
 * connection
 *
 * \param msg the message from nufw
 * \param conn the connection to be filled
 * \return a nu_error_t
 */

nu_error_t parse_v4_fields(nuv4_nufw_to_nuauth_auth_message_t * msg,
			   connection_t * conn)
{
	conn->mark = ntohl(msg->mark);

	GET_IFACE_FROM_MSG(conn, msg, indev);
	GET_IFACE_FROM_MSG(conn, msg, physindev);
	GET_IFACE_FROM_MSG(conn, msg, outdev);
	GET_IFACE_FROM_MSG(conn, msg, physoutdev);

	return NU_EXIT_OK;
}

#undef GET_IFACE_FROM_MSG

/**
 * Parse message content for message of type #AUTH_REQUEST or #AUTH_CONTROL
 * using structure ::nufw_to_nuauth_auth_message_t.
 *
 * \param dgram Pointer to packet datas
 * \param dgram_size Number of bytes in the packet
 * \param conn Pointer of pointer to the ::connection_t that we have to authenticate
 * \return A nu_error_t
 */
nu_error_t authpckt_new_connection(unsigned char *dgram,
				   unsigned int dgram_size,
				   connection_t ** conn)
{
	nuv4_nufw_to_nuauth_auth_message_t *msg =
	    (nuv4_nufw_to_nuauth_auth_message_t *) dgram;
	connection_t *connection;
	nu_error_t ret;

	if (dgram_size < sizeof(nuv4_nufw_to_nuauth_auth_message_t)) {
		log_message(WARNING, DEBUG_AREA_PACKET | DEBUG_AREA_GW,
			    "NuFW packet too small: %d for a minimum of %lu",
			    dgram_size,
			    (unsigned long)sizeof(nuv4_nufw_to_nuauth_auth_message_t));
		return NU_EXIT_ERROR;
	}
	dgram += sizeof(nuv4_nufw_to_nuauth_auth_message_t);
	dgram_size -= sizeof(nuv4_nufw_to_nuauth_auth_message_t);

	/* allocate new connection */
	connection = g_new0(connection_t, 1);
	if (connection == NULL) {
		log_message(WARNING, DEBUG_AREA_PACKET | DEBUG_AREA_GW,
			    "Can not allocate connection");
		return NU_EXIT_ERROR;
	}
#ifdef PERF_DISPLAY_ENABLE
	if (nuauthconf->debug_areas & DEBUG_AREA_PERF) {
		gettimeofday(&(connection->arrival_time), NULL);
	}
#endif
	connection->acl_groups = NULL;
	connection->user_groups = NULL;
	connection->decision = DECISION_NODECIDE;
	connection->expire = -1;
	connection->payload_len = 0;

	connection->packet_id =
	    g_slist_append(NULL, GUINT_TO_POINTER(ntohl(msg->packet_id)));
	debug_log_message(DEBUG, DEBUG_AREA_PACKET | DEBUG_AREA_GW,
			  "Auth pckt: Working on new connection (id=%u)",
			  (uint32_t) GPOINTER_TO_UINT(connection->
						      packet_id->data));

	/* timestamp */
	connection->timestamp = ntohl(msg->timestamp);
	if (connection->timestamp == 0) {
		connection->timestamp = time(NULL);
	}

	connection->flags = ACL_FLAGS_NONE;
	connection->nufw_version = msg->protocol_version;

	ret = parse_dgram(connection, dgram, dgram_size, conn,
			msg->msg_type);
	if (ret != NU_EXIT_CONTINUE) {
		return ret;
	}

	/* parse supplementary fields */
	if (parse_v4_fields(msg, connection) != NU_EXIT_OK) {
		return ret;
	}

	if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG, DEBUG_AREA_PACKET)) {
		print_connection(connection, "NuFW Packet");
	}
	*conn = connection;
	return NU_EXIT_OK;
}

/**
 * Parse a datagram packet from NuFW using structure
 * ::nufw_to_nuauth_message_header_t. Create a connection
 * (type ::connection_t) for message of type #AUTH_REQUEST or #AUTH_CONTROL.
 *
 * Call:
 *   - authpckt_new_connection(): Message type #AUTH_REQUEST or #AUTH_CONTROL
 *
 * \param pdgram Pointer to datagram
 * \param pdgram_size Pointer to size of the datagram (in bytes)
 * \param conn Pointer of pointer to the ::connection_t that will be modified
 * \return
 *   - #NU_EXIT_ERROR if failure
 *   - #NU_EXIT_OK if ok and conn created
 *   - #NU_EXIT_NO_RETURN if no conn is needed but work is ok
 */
nu_error_t authpckt_decode(unsigned char **pdgram,
			   unsigned int *pdgram_size, connection_t ** conn)
{
	unsigned char *dgram = *pdgram;
	unsigned int dgram_size = *pdgram_size;
	nufw_to_nuauth_message_header_t *header;
	int ret;

	/* Switch following protocol version */
	header = (nufw_to_nuauth_message_header_t *) dgram;
	switch (header->protocol_version) {
	case PROTO_VERSION_NUFW_V22_2:
	case PROTO_VERSION_NUFW_V24:
		switch (header->msg_type) {
		case AUTH_REQUEST:
		case AUTH_CONTROL:
			ret = authpckt_new_connection(dgram, dgram_size, conn);
			if (ret == NU_EXIT_ERROR) {
				return NU_EXIT_ERROR;
			}

			if (ntohs(header->msg_length) < dgram_size) {
				*pdgram_size =
				    dgram_size - ntohs(header->msg_length);
				*pdgram =
				    dgram + ntohs(header->msg_length);
			} else {
				*pdgram_size = 0;
			}
			return ret;

			break;
		default:
			log_message(CRITICAL, DEBUG_AREA_PACKET | DEBUG_AREA_GW,
				    "NuFW packet type is unknown");
			return NU_EXIT_ERROR;
		}
		return NU_EXIT_OK;
	case PROTO_VERSION_NUFW_V20:
		switch (header->msg_type) {
		case AUTH_REQUEST:
		case AUTH_CONTROL:
			ret = authpckt_new_connection_v3(dgram, dgram_size,
						   conn);
			if (ret == NU_EXIT_ERROR) {
				return NU_EXIT_ERROR;
			}
			if (ntohs(header->msg_length) < dgram_size) {
				*pdgram_size =
				    dgram_size - ntohs(header->msg_length);
				*pdgram =
				    dgram + ntohs(header->msg_length);
			} else {
				*pdgram_size = 0;
			}
			return ret;

			break;
		default:
			log_message(CRITICAL, DEBUG_AREA_PACKET | DEBUG_AREA_GW,
				    "NuFW packet type is unknown");
			return NU_EXIT_ERROR;
		}
		return NU_EXIT_OK;
	case PROTO_VERSION_NUFW_V22:
		log_message(CRITICAL, DEBUG_AREA_PACKET | DEBUG_AREA_GW,
				    "nufw server runs pre 2.2.2 protocol: please upgrade");
		return NU_EXIT_OK;
	default:
		{
			log_message(CRITICAL, DEBUG_AREA_PACKET | DEBUG_AREA_GW,
				    "NuFW protocol is unknown");
		}

	}
	return NU_EXIT_OK;
}

/**
 * \return 0 if there is an error, value of protocol elsewhere
 */
unsigned char get_proto_version_from_packet(const unsigned char *dgram,
					    size_t dgram_size)
{
	nufw_to_nuauth_message_header_t *header;

	if (dgram_size < sizeof(nufw_to_nuauth_message_header_t)) {
		return 0;
	}
	/* Check protocol version */
	header = (nufw_to_nuauth_message_header_t *) dgram;
	/* Is protocol supported */
	if (check_protocol_version(NUFW_PROTO, header->protocol_version) == NU_EXIT_OK) {
		return header->protocol_version;
	} else {
		return 0;
	}
}

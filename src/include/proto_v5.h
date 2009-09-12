/*
 ** Copyright (C) 2009 INL
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

#ifndef NUFW_PROTOCOL_V5_H
#define NUFW_PROTOCOL_V5_H

/* almost everything is unchanged */
#define nuv5_conntrack_message_t nuv4_conntrack_message_t
#define nuv5_nufw_to_nuauth_auth_message_t nuv4_nufw_to_nuauth_auth_message_t

/**
 * Send NuAuth decision to NuFW
 */
typedef struct {
	uint8_t protocol_version;	/*!< Version of the protocol (#PROTO_VERSION) */
	uint8_t msg_type;	/*!< Message type (#AUTH_ANSWER) */
	u_int8_t decision;	/*!< NuAuth decision (see ::decision_t) */
	u_int8_t priority;	/*!< priority (See if there is an interest of having this in the scope of asynchronous message) */
	uint32_t packet_id;	/*!< NetFilter packet unique identifier */
	uint32_t tcmark;	/*!< User identifier */
	uint32_t expiration;	/*!< Packet expiration */
	uint16_t payload_len;	/*!< Indicate the length of data in the recv buffer after 
				   the end of the structure that contains the payload of packet. Set
				   to 0 to treat the following data as a new decision response */
	uint16_t padding;	/*!< 0x00000000 */
} nuv5_nuauth_decision_response_t;



#endif /* NUFW_PROTOCOL_V5_H */



/*
 ** proto.h, definition of structure for NuFW protocol
 ** Copyright (C) 2002-2006 Eric Leblond <eric@regit.org>
 **		      Vincent Deffontaines <vincent@gryzor.com>
 **                    INL http://www.inl.fr/
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

#ifndef NUFW_PROTOCOL_V4_H
#define NUFW_PROTOCOL_V4_H

#include <netinet/in.h>    /* struct in6addr */
/** \todo Fix this for nuauth on non Linux computer */
#ifdef LINUX
#include <linux/if.h>
#else
#define IFNAMSIZ 16
#endif

/** 
 * Protocol version of message exchanged between NuFW and NuAuth.
 *
 * Value of field protocol_version of ::nufw_to_nuauth_message_header_t
 */

/* 
 * Protocol 4 definition 
 */

/**
 * Message of type #AUTH_CONN_DESTROY or #AUTH_CONN_UPDATE send 
 * by NuFW to NuAuth
 */
struct nuv4_conntrack_message_t {
    /* Copy/paste nufw_to_nuauth_message_header_t content */
    uint8_t protocol_version; /*!< Version of the protocol (#PROTO_VERSION) */
    uint8_t msg_type;         /*!< Message type (from ::nufw_message_t) */
    uint16_t msg_length;      /*!< Message length including header (in bytes) */

    /* Conntrack fields */
    uint32_t timeout;        /*!< Timeout (Epoch format) */
    struct in6_addr ip_src;  /*!< IPv6 source IP */
    struct in6_addr ip_dst;  /*!< IPv6 destination IP */
    uint8_t  ip_protocol;    /*!< IP protocol number */
    uint16_t src_port;       /*!< TCP/UDP source port or ICMP type */
    uint16_t dest_port;      /*!< TCP/UDP destionation port or ICMP code */

    /* mark field */
    u_int32_t	mark;

    /* counters fields */
    u_int64_t packets_in;
    u_int64_t bytes_in;
    u_int64_t packets_out;
    u_int64_t bytes_out;

};

/**
 * Message of type #AUTH_REQUEST or #AUTH_CONTROL
 * send by NuFW to NuAuth
 */
typedef struct {
    /* Copy/paste nufw_to_nuauth_message_header_t content */
    uint8_t protocol_version; /*!< Version of the protocol (#PROTO_VERSION) */
    uint8_t msg_type;         /*!< Message type (from ::nufw_message_t) */
    uint16_t msg_length;      /*!< Message length including header (in bytes) */

    /* Authentification fields */
    uint32_t packet_id;      /*!< Netfilter packet unique identifier */
    uint32_t timestamp;      /*!< Timestamp (Epoch format) */

    u_int32_t mark;
    char indev[IFNAMSIZ] ;
    char physindev[IFNAMSIZ] ;
    char outdev[IFNAMSIZ] ;
    char physoutdev[IFNAMSIZ] ;
    /* \todo Internal fields 
    	 hwmac
     */

    /* (...): packet content (maybe truncated) */
} nuv4_nufw_to_nuauth_auth_message_t;

/**
 * Send NuAuth decision to NuFW
 */
typedef struct {
    uint8_t protocol_version;   /*!< Version of the protocol (#PROTO_VERSION) */
    uint8_t msg_type;           /*!< Message type (#AUTH_ANSWER) */
    u_int8_t decision;          /*!< NuAuth decision (see ::decision_t) */
    u_int8_t priority;          /*!< priority (See if there is an interest of having this in the scope of asynchronous message) */
    uint32_t packet_id;         /*!< NetFilter packet unique identifier */
    u_int32_t tcmark;          /*!< User identifier */
    uint16_t payload_len;       /*!< Indicate the length of datas in the recv buffer after 
                                  the end of the structure that contains the payload of packet. Set
                                  to 0 to treat the following datas as a new decision response */
    uint16_t padding;		/*!< 0x00000000 */
} nuv4_nuauth_decision_response_t;    

#endif


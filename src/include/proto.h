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

#ifndef NUFW_PROTOCOL_H
#define NUFW_PROTOCOL_H

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#ifdef LINUX 
#  include <endian.h>
#else
#  include <machine/endian.h>
#endif

#include <netinet/in.h>    /* struct in6addr */

/** 
 * Protocol version of message exchanged between NuFW and NuAuth.
 *
 * Value of field protocol_version of ::nufw_to_nuauth_message_header_t
 */
#define PROTO_VERSION 3

/**
 * Message type : stored on 4 bits
 *
 * Used in ::nufw_to_nuauth_message_header_t
 */
typedef enum
{
    AUTH_REQUEST=0x1,
    AUTH_ANSWER,
    USER_REQUEST,
    AUTH_CONTROL,
    USER_HELLO,
    AUTH_CONN_DESTROY,
    AUTH_CONN_UPDATE,
    AUTH_CONN_FIXED_TIMEOUT
} nufw_message_t;

typedef enum
{
    DECISION_DROP=0,    /*!< NuAuth decision answer: drop packet */
    DECISION_ACCEPT,    /*!< NuAuth decision answer: packet accepted */
    DECISION_NODECIDE,  /*!< NuAuth decision answer: can't decide! */
    DECISION_REJECT     /*!< NuAuth decision answer: reject the packet */ 
} decision_t;    

#define AUTHREQ_PORT "4129"
#define USERPCKT_PORT "4130"

/* 
 * Protocol 2 definition 
 */

/* header common for all packets
   1         4            8            16          24     32
   |         |            |            |           |      |
   |  Proto  |Msg Type    | Msg option |    packet length |

   message type is one of :

AUTHREQ : user send packet

*/

struct nuv2_header {
#ifdef WORDS_BIGENDIAN	
    uint8_t msg_type:4;
    uint8_t proto:4;
#else
    uint8_t proto:4;
    uint8_t msg_type:4;
#endif
    uint8_t option;
    uint16_t length;
};

typedef enum
{
    IPV4_FIELD=1,
    IPV6_FIELD,
    APP_FIELD,
    OS_FIELD,
    USERNAME_FIELD,
    HELLO_FIELD
} field_identifier_t;    

/**
 * (possible value of the option member of ::nuv2_authfield)
 */
#define OS_SRV 0x1

#define APP_TYPE_NAME 0x1 /** application is defined by full path.  */

/**
 * Application is defined by full path and SHA1 sig of binary.
 *
 * Format is : "full_path_app;SHA1 sig" each filed being base64 encoded
 */
#define APP_TYPE_SHA1 0x2 

struct nuv2_authreq {
    uint16_t packet_seq;
    uint16_t packet_length; /*!< Length of the whole packet including this header */
};

/**
 * Header of one field.
 * See also the header of the whole packet: ::nuv2_authreq
 */
struct nuv2_authfield {
    uint8_t type;    /*!< Field type identifier: see ::field_identifier_t */
    uint8_t option;  /*!< Option: equals to 0 to #OS_SRV */
    uint16_t length; /*!< Length of one field */
};

/* TODO : inject struct nuv2_authfield ? */
struct nuv2_authfield_ipv6 {
    uint8_t type;
    uint8_t option;
    uint16_t length;   /*!< Length of one field */
    struct in6_addr src;
    struct in6_addr dst;
    uint8_t proto;
    uint8_t flags;
    uint16_t FUSE;
    uint16_t sport;
    uint16_t dport;
};

/**
 * Application field datas
 */
struct nuv2_authfield_app {
    uint8_t type;
    uint8_t option;
    uint16_t length;   /*!< Length of content */

    /* after that is the application content */
};

/** 
 * Username field data
 */ 
struct nuv2_authfield_username {
    uint8_t type;
    uint8_t option;
    uint16_t length;   /*!< Length of one field */
    char *datas;
};

struct nuv2_authfield_hello {
    uint8_t type;
    uint8_t option;
    uint16_t length;
    uint32_t helloid;   /*!< Length of one field */
};


/* sender to client message */

/* type message */
typedef enum
{
    SRV_TYPE = 1,               /*!< Send server mode: #SRV_TYPE_PUSH or #SRV_TYPE_POLL */
    SRV_REQUIRED_PACKET,
    SRV_REQUIRED_DISCONNECT,
    SRV_REQUIRED_HELLO
} nuv2_type_t;

/** Server mode, value of with #SRV_TYPE (::nuv2_srv_message) message type */
typedef enum
{
    SRV_TYPE_POLL=0,   /*!< Server works in POLL mode (default) */
    SRV_TYPE_PUSH      /*!< Server works in PUSH mode */
} nuv2_server_mode_t;

struct nuv2_srv_message {
    uint8_t type;
    uint8_t option;
    uint16_t length;
};

struct nuv2_srv_helloreq {
    uint8_t type,option;
    uint16_t length;
    uint32_t helloid;
};

/** 
 * Header of message send by NuFW to NuAuth 
 *
 * See also structures ::nufw_to_nuauth_conntrack_message_t and
 * ::nufw_to_nuauth_auth_message_t which include message content.
 */
typedef struct {
    /** Version of the protocol (#PROTO_VERSION) */
    uint8_t protocol_version;

    /** Message type (from ::nufw_message_t) */
    uint8_t msg_type;

    /** Message length including header (in bytes) */
    uint16_t msg_length;
} nufw_to_nuauth_message_header_t;

/**
 * Message of type #AUTH_CONN_DESTROY or #AUTH_CONN_UPDATE send 
 * by NuFW to NuAuth
 */
struct nu_conntrack_message_t {
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

    /* (...): packet content (maybe truncated) */
} nufw_to_nuauth_auth_message_t;

/**
 * Send NuAuth decision to NuFW
 */
typedef struct {
    uint8_t protocol_version;   /*!< Version of the protocol (#PROTO_VERSION) */
    uint8_t msg_type;           /*!< Message type (#AUTH_ANSWER) */
    /* TODO Use user id in 32 bits? Or rename the field "QoS_group_id"? */
    u_int16_t user_id;          /*!< User identifier */
    u_int8_t decision;          /*!< NuAuth decision (see ::decision_t) */
    uint8_t priority;           /*!< Priority ? */
    uint16_t padding;           /*!< Padding (0x0000) */
    uint32_t packet_id;         /*!< NetFilter packet unique identifier */
    uint16_t payload_len;       /*!< Indicate the length of datas in the recv buffer after 
                                  the end of the structure that contains the payload of packet. Set
                                  to 0 to treat the following datas as a new decision response */
} nuauth_decision_response_t;    

#endif


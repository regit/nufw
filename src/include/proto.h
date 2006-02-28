/*
 ** proto.h, definition of structure for NuFW protocol
 ** Copyright (C) 2002-2004 Eric Leblond <eric@regit.org>
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


#include <config.h>
#ifdef LINUX 
#  include <endian.h>
#else
#  include <machine/endian.h>
#endif

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
    AUTH_ANSWER, // 0x2
    USER_REQUEST, // 0x3
    AUTH_CONTROL, // 0x4
    USER_HELLO, // 0x5
    AUTH_CONN_DESTROY, // 0x6
    AUTH_CONN_UPDATE, // 0x7
    AUTH_CONN_FIXED_TIMEOUT // 0x8 
} nufw_message_t;

typedef enum
{
    DECISION_DROP=0,    /*!< NuAuth decision answer: drop packet */
    DECISION_ACCEPT,    /*!< NuAuth decision answer: packet accepted */
#ifdef GRYZOR_HACKS
    DECISION_NODECIDE,  /*!< NuAuth decision answer: can't decide! */
    DECISION_REJECT     /*!< NuAuth decision answer: reject the packet */ 
#else            
    DECISION_NODECIDE   /*!< NuAuth decision answer: can't decide! */
#endif
} decision_t;    

#define AUTHSRV_PORT 4128
#define AUTHREQ_PORT 4129

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
    uint8_t msg_type:4,proto:4;
    uint8_t option;
#else
    uint8_t proto:4,msg_type:4;
    uint8_t option;
#endif
    uint16_t length;
};

struct nuv2_authreq {
    uint16_t packet_id;
    uint16_t packet_length;
};

#define IPV4_FIELD 0x1
#define IPV6_FIELD 0x2
#define APP_FIELD 0x3
#define OS_FIELD 0x4
#define USERNAME_FIELD 0x5
#define HELLO_FIELD 0x6
#define OS_SRV 0x1

struct nuv2_authfield {
        uint8_t type;
        uint8_t option;
        uint16_t length;
};

/* TODO : inject struct nuv2_authfield ? */
struct nuv2_authfield_ipv4 {
        uint8_t type;
        uint8_t option;
        uint16_t length;
        uint32_t src;
        uint32_t dst;
        uint8_t proto;
        uint8_t flags;
        uint16_t FUSE;
        uint16_t sport;
        uint16_t dport;
};

#define APP_TYPE_NAME 0x1 /** application is defined by full path.  */
/** application is defined by full path and SHA1 sig of binary.
 *
 * Format is : "full_path_app;SHA1 sig" each filed being base64 encoded
 */
#define APP_TYPE_SHA1 0x2 
struct nuv2_authfield_app {
        uint8_t type;
        uint8_t option;
        uint16_t length;
	char *datas;
};

/** 
 * username data
 * 
 */ 

struct nuv2_authfield_username {
        uint8_t type;
        uint8_t option;
        uint16_t length;
	char *datas;
};

struct nuv2_authfield_hello {
        uint8_t type;
        uint8_t option;
        uint16_t length;
	uint32_t helloid;
};


/* sender to client message */

/* type message */
#define SRV_TYPE 0x1
#define SRV_REQUIRED_PACKET 0x2
#define SRV_REQUIRED_DISCONNECT 0x3
#define SRV_REQUIRED_HELLO 0x4

/* option set to 0 by default */
/* option for server type */
#define SRV_TYPE_POLL 0x0
#define SRV_TYPE_PUSH 0x1

struct nuv2_srv_message {
        uint8_t type,option;
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
    /** Version of the protocol (equals to #PROTO_VERSION) */
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
    uint8_t protocol_version; /*!< Version of the protocol (equals to #PROTO_VERSION) */
    uint8_t msg_type;         /*!< Message type (from ::nufw_message_t) */
    uint16_t msg_length;      /*!< Message length including header (in bytes) */

    /* Conntrack fields */
    uint32_t timeout;        /*!< Timeout (Epoch format) */
    uint32_t ipv4_src;       /*!< IPv4 source IP */
    uint32_t ipv4_dst;       /*!< IPv4 destination IP */
    uint8_t  ipv4_protocol;  /*!< IPv4 protocol number */
    uint16_t src_port;       /*!< TCP/UDP source port or ICMP type */
    uint16_t dest_port;      /*!< TCP/UDP destionation port or ICMP code */
};

/**
 * Message of type #AUTH_REQUEST or #AUTH_CONTROL
 * send by NuFW to NuAuth
 */
typedef struct {
    /* Copy/paste nufw_to_nuauth_message_header_t content */
    uint8_t protocol_version; /*!< Version of the protocol (equals to #PROTO_VERSION) */
    uint8_t msg_type;         /*!< Message type (from ::nufw_message_t) */
    uint16_t msg_length;      /*!< Message length including header (in bytes) */

    /* Authentification fields */
    uint32_t packet_id;      /*!< Netfilter packet unique identifier */
    uint32_t timestamp;      /*!< Timestamp (Epoch format) */

    /* (...): packet content (maybe truncated) */
} nufw_to_nuauth_auth_message_t;


/*
 ** Copyright (C) 2002-2007 - INL
 ** Written by Eric Leblond <regit@inL.fr>
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

#define AUTHREQ_PORT 4128
#define USERPCKT_PORT 4129
#define USERPCKT_SERVICE "4129"

/* define here last proto */

#define PROTO_STRING "PROTO"
#define PROTO_UNKNOWN 0

enum proto_type_t {
	NUFW_PROTO = 0,
	CLIENT_PROTO
};

enum proto_client_version_t {
	PROTO_VERSION_NONE,
	PROTO_VERSION_V20 = 3,
	PROTO_VERSION_V22,
	PROTO_VERSION_V22_1,
	PROTO_VERSION_V24
};

#define PROTO_VERSION PROTO_VERSION_V24

enum proto_nufw_version_t {
	PROTO_VERSION_NUFW_V20 = 3,
	PROTO_VERSION_NUFW_V22,
	PROTO_VERSION_NUFW_V22_2,
	PROTO_VERSION_NUFW_V24
};

#define PROTO_NUFW_VERSION PROTO_VERSION_NUFW_V24

/* header common for all packets
   1         4            8            16          24     32
   |         |            |            |           |      |
   |  Proto  |Msg Type    | Msg option |    packet length |

   message type is one of :

AUTHREQ : user send packet

*/

struct nu_header {
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
 * (possible value of the option member of ::nuv2_authfield)
 */
#define OS_SRV 0x1
#define CLIENT_SRV 0x1

#define APP_TYPE_NAME 0x1 /** application is defined by full path.  */

/**
 * Application is defined by full path and SHA1 sig of binary.
 *
 * Format is : "full_path_app;SHA1 sig" each filed being base64 encoded
 */
#define APP_TYPE_SHA1 0x2

/**
 * Define client HELLO interval
 */
#define NU_USER_HELLO_INTERVAL 30
#define NU_USER_HELLO_GRACETIME 10

typedef enum {
	DECISION_DROP = 0,	/*!< NuAuth decision answer: drop packet */
	DECISION_ACCEPT,	/*!< NuAuth decision answer: packet accepted */
	DECISION_NODECIDE,	/*!< NuAuth decision answer: can't decide! */
	DECISION_REJECT		/*!< NuAuth decision answer: reject the packet */
} decision_t;


/**
 * Message type : stored on 4 bits
 *
 * Used in ::nufw_to_nuauth_message_header_t
 */
typedef enum {
	AUTH_REQUEST = 0x1,
	AUTH_ANSWER,
	USER_REQUEST,
	AUTH_CONTROL,
	USER_HELLO,
	AUTH_CONN_DESTROY,
	AUTH_CONN_UPDATE,
	AUTH_CONN_FIXED_TIMEOUT,
	EXTENDED_PROTO,
} nufw_message_t;


typedef enum {
	IPV4_FIELD = 1,
	IPV6_FIELD,
	APP_FIELD,
	OS_FIELD,
	VERSION_FIELD,
	HELLO_FIELD,
	CAPA_FIELD,
	EXTENDED_PROTO_FIELD,
	HASH_FIELD,
} nu_field_identifier_t;

struct nu_authreq {
	uint16_t packet_seq;
	uint16_t packet_length;	/*!< Length of the whole packet including this header */
};

/**
 * Header of one field.
 * See also the header of the whole packet: ::nu_authreq
 */
struct nu_authfield {
	uint8_t type;		/*!< Field type identifier: see ::nuv_field_identifier_t */
	uint8_t option;		/*!< Option: equals to 0 to #OS_SRV */
	uint16_t length;	/*!< Length of one field */
};

struct nu_authfield_ipv6 {
	uint8_t type;
	uint8_t option;
	uint16_t length;	/*!< Length of one field */
	struct in6_addr src;
	struct in6_addr dst;
	uint8_t proto;
	uint8_t flags;
	uint16_t FUSE;
	uint16_t sport;
	uint16_t dport;
};

struct nu_authfield_ipv4 {
	uint8_t type;
	uint8_t option;
	uint16_t length;	/*!< Length of one field */
	uint32_t src;
	uint32_t dst;
	uint8_t proto;
	uint8_t flags;
	uint16_t FUSE;
	uint16_t sport;
	uint16_t dport;
};



/**
 * Application field datas
 */
struct nu_authfield_app {
	uint8_t type;
	uint8_t option;
	uint16_t length;	/*!< Length of content */

	/* after that is the application content */
};

struct nu_authfield_hello {
	uint8_t type;
	uint8_t option;
	uint16_t length;
	uint32_t helloid;	/*!< Length of one field */
};


/* sender to client message */

/* type message */
typedef enum {
	SRV_TYPE = 1,		/*!< Send server mode: #SRV_TYPE_PUSH or #SRV_TYPE_POLL */
	SRV_REQUIRED_PACKET,
	SRV_REQUIRED_DISCONNECT,
	SRV_REQUIRED_HELLO,
	SRV_REQUIRED_INFO,
	SRV_EXTENDED_PROTO,
	SRV_INIT,
} nu_type_t;

/** Server mode, value of with #SRV_TYPE (::nuv2_srv_message) message type */
typedef enum {
	SRV_TYPE_POLL = 0,	/*!< Server works in POLL mode (default) */
	SRV_TYPE_PUSH,		/*!< Server works in PUSH mode */
	SRV_HASH_TYPE		/*!< Server hash function for app sig */
} nu_server_mode_t;

typedef enum {
	OS_VERSION = 0,
	CLIENT_VERSION,
	CLIENT_CAPA
} nu_client_info_t;

typedef enum {
	INIT_NOK = 0,
	INIT_OK
} nu_srv_init_t;


struct nu_srv_message {
	uint8_t type;
	uint8_t option;
	uint16_t length;
};

struct nu_srv_helloreq {
	uint8_t type, option;
	uint16_t length;
	uint32_t helloid;
};

/* include definition for NuFW 2.0 */
#include <proto_v3.h>

/* include definition for NuFW 2.2 */
#include <proto_v4.h>

/* include definition for NuFW 2.4 */
#include <proto_v5.h>

#endif

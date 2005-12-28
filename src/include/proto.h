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

#include <endian.h>

#define swap16(A)  ((((uint16_t)(A) & 0xff00) >> 8) | (((uint16_t)(A) & 0x00ff) << 8))
#define swap32(A)  ((((uint32_t)(A) & 0xff000000) >> 24) | \
		                   (((uint32_t)(A) & 0x00ff0000) >> 8)  | \
		                   (((uint32_t)(A) & 0x0000ff00) << 8)  | \
		                   (((uint32_t)(A) & 0x000000ff) << 24))

#define PROTO_VERSION 1
#define AUTHREQ_OFFSET 12

/**
 * Message type : stored on 4 bits
 */
#define AUTH_REQUEST 0x1
#define AUTH_ANSWER 0x2
#define USER_REQUEST 0x3
#define AUTH_CONTROL 0x4
#define USER_HELLO 0x5
#define AUTH_CONN_DESTROY 0x6

#define NOK 0
#define OK 1
#define NODECIDE 2
#ifdef GRYZOR_HACKS
#define NOK_REJ 3
#endif

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

/* TODO : inject struct nuv2_authfield ? */
struct nuv2_destroy_message {
        uint8_t protocol;
        uint8_t type;
        uint16_t length;
        uint32_t src;
        uint32_t dst;
        uint8_t ipproto;
        uint16_t sport;
        uint16_t dport;
};



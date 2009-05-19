/*
 ** Copyright(C) 2003-2009 - INL
 ** Written by Eric Leblond <regit@inl.fr>
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

/** \file pckt_authsrv.h
 *  \brief Functions to parse a network packet
 *
 * Functions fill ::tracking_t structure fields. Parser are: IPv4, IPv6, UDP,
 * TCP, ICMP and ICMP6.
 */

#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include "ipv6.h"
#include <sys/types.h>

/** State of a connection */
typedef enum {
	TCP_STATE_DROP = 0,	/*!< NuAuth decide to drop the connection */
	TCP_STATE_OPEN,		/*!< A new connection is just created (SYN) */
	TCP_STATE_ESTABLISHED,	/*!< The connection is established (SYN,ACK) */
	TCP_STATE_CLOSE,	/*!< The connection is closed (RST) */
	TCP_STATE_UNKNOW	/*!< Error code of get_tcp_headers() function */
} tcp_state_t;

/**
 * Informations about an IPv4 connection used as key for connection
 * identification.
 */
typedef struct {
	/* Group informations about destination to make
	 * ACL hash function faster. If you change this
	 * structure, please also change hash_acl() and hash_connection() */
	struct in6_addr saddr;	/*!< IPv6 source address */
	struct in6_addr daddr;	/*!< IPv6 destination address */
	u_int8_t protocol;	/*!< IP protocol */
	u_int8_t padding;	/*!< Padding to 32 bits alignment */

	u_int16_t dest;		/*!< TCP/UDP destination port */
	u_int16_t source;	/*!< TCP/UDP source port */

	u_int8_t type;		/*!< ICMP message type */
	u_int8_t code;		/*!< ICMP code type */

} tracking_t;

unsigned int get_ip_headers(tracking_t * tracking,
			    const unsigned char *dgram,
			    unsigned int dgram_size);
int get_udp_headers(tracking_t * tracking, const unsigned char *dgram,
		    unsigned int dgram_size);
tcp_state_t get_tcp_headers(tracking_t * tracking,
			    const unsigned char *dgram,
			    unsigned int dgram_size);
int get_icmp_headers(tracking_t * tracking, const unsigned char *dgram,
		     unsigned int dgram_size);
int get_icmpv6_headers(tracking_t * tracking, const unsigned char *dgram,
		       unsigned int dgram_size);

#endif

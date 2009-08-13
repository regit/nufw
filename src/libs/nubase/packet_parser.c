/*
 ** Copyright(C) 2003-2006 - INL
 ** Written by Eric Leblond <regit@inl.fr>
 **            Victor Stinner <haypo@inl.fr>
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

/**
 * \addtogroup Nubase
 *
 * @{
 */ 

/** \file packet_parser.c
 *  \brief Functions to parse a network packet
 *
 * Functions fill ::tracking_t structure fields. Parser are: IPv4, IPv6, UDP,
 * TCP, ICMP and ICMP6.
 */

#include "packet_parser.h"

#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include <config.h>

/**
 * Fill IP fields (saddr, daddr and protocol) of the a connection tracking
 * (::tracking_t) structure.
 *
 * \param tracking Pointer to a connection tracking
 * \param dgram Pointer to packet datas
 * \param dgram_size Number of bytes in the packet
 * \return Offset to next type of headers, or 0 if the packet is not recognized
 */
unsigned int get_ip_headers(tracking_t * tracking,
			    const unsigned char *dgram,
			    unsigned int dgram_size)
{
#ifdef LINUX
	struct iphdr *ip = (struct iphdr *) dgram;
#endif
#ifdef FREEBSD
	struct ip *ip = (struct ip*) dgram;
#endif
	struct ip6_hdr *ip6 = (struct ip6_hdr *) dgram;
	unsigned int offset;

	/* check ip headers minimum size */
#ifdef LINUX
	if (dgram_size < sizeof(struct iphdr))
#elif defined(FREEBSD)
	if (dgram_size < sizeof(struct ip))
#endif
		return 0;

	/* check IP version (should be IPv4) */
#ifdef LINUX
	if (ip->version == 4) {
		/* convert IPv4 addresses to IPv6 addresses in format "::ffff:IPv4" */
		uint32_to_ipv6(ip->saddr, &tracking->saddr);
		uint32_to_ipv6(ip->daddr, &tracking->daddr);

		/* compute offset to next header and copy protocol */
		offset = 4 * ip->ihl;
		tracking->protocol = ip->protocol;
	} else if (ip->version == 6) {
#else
	if (ip->ip_v == 4) {
		/* convert IPv4 addresses to IPv6 addresses in format "::ffff:IPv4" */
		uint32_to_ipv6(ip->ip_src.s_addr, &tracking->saddr);
		uint32_to_ipv6(ip->ip_dst.s_addr, &tracking->daddr);

		/* compute offset to next header and copy protocol */
		offset = 4 * ip->ip_hl;
		tracking->protocol = ip->ip_p;
	} else if (ip->ip_v == 6) {
#endif


		unsigned char found_transport_layer = 0;
		struct ip6_ext *generic_hdr;
		struct ip6_frag *frag_hdr;

		/* check buffer underflow */
		if (dgram_size < sizeof(struct ip6_hdr))
			return 0;

		/* copy ipv6 addresses */
		tracking->saddr = ip6->ip6_src;
		tracking->daddr = ip6->ip6_dst;

		/* copy protocol */
		tracking->protocol = ip6->ip6_nxt;

		/* compute offset of next interresting header (udp/tcp/icmp):
		 * skip custom ipv6 headers like Hop-by-hop */
		offset = sizeof(struct ip6_hdr);	/* offset=40 */
		found_transport_layer = 0;
		do {
			switch (tracking->protocol) {
			case IPPROTO_HOPOPTS:
			case IPPROTO_ROUTING:
			case IPPROTO_DSTOPTS:
			case IPPROTO_AH:
				/* we can use generic extension header since we just need
				 * next header and length of this header */
				generic_hdr =
				    (struct ip6_ext *) (dgram + offset);
				tracking->protocol = generic_hdr->ip6e_nxt;
				offset +=
				    (unsigned int) (generic_hdr->
						    ip6e_len) * 8;
				break;

			case IPPROTO_FRAGMENT:
				frag_hdr =
				    (struct ip6_frag *) (dgram + offset);
				tracking->protocol = frag_hdr->ip6f_nxt;
				offset += 8;	/* fragment header has fixed size */
				break;

			case IPPROTO_ESP:
			case IPPROTO_NONE:
				/*
				 * - RFC 2460 asks to ignore payload is last "Next Header"
				 *   is IPPROTO_NONE.
				 * - For ESP, it's not possible to extract any useful
				 *   informations to match ACLs
				 */
				found_transport_layer = 1;
				break;

			default:
				/* TCP, UDP, ICMP */
				found_transport_layer = 1;
				break;
			}
		} while (!found_transport_layer);
	} else {
		offset = 0;
	}
	return offset;
}

/**
 * Fill UDP fields (source and dest) of a connection tracking
 * (::tracking_t) structure.
 *
 * \param tracking Pointer to a connection tracking
 * \param dgram Pointer to packet datas
 * \param dgram_size Number of bytes in the packet
 * \return If an error occurs return 1, else returns 0
 */
int get_udp_headers(tracking_t * tracking, const unsigned char *dgram,
		    unsigned int dgram_size)
{
#ifdef LINUX
	struct udphdr *udp = (struct udphdr *) dgram;

	/* check udp headers minimum size */
	if (dgram_size < sizeof(struct udphdr))
		return -1;

	tracking->source = ntohs(udp->source);
	tracking->dest = ntohs(udp->dest);
	tracking->type = 0;
	tracking->code = 0;
#else
	/* TODO ;) */
#endif
	return 0;
}


/**
 * Fill TCP fields (source and dest) of the connection tracking
 * (::tracking_t) structure.
 *
 * \param tracking Pointer to a connection tracking
 * \param dgram Pointer to packet datas
 * \param dgram_size Number of bytes in the packet
 * \return State of the TCP connection (#TCP_STATE_OPEN,
 *         #TCP_STATE_ESTABLISHED, #TCP_STATE_CLOSE), or #TCP_STATE_UNKNOW
 *         if an error occurs.
 */
tcp_state_t get_tcp_headers(tracking_t * tracking,
			    const unsigned char *dgram,
			    unsigned int dgram_size)
{
#ifdef LINUX
	struct tcphdr *tcp = (struct tcphdr *) dgram;

	/* check icmp headers minimum size */
	if (dgram_size < sizeof(struct tcphdr))
		return TCP_STATE_UNKNOW;

	tracking->source = ntohs(tcp->source);
	tracking->dest = ntohs(tcp->dest);
	tracking->type = 0;
	tracking->code = 0;

	/* test if fin ack or syn */
	/* if fin ack return 0 end of connection */
	if (tcp->fin || tcp->rst)
		return TCP_STATE_CLOSE;

	/* if syn return 1 */
	if (tcp->syn) {
		if (tcp->ack) {
			return TCP_STATE_ESTABLISHED;
		} else {
			return TCP_STATE_OPEN;
		}
	}
#else
	/* TODO :P */
#endif
	return TCP_STATE_UNKNOW;
}

/**
 * Fill ICMP fields (type and code) of the connection tracking
 * (::tracking_t) structure.
 *
 * \param tracking Pointer to a connection tracking
 * \param dgram Pointer to packet datas
 * \param dgram_size Number of bytes in the packet
 * \return If an error occurs return 1, else returns 0
 */
int get_icmp_headers(tracking_t * tracking, const unsigned char *dgram,
		     unsigned int dgram_size)
{
#ifdef LINUX
	struct icmphdr *icmp = (struct icmphdr *) dgram;

	/* check udp headers minimum size */
	if (dgram_size < sizeof(struct icmphdr))
		return -1;

	tracking->source = 0;
	tracking->dest = 0;
	tracking->type = icmp->type;
	tracking->code = icmp->code;
#else
	/* TODO ! */
#endif
	return 0;
}

/**
 * Parse ICMPv6 header: extract type and code fields
 * for the connection tracking (::tracking_t) structure.
 *
 * \param tracking Pointer to a connection tracking
 * \param dgram Pointer to packet datas
 * \param dgram_size Number of bytes in the packet
 * \return If an error occurs return 1, else returns 0
 */
int get_icmpv6_headers(tracking_t * tracking, const unsigned char *dgram,
		       unsigned int dgram_size)
{
	struct icmp6_hdr *hdr = (struct icmp6_hdr *) dgram;

	/* check icmp headers minimum size */
	if (dgram_size < sizeof(struct icmp6_hdr))
		return -1;

	tracking->source = 0;
	tracking->dest = 0;
	tracking->type = hdr->icmp6_type;
	tracking->code = hdr->icmp6_code;
	return 0;
}

/** @} */

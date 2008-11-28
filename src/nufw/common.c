/*
**
** Copyright 2002 - 2007 INL
** Written by Eric Leblond <eric@regit.org>
**            Vincent Deffontaines <vincent@gryzor.com>
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

/** \file common.c
 *  \brief Common tools to manage ::packets_list.
 *   
 * Function to add (padd()), suppress (psuppress() and psearch_and_destroy()) and clean up 
 * (clean_old_packets()) packets from packet list (::packets_list).
 */

#include "nufw.h"

#include <stdlib.h>
#include <time.h>
#include <linux/icmp.h>		/* icmphdr */
#include <netinet/icmp6.h>	/* icmp6_hdr */
#include <netinet/ip.h>		/* iphdr */
#include <netinet/ip6.h>	/* ip6_hdr */

#include <nubase.h>


/* data stuff */

#ifdef PERF_DISPLAY_ENABLE
/**
 * Subtract the `struct timeval' values X and Y,
 * storing the result in RESULT.
 * Return 1 if the difference is negative, otherwise 0.  */

int timeval_substract(struct timeval *result, struct timeval *x,
		      struct timeval *y)
{
	/* Perform the carry for the later subtraction by updating y. */
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	 *           tv_usec is certainly positive. */
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;

	/* Return 1 if result is negative. */
	return x->tv_sec < y->tv_sec;
}
#endif

/**
 * Close the TLS session
 */
void close_tls_session()
{
	if (tls.session == NULL)
		return;

	pthread_mutex_destroy(&tls.auth_server_mutex);
	nussl_session_destroy(tls.session);
	tls.session = NULL;
}

/**
 * Suppress the packet current from the packet list (::packets_list).
 *
 * \param previous Packet before current
 * \param current Packet to remove
 */
void psuppress(packet_idl * previous, packet_idl * current)
{
	if (previous != NULL)
		previous->next = current->next;
	else
		packets_list.start = current->next;
	if (current->next == NULL) {
		packets_list.end = previous;
	}
	free(current);
	packets_list.length--;
}

/**
 * Try to add a packet to the end of ::packets_list. If we exceed max length
 * (::track_size), just drop the packet.
 *
 * \return 0 if ok, -1 if list is full. 
 */
int padd(packet_idl * current)
{
	if (track_size <= packets_list.length) {
		log_area_printf(DEBUG_AREA_PACKET, DEBUG_LEVEL_WARNING,
				"Warning: queue is full, dropping element");
		IPQ_SET_VERDICT(current->id, NF_DROP);
		return -1;
	}

	packets_list.length++;
	current->next = NULL;

	if (current->timestamp == 0) {
		current->timestamp = time(NULL);
	}

	if (packets_list.end != NULL)
		packets_list.end->next = current;
	packets_list.end = current;
	if (packets_list.start == NULL)
		packets_list.start = current;
	return 0;
}


/* called by authsrv */

/**
 * Search an entry in packet list (::packets_list), and drop and
 * suppress old packets (using ::packet_timeout). If the packet can be found,
 * delete it and copy it's mark into nfmark.
 * 
 * \return Returns 1 and the mark (in nfmark) if the packet can be found, 0 else.
 */
int psearch_and_destroy(uint32_t packet_id, uint32_t * nfmark)
{
	packet_idl *current = packets_list.start, *previous = NULL;
	int timestamp = time(NULL);

	/** \todo Do benchmarks and check if an hash-table + list (instead of just
	 * list) wouldn't be faster than just a list when NuAuth is slow */
	while (current != NULL) {
		if (current->id == packet_id) {
#if HAVE_LIBIPQ_MARK || USE_NFQUEUE
			*nfmark = current->nfmark;
#endif

#ifdef PERF_DISPLAY_ENABLE
			{
				struct timeval elapsed_time, leave_time;
				double ms;
				gettimeofday(&leave_time, NULL);
				timeval_substract(&elapsed_time,
						  &leave_time,
						  &(current->
						    arrival_time));
				ms = (double) elapsed_time.tv_sec * 1000 +
				    (double) elapsed_time.tv_usec / 1000;
				log_area_printf(DEBUG_AREA_PACKET,
						DEBUG_LEVEL_INFO,
						"Treatment time for connection: %.1f ms",
						ms);
			}
#endif


			psuppress(previous, current);
			return 1;

			/* we want to suppress first element if it is too old */
		} else if (timestamp - current->timestamp > packet_timeout) {
			IPQ_SET_VERDICT(current->id, NF_DROP);
			debug_log_printf(DEBUG_AREA_PACKET, DEBUG_LEVEL_INFO,
					 "Dropped: %lu", current->id);
			psuppress(previous, current);
			current = packets_list.start;
			previous = NULL;
		} else {
			previous = current;
			current = current->next;
		}
	}
	return 0;
}

/**
 * Clear packet list: delete all elements
 */
void clear_packet_list()
{
	packet_idl *current = packets_list.start, *next;
	while (current != NULL) {
		next = current->next;
		free(current);
		current = next;
	}
	packets_list.start = NULL;
	packets_list.end = NULL;
	packets_list.length = 0;
}

/**
 * Walk in the packet list (::packets_list) and remove old packets (using ::packet_timeout limit).
 */
void clean_old_packets()
{
	packet_idl *current = packets_list.start, *previous = NULL;
	int timestamp = time(NULL);

	while (current != NULL) {
		/* we want to suppress first element if it is too old */
		if (timestamp - current->timestamp > packet_timeout) {
			IPQ_SET_VERDICT(current->id, NF_DROP);
			debug_log_printf(DEBUG_AREA_PACKET,
					 DEBUG_LEVEL_DEBUG, "Dropped: %lu",
					 current->id);
			psuppress(previous, current);
			current = packets_list.start;
			previous = NULL;
		} else {
			current = NULL;
		}
	}
}


/*
 * Copy taken from hping2 project, original comment was:
 * "from R. Stevens's Network Programming"
 */
__u16 icmp_cksum(__u16 * buf, int nbytes)
{
	__u32 sum;
	__u16 oddbyte;

	sum = 0;
	while (nbytes > 1) {
		sum += *buf++;
		nbytes -= 2;
	}

	if (nbytes == 1) {
		oddbyte = 0;
		*((__u16 *) & oddbyte) = *(__u16 *) buf;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return (__u16) ~ sum;
}

int send_icmp_ipv4_unreach(char *payload)
{
	struct sockaddr_in to;
	char buffer[sizeof(struct icmphdr) + 20 + 8];
	struct iphdr *ip = (struct iphdr *) payload;
	struct icmphdr *icmp = (struct icmphdr *) buffer;

	/* write ICMP header */
	icmp->type = 3;
	icmp->code = 0;
	icmp->checksum = 0x0000;
	icmp->un.frag.__unused = 0;
	icmp->un.frag.mtu = 0;

	/* copy old packet header */
	memcpy(buffer + sizeof(struct icmphdr), payload, 20 + 8);

	/* get destination IPv4 address */
	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = ip->saddr;

	/* compute icmp checksum */
	icmp->checksum = icmp_cksum((__u16 *) buffer, sizeof(buffer));

	/* send packet */
	return sendto(raw_sock4, buffer, sizeof(buffer), 0,
		      (struct sockaddr *) &to, sizeof(to));
}

int send_icmp_ipv6_unreach(char *payload)
{
	struct sockaddr_in6 to;
	char buffer[sizeof(struct icmp6_hdr) + 40 + 8];
	struct ip6_hdr *ip = (struct ip6_hdr *) payload;
	struct icmp6_hdr *icmp = (struct icmp6_hdr *) buffer;

	/* write ICMP header */
	memset(icmp, 0, sizeof(*icmp));
	icmp->icmp6_type = 1;
	icmp->icmp6_code = 0;
	/* checksum and data are nul */

	/* copy old packet header */
	memcpy(buffer + sizeof(*icmp), payload, 40 + 8);

	/* get destination IPv6 address */
	memset(&to, 0, sizeof(to));
	to.sin6_family = AF_INET6;
	to.sin6_addr = ip->ip6_src;

#ifdef LINUX
	/* don't compute icmp checksum, Linux do it for us */
#else
#  error "You may compute the checksum!"
#endif

	if (raw_sock6 > 0) {
		/* send packet */
		return sendto(raw_sock6, buffer, sizeof(buffer), 0,
			      (struct sockaddr *) &to, sizeof(to));
	} else {
		return 0;
	}
}

int send_icmp_unreach(char *payload)
{
	struct iphdr *ip4 = (struct iphdr *) payload;
	if (ip4->version == AF_INET) {
		return send_icmp_ipv4_unreach(payload);
	} else {
		return send_icmp_ipv6_unreach(payload);
	}
}

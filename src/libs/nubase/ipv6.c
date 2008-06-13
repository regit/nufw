/*
 ** Copyright(C) 2007 INL
 ** Written by Victor Stinner <victor.stinner@inl.fr>
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

#include <ipv6.h>
#include <string.h>
#include <stdio.h> /* sscanf() */
#include <inttypes.h> /* SCNx32 */
#include <arpa/inet.h>
#include <sys/socket.h>
#include <security.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/** \defgroup Nubase Nubase Library
 * \brief This is a convenient library use in different part of NuFW.
 *
 * @{
 */

/**
 * \file ipv6.c
 * \brief IPv6 related function
 */

/**
 * Set IPv6 address to "empty" address ("::")
 */
void clear_ipv6(struct in6_addr *ipv6)
{
	memset(ipv6, 0, sizeof(*ipv6));
}

/**
 * Convert IPv4 address (as 32-bit unsigned integer) to IPv6 address:
 * add 96 bits prefix "::ffff:" to get IPv6 address "::ffff:a.b.c.d".
 */
void uint32_to_ipv6(const uint32_t ipv4, struct in6_addr *ipv6)
{
#ifdef LINUX
	ipv6->s6_addr32[0] = 0x00000000;
	ipv6->s6_addr32[1] = 0x00000000;
	ipv6->s6_addr32[2] = htonl(0xffff);
	ipv6->s6_addr32[3] = ipv4;
#else
	ipv6->__u6_addr.__u6_addr32[0] = 0x00000000;
	ipv6->__u6_addr.__u6_addr32[1] = 0x00000000;
	ipv6->__u6_addr.__u6_addr32[2] = htonl(0xffff);
	ipv6->__u6_addr.__u6_addr32[3] = ipv4;
#endif
}

/**
 * Convert IPv4 address (as in_addr struture) to IPv6 address:
 * add 96 bits prefix "::ffff:" to get IPv6 address "::ffff:a.b.c.d".
 */
void ipv4_to_ipv6(const struct in_addr ipv4, struct in6_addr *ipv6)
{
	uint32_to_ipv6(ipv4.s_addr, ipv6);
}

/**
 * Convert IPv6 address (as in6_addr struture) to IPv4 address (in_addr):
 * copy 32 bits address.
 */
void ipv6_to_ipv4(const struct in6_addr *ipv6, struct in_addr *ipv4)
{
#ifdef LINUX
	ipv4->s_addr = ntohl(ipv6->s6_addr32[3]);
#else
	ipv4->s_addr = ntohl(ipv6->__u6_addr.__u6_addr32[3]);
#endif
}

/**
 * Check if a IPv6 address is a IPv4 or not.
 *
 * \return 1 for IPv4 and 0 for IPv6
 */
int is_ipv4(const struct in6_addr *addr)
{
#ifdef LINUX
	if (ntohl(addr->s6_addr32[2]) != 0x0000ffff)
		return 0;
	if (addr->s6_addr32[0] != 0 || addr->s6_addr32[1] != 0)
		return 0;
#else
	if (ntohl(addr->__u6_addr.__u6_addr32[2]) != 0x0000ffff)
		return 0;
	if (addr->__u6_addr.__u6_addr32[0] != 0 || addr->__u6_addr.__u6_addr32[1] != 0)
		return 0;
#endif
	return 1;
}

/**
 * Format IPv6 address in specified string buffer.
 * Use IPv4 format ("192.168.0.1") for IPv4 in IPv6 address (::ffff:192.168.0.2).
 *
 * If protocol is not NULL, it will contains the address family:
 * AF_INET (IPv4) or AF_INET6 (IPv6).
 *
 * Returns new allocated string.
 */
void format_ipv6(const struct in6_addr *addr, char *buffer, size_t buflen, uint8_t *protocol)
{
	if (is_ipv4(addr)) {
		struct in_addr addr4;
#ifdef LINUX
		addr4.s_addr = addr->s6_addr32[3];
#else
		addr4.s_addr = addr->__u6_addr.__u6_addr32[3];
#endif
		if (protocol) *protocol = AF_INET;
		if (inet_ntop(AF_INET, &addr4, buffer, buflen) == NULL)
		{
			/* error */
			SECURE_STRNCPY(buffer, "<ipv4>", buflen);
		}
	} else {
		if (protocol) *protocol = AF_INET6;
		if (inet_ntop(AF_INET6, addr, buffer, buflen) == NULL)
		{
			/* error */
			SECURE_STRNCPY(buffer, "<ipv6>", buflen);
		}
	}
	/* always write nul byte at the end */
	if (0 < buflen) buffer[buflen-1] = 0;
}

/**
 * Get socket "name" (local address) as IPv6 address
 *
 * \return 0 on error, 1 on success
 */
int getsockname_ipv6(int fileno, struct in6_addr *addr)
{
	struct sockaddr_storage peer_storage;
	socklen_t peerlen = sizeof(peer_storage) ;
	int ret;

	ret = getsockname(fileno, (struct sockaddr*)&peer_storage, &peerlen);
	if (ret != 0 )
	{
		clear_ipv6(addr);
		return 0;
	}
	if (peer_storage.ss_family == AF_INET6)
	{
		struct sockaddr_in6 *peer6 = (struct sockaddr_in6 *)&peer_storage;
		*addr = peer6->sin6_addr;
		return 1;
	} else if (peer_storage.ss_family == AF_INET) {
		struct sockaddr_in *peer4 = (struct sockaddr_in *)&peer_storage;
		ipv4_to_ipv6(peer4->sin_addr, addr);
		return 1;
	} else {
		clear_ipv6(addr);
		return 0;
	}
}

/**
 * Convert an IPv6 address as hexadecimal without ":" separator (32 characters)
 * into in6_addr structure.
 *
 * \return Returns 0 on failure, or 1 on error.
 */
int hex2ipv6(const char *text, struct in6_addr *ip)
{
#ifdef LINUX
#  define READ(text, index) sscanf((text), "%08" SCNx32, (uint32_t *) &ip->s6_addr32[index])
#else
#  define READ(text, index) sscanf((text), "%08" SCNx32, (uint32_t *) &ip->__u6_addr.__u6_addr32[index])
#endif
	/* Copy text */
	char copy[33];
	if (strlen(text) != 32)
		return 0;
	SECURE_STRNCPY(copy, text, sizeof(copy));

	if (READ(copy + 8 * 3, 3) != 1)
		return 0;
	copy[8 * 3] = 0;

	if (READ(copy + 8 * 2, 2) != 1)
		return 0;
	copy[8 * 2] = 0;

	if (READ(copy + 8 * 1, 1) != 1)
		return 0;
	copy[8] = 0;

	if (READ(copy + 8 * 0, 0) != 1)
		return 0;
	return 1;
#undef READ
}

/**
 * Compare two IPv6 addresses.
 *
 * \return 1 on equality, 0 otherwise.
 */
int ipv6_equal(const struct in6_addr *ipa, const struct in6_addr *ipb)
{
	return memcmp(ipa, ipb, sizeof(struct in6_addr)) == 0;
}

/**
 * Compare addr1 with (addr2 & netmask)
 *
 * \return 0 if they match, integer different than zero otherwise (memcmp result)
 */
int compare_ipv6_with_mask(
	const struct in6_addr *addr1,
	const struct in6_addr *addr2,
	const struct in6_addr *mask)
{
	struct in6_addr masked = *addr2;
#ifdef LINUX
	masked.s6_addr32[0] &= mask->s6_addr32[0];
	masked.s6_addr32[1] &= mask->s6_addr32[1];
	masked.s6_addr32[2] &= mask->s6_addr32[2];
	masked.s6_addr32[3] &= mask->s6_addr32[3];
#else
	masked.__u6_addr.__u6_addr32[0] &= mask->__u6_addr.__u6_addr32[0];
	masked.__u6_addr.__u6_addr32[1] &= mask->__u6_addr.__u6_addr32[1];
	masked.__u6_addr.__u6_addr32[2] &= mask->__u6_addr.__u6_addr32[2];
	masked.__u6_addr.__u6_addr32[3] &= mask->__u6_addr.__u6_addr32[3];
#endif
	return memcmp(addr1, &masked, sizeof(struct in6_addr));
}

/**
 * Create an IPv6 netmask
 */
void create_ipv6_netmask(struct in6_addr *netmask, int mask)
{
	uint32_t *p_netmask;
	memset(netmask, 0, sizeof(struct in6_addr));
	if (mask < 0) {
		mask = 0;
	} else if (128 < mask) {
		mask = 128;
	}
#ifdef LINUX
	p_netmask = &netmask->s6_addr32[0];
#else
	p_netmask = &netmask->__u6_addr.__u6_addr32[0];
#endif
	while (32 < mask)
	{
		*p_netmask = 0xffffffff;
		p_netmask++;
		mask -= 32;
	}
	if (mask != 0) {
		*p_netmask = htonl(0xFFFFFFFF << (32 - mask));
	}
}

/** @} */

/*
 ** Copyright(C) 2007 INL
 ** Written by Victor Stinner <victor.stinner@inl.fr>
 **
 ** $Id$
 **
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

#include <auth_srv.h>
#include <arpa/inet.h>
#include <security.h>

/**
 * Convert IPv4 address (as 32-bit unsigned integer) to IPv6 address:
 * add 96 bits prefix "::ffff:" to get IPv6 address "::ffff:a.b.c.d".
 */
void uint32_to_ipv6(const uint32_t ipv4, struct in6_addr *ipv6)
{
	ipv6->s6_addr32[0] = 0x00000000;
	ipv6->s6_addr32[1] = 0x00000000;
	ipv6->s6_addr32[2] = 0xffff0000;
	ipv6->s6_addr32[3] = ipv4;
}

/**
 * Convert IPv4 address (as in_addr struture) to IPv6 address:
 * add 96 bits prefix "::ffff:" to get IPv6 address "::ffff:a.b.c.d".
 */
inline void ipv4_to_ipv6(const struct in_addr ipv4, struct in6_addr *ipv6)
{
	uint32_to_ipv6(ipv4.s_addr, ipv6);
}

/**
 * Check if a IPv6 address is a IPv4 or not.
 *
 * \return 1 for IPv4 and 0 for IPv6
 */
int is_ipv4(const struct in6_addr *addr)
{
	if (addr->s6_addr32[2] != 0xffff0000)
		return 0;
	if (addr->s6_addr32[0] != 0 || addr->s6_addr32[1] != 0)
		return 0;
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
		addr4.s_addr = addr->s6_addr32[3];
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
 * Convert IPv6 address to a string.
 * Use IPv4 format ("192.168.0.1") for IPv4 in IPv6 address (::ffff:192.168.0.2).
 *
 *
 * Returns new allocated string.
 */
char* ipv6_to_str(const struct in6_addr *addr)
{
	char buffer[INET6_ADDRSTRLEN];
	format_ipv6(addr, buffer, sizeof(buffer), NULL);
	return g_strdup(buffer);
}


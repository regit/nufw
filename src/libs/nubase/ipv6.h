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

#ifndef NUFW_IPV6_H
#define NUFW_IPV6_H

#ifdef FREEBSD
#  include <sys/types.h>
#  include <netinet/in_systm.h>
#endif

#include <netinet/in.h>

void clear_ipv6(struct in6_addr *ipv6);
void uint32_to_ipv6(const uint32_t ipv4, struct in6_addr *ipv6);
void ipv4_to_ipv6(const struct in_addr ipv4, struct in6_addr *ipv6);
void ipv6_to_ipv4(const struct in6_addr *ipv6, struct in_addr *ipv4);
int is_ipv4(const struct in6_addr *addr);
void format_ipv6(const struct in6_addr *addr, char *buffer, size_t buflen, uint8_t *protocol);
int getsockname_ipv6(int fileno, struct in6_addr *addr);
int hex2ipv6(const char *text, struct in6_addr *ip);
int ipv6_equal(const struct in6_addr *ipa, const struct in6_addr *ipb);
int compare_ipv6_with_mask(const struct in6_addr *addr1,
	const struct in6_addr *addr2, const struct in6_addr *mask);
void create_ipv6_netmask(struct in6_addr *netmask, int mask);

#endif


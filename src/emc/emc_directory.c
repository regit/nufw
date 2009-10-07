/*
 ** Copyright(C) 2009 INL
 ** Written by Pierre Chifflier <chifflier@inl.fr>
 **     INL : http://www.inl.fr/
 **
 ** All rights reserved.
 **
 */

#include <config.h>

#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif

#include <nussl.h>

#include <nubase.h>
#include <config-parser.h>

#include "emc_server.h"
#include "emc_config.h"

#include "emc_directory.h"
#include "emc_data_parser.h"

int emc_netmask_order_func (gconstpointer a, gconstpointer b)
{
	const struct emc_netmask_t *val1, *val2;

	val1 = (const struct emc_netmask_t *)a;
	val2 = (const struct emc_netmask_t *)b;

	if (val1->af_family < val2->af_family)
		return -1;
	if (val1->af_family > val2->af_family)
		return 1;

	if (val1->af_family == AF_INET) {
		u_int32_t u1, u2;

		u1 = val1->ip.u4;
		u2 = val2->ip.u4;

		if ( u1 < u2 )
			return -1;
		if ( u1 > u2 )
			return 1;
	} else {
		int i;
		u_int32_t u1, u2;

		for (i=0; i<4; i++) {
			u1 = val1->ip.u16[i];
			u2 = val2->ip.u16[i];

			if ( u1 < u2 )
				return -1;
			if ( u1 > u2 )
				return 1;
		}
	}

	return 0;
}

int emc_netmask_is_included(struct emc_netmask_t*netmask, const char *ip)
{
	struct addrinfo *res;
	struct addrinfo hints;
	int ecode;
	struct sockaddr_in6 *peer6;
	struct sockaddr_in  *peer4;
	int result = 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = PF_UNSPEC;

	ecode = getaddrinfo(ip, NULL,
			&hints, &res);
	if (ecode != 0) {
		log_printf(DEBUG_LEVEL_FATAL, "Invalid server address %s, error: %s",
		     ip,
		     gai_strerror(ecode));
		return 0;
	}

	if ( (res->ai_family != AF_INET) && (res->ai_family != AF_INET6) ) {
		log_printf(DEBUG_LEVEL_WARNING, "Invalid ai_family for address %s", ip);
		freeaddrinfo(res);
		return 0;
	}

	if (res->ai_family != netmask->af_family) {
		// networks do not have the same type (IPv4 vs IPv6), so
		// they can't match
		freeaddrinfo(res);
		return 0;
	}

	if ( res->ai_family == AF_INET ) {
		u_int32_t ipv4;
		peer4 = (struct sockaddr_in *)res->ai_addr;
		ipv4 = ntohl((u_int32_t)peer4->sin_addr.s_addr);

		//log_printf(DEBUG_LEVEL_DEBUG, "Comparing ip %x vs netmask %x/%d (mask %x)", ipv4, netmask->ip.u4, netmask->length, netmask->mask.u4);

		result = ( (ipv4 & netmask->mask.u4) == netmask->ip.u4);
	}
	else if ( res->ai_family == AF_INET6 ) {
		peer6 = (struct sockaddr_in6 *)res->ai_addr;
		//memcpy(&netmask->u.u16, peer6->sin6_addr.s6_addr, sizeof(netmask->u.u16));
		//for (i=0; i<4; i++) {
		//	netmask->u.u16[i] = ntohl( netmask->u.u16[i] );
		//}
	}

	freeaddrinfo(res);

	return result;
}


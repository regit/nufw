/*
 ** Copyright(C) 2009 INL
 ** Written by Pierre Chifflier <chifflier@inl.fr>
 **     INL : http://www.inl.fr/
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

static struct emc_netmask_t * _convert_str_to_netmask(char *mask, unsigned int masklen)
{
	struct addrinfo *res;
	struct addrinfo hints;
	int ecode;
	struct sockaddr_in6 *peer6;
	struct sockaddr_in  *peer4;
	struct emc_netmask_t *netmask = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = PF_UNSPEC;

	ecode = getaddrinfo(mask, NULL,
			&hints, &res);
	if (ecode != 0) {
		log_printf(DEBUG_LEVEL_FATAL, "Invalid server listening address %s:%d, error: %s",
		     mask, 0,
		     gai_strerror(ecode));
		return NULL;
	}

	if ( (res->ai_family != AF_INET) && (res->ai_family != AF_INET6) ) {
		log_printf(DEBUG_LEVEL_WARNING, "Invalid ai_family for address %s", mask);
		freeaddrinfo(res);
		return NULL;
	}

	netmask = malloc(sizeof(struct emc_netmask_t));
	netmask->af_family = res->ai_family;

	if ( res->ai_family == AF_INET ) {
		peer4 = (struct sockaddr_in *)res->ai_addr;
		netmask->ip.u4 = ntohl((u_int32_t)peer4->sin_addr.s_addr);
		netmask->mask.u4 = (0xffffffff << (32-masklen));
	}
	else if ( res->ai_family == AF_INET6 ) {
		int i;
		peer6 = (struct sockaddr_in6 *)res->ai_addr;
		memcpy(&netmask->ip.u16, peer6->sin6_addr.s6_addr, sizeof(netmask->ip.u16));
		for (i=0; i<4; i++) {
			netmask->ip.u16[i] = ntohl( netmask->ip.u16[i] );
		}
	}

	netmask->length = (u_int16_t)masklen;

	freeaddrinfo(res);

	return netmask;
}

static int _extract_ip_mask(char *str, char **mask, unsigned int *masklen)
{
	char *ptr;
	char *errptr;
	unsigned long ul;
	unsigned int af_family = AF_INET;

	if (str[0] == '[') {
		af_family = AF_INET6;
	}

	if (af_family == AF_INET) {
		/* IPv4 */
		ptr = strchr(str, '/');
		if (ptr == NULL) {
			log_printf(DEBUG_LEVEL_CRITICAL, "ERROR Invalid line format (missing /)");
			return -1;
		}
		*ptr++ = '\0';
	}
	else if (af_family == AF_INET6) {
		/* IPv6 */
		*str++ = '\0';
		ptr = strchr(str, ']');
		if (ptr == NULL) {
			log_printf(DEBUG_LEVEL_CRITICAL, "ERROR Invalid line format (missing ])");
			return -1;
		}
		*ptr++ = '\0';
		if (*ptr != '/') {
			log_printf(DEBUG_LEVEL_CRITICAL, "ERROR Invalid line format (missing /)");
			return -1;
		}
		*ptr++ = '\0';
	}

	*mask = str;

	ul = strtoul(ptr, &errptr, 10);
	if (errptr != NULL && errptr[0] != '\0') {
		log_printf(DEBUG_LEVEL_CRITICAL, "ERROR Invalid mask format (should be an integer)");
		return -1;
	}

	*masklen = (u_int16_t)ul;

	return 0;
}

static struct emc_netmask_t * _emc_parse_line(const char *line)
{
	char **fields;
	int ret;
	char *mask = NULL;
	unsigned int masklen;
	struct emc_netmask_t *netmask = NULL;

	/* split line and extract fields */
	fields = g_strsplit_set(line, " \r\n", 3);

	if (fields[0] != NULL) {
		ret = _extract_ip_mask(fields[0], &mask, &masklen);
		if (ret == 0)
			netmask = _convert_str_to_netmask(mask, masklen);
			netmask->nuauth_server = strdup(fields[1]);
	}

	g_strfreev(fields);

	return netmask;
}

int emc_parse_datafile(struct emc_server_context *ctx, const char *file)
{
	FILE *fp;
	char buf[1024];
	struct emc_netmask_t *netmask = NULL;

	fp = fopen(file, "r+");
	if (fp == NULL) {
		log_printf(DEBUG_LEVEL_CRITICAL, "ERROR Could not open EMC data file");
		return 0;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		netmask = _emc_parse_line(buf);
		if (netmask == NULL) {
			log_printf(DEBUG_LEVEL_CRITICAL, "ERROR invalid line is:\n%s", buf);
			continue;
		}
		g_tree_insert(ctx->nuauth_directory, netmask, netmask);
	}

	fclose(fp);

	return 0;
}

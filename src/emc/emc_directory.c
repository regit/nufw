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

		u1 = val1->u.u4;
		u2 = val2->u.u4;

		if ( u1 < u2 )
			return -1;
		if ( u1 > u2 )
			return 1;
	} else {
		int i;
		u_int32_t u1, u2;

		for (i=0; i<4; i++) {
			u1 = val1->u.u16[i];
			u2 = val2->u.u16[i];

			if ( u1 < u2 )
				return -1;
			if ( u1 > u2 )
				return 1;
		}
	}

	return 0;
}


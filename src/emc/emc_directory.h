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

#ifndef __EMC_DIRECTORY_H__
#define __EMC_DIRECTORY_H__

/** \brief Structure for netmask
 */
struct emc_netmask_t {
	u_int16_t af_family;

	union {
		u_int32_t u4;
		u_int32_t u16[4];
	} ip;

	union {
		u_int32_t u4;
		u_int32_t u16[4];
	} mask;

	u_int16_t length;

	char *nuauth_server;
};

int emc_netmask_order_func (gconstpointer a, gconstpointer b);

int emc_netmask_is_included(struct emc_netmask_t*netmask, const char *ip);

#endif /* __EMC_DIRECTORY_H__ */

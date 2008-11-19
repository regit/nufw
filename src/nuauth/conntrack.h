/*
 ** Copyright(C) 2005 INL
 ** Written by Eric Leblond <regit@inl.fr>
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

#ifndef CONNTRACK_H
#define CONNTRACK_H


struct limited_connection {
	struct in6_addr gwaddr;
	time_t expire; /**< expiration time of connection */
	tracking_t tracking;
};

struct accounted_connection {
	tracking_t tracking;
	time_t timestamp;
	/* counters fields */
	u_int64_t packets_in;
	u_int64_t bytes_in;
	u_int64_t packets_out;
	u_int64_t bytes_out;
};

void *limited_connection_handler(GMutex * mutex);

nu_error_t send_conntrack_message(struct limited_connection *lconn,
				  unsigned char msgtype);


#endif				/* CONNTRACK_H */

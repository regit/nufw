/*
 ** Copyright(C) 2007 INL
 ** Written by  Eric Leblond <regit@inl.fr>
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
 **
 */

#ifndef NUFW_SERVERS_H
#define NUFW_SERVERS_H

struct nufw_message_t {
	char *msg;
	int length;
};

void init_nufw_servers();

nu_error_t add_nufw_server(int conn_fd, nufw_session_t * nu_session);

nufw_session_t *get_nufw_session();
nufw_session_t * acquire_nufw_session_by_addr(struct  in6_addr * addr);
nufw_session_t * acquire_nufw_session_by_socket(int c);

nu_error_t increase_nufw_session_usage(nufw_session_t * session);

nu_error_t nufw_session_send(nufw_session_t * session,
			     char* buffer,
			     int length);

void release_nufw_session(nufw_session_t * session);

nu_error_t declare_dead_nufw_session(nufw_session_t * session);

void clean_nufw_session(nufw_session_t * c_session);

void close_nufw_servers();

void foreach_nufw_server(GHFunc callback, void *data);

#endif

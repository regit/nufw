/*
 ** Copyright(C) 2005-2007 INL
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

#ifndef CLIENT_MNGR_H
#define CLIENT_MNGR_H

/**
 * \addtogroup NuauthCore
 * @{
 */

void init_client_struct();

void add_client(int socket, gpointer datas);

nu_error_t delete_client_by_socket(int c);
nu_error_t delete_locked_client_by_socket(int socket);
nu_error_t delete_rw_locked_client(user_session_t *c_session);
void unlock_client_datas();
void lock_client_datas();

user_session_t *get_client_datas_by_socket(int c);

GSList *get_client_sockets_by_ip(struct in6_addr *ip);

user_session_t *look_for_username(const gchar * username);

gboolean test_username_count_vs_max(const gchar * username, int maxcount);

void log_clean_session(user_session_t *);
void clean_session(user_session_t *);

void foreach_session(GHFunc callback, void *data);

struct msg_addr_set {
	struct in6_addr addr;
	struct nu_srv_message *msg;
	gboolean found;
};

typedef gboolean user_session_check_t(user_session_t * session, gpointer data);

char warn_clients(struct msg_addr_set *global_msg, user_session_check_t *scheck,
		  gpointer data);

gboolean check_property_clients(struct in6_addr *addr, user_session_check_t *scheck, int mode, gpointer data);

void clean_client_session_bycallback(GHRFunc cb, gpointer data);

void close_clients();

nu_error_t kill_all_clients();
void kill_expired_clients_session();
nu_error_t activate_client_by_socket(int socket);

guint get_number_of_clients();

struct username_counter {
	const char* name;
	int max;
	int counter;
};


/** @} */

#endif

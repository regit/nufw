/*
 ** Copyright(C) 2005 Eric Leblond <regit@inl.fr>
 **                  INL http://www.inl.fr/
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

#ifndef USERS_H
#define USERS_H

int init_user_cache();

void free_user_cache(gpointer datas);
void free_user_struct(gpointer datas,gpointer uda);
void get_users_from_cache (connection_t* conn_elt);
gpointer user_duplicate_key(gpointer datas);

struct user_cached_datas {
    uint32_t uid;
    GSList * groups;
};

/**
 * stores all information relative to a TLS user session
 * so we don't have to get this information at each packet
 */
typedef struct User_session {
    uint32_t addr;
    gnutls_session* tls;
    GMutex* tls_lock;
    char * user_name;
    uint32_t user_id;
    GSList * groups;
    gchar * sysname;
    gchar * release;
    gchar * version;
    struct timeval last_req;
    gboolean req_needed;
    gboolean multiusers;
    time_t expire; /**< set to -1 to have unlimited session */
} user_session;

#endif


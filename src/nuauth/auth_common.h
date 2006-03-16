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

#ifndef AUTH_COMMON_H
#define AUTH_COMMON_H

typedef enum {
  PACKET_ALONE=0,
  PACKET_IN_HASH
} packet_place_t;

void* search_and_fill (GMutex *mutex);

gboolean compare_connection(gconstpointer conn1, gconstpointer conn2);
int sck_auth_reply;
void send_auth_response(gpointer data, gpointer userdata);
int conn_cl_delete(gconstpointer conn);
inline char get_state(connection_t *elt);
gint take_decision(connection_t * element, packet_place_t place);
gint print_connection(gpointer data,gpointer userdata);
void free_connection_list(GSList *list);
connection_t* duplicate_connection(connection_t* element);
void free_connection(connection_t * conn);
int lock_and_free_connection(connection_t * conn);
void clean_connections_list ();
guint hash_connection(gconstpointer conn_p);
void decisions_queue_work (gpointer userdata, gpointer data);

char * get_rid_of_domain(const char* user);

gboolean  get_old_conn (gpointer key,
		gpointer value,
		gpointer user_data);


gboolean secure_snprintf(char *buffer, unsigned int buffer_size, char *format, ...);


/**
 * internal for send_auth_response. */

struct auth_answer {
  uint8_t answer;
  uint32_t user_id;
  int socket;
  nufw_session_t* tls;
};

void free_buffer_read(struct tls_buffer_read* datas);

/*
 * Keep connection in a hash
 */

/** hash table containing the connections. */
GHashTable * conn_list;
/** global lock for the conn list. */
GStaticMutex insert_mutex;

#ifdef PERF_DISPLAY_ENABLE
int timeval_substract (struct timeval *result,struct timeval *x,struct timeval *y);
#endif

#endif

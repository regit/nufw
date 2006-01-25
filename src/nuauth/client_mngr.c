/*
 ** Copyright(C) 2005 INL
 ** written by  Eric Leblond <regit@inl.fr>
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
 **
 ** In addition, as a special exception, the copyright holders give
 ** permission to link the code of portions of this program with the
 ** Cyrus SASL library under certain conditions as described in each
 ** individual source file, and distribute linked combinations
 ** including the two.
 ** You must obey the GNU General Public License in all respects
 ** for all of the code used other than Cyrus SASL.  If you modify
 ** file(s) with this exception, you may extend this exception to your
 ** version of the file(s), but you are not obligated to do so.  If you
 ** do not wish to do so, delete this exception statement from your
 ** version.  If you delete this exception statement from all source
 ** files in the program, then also delete it here.
 **
 ** This product includes software developed by Computing Services
 ** at Carnegie Mellon University (http://www.cmu.edu/computing/).
 **
 */

#include <auth_srv.h>


/* Client structure */
GHashTable* client_conn_hash;
GHashTable* client_ip_hash;

void clean_session(user_session * c_session)
{
	if (c_session->tls)
	{
		gnutls_deinit(
				*(c_session->tls)	
			     );
		g_free(c_session->tls);
	}
	if (c_session->userid){
		g_free(c_session->userid);
	}
	if (c_session->groups){
		g_slist_free(c_session->groups);
	}

	if (c_session){
		g_free(c_session); 
	}
}

static void hash_clean_session(user_session * c_session){
	gnutls_transport_ptr socket_tls;

	socket_tls=gnutls_transport_get_ptr(*(c_session->tls));
	if (socket_tls){
		shutdown((int)socket_tls,SHUT_RDWR); 
	}
	clean_session(c_session);
}


void init_client_struct(){
	/* build client hash */
	client_conn_hash = g_hash_table_new_full(
			NULL,
			NULL,
			NULL,
			(GDestroyNotify) hash_clean_session
			);

	/* build client hash */
	client_ip_hash = g_hash_table_new(
			NULL,
			NULL	
			);

}

void add_client(int socket, gpointer datas)
{
	user_session * c_session=(user_session *) datas;
	GSList * ipsockets;
	g_hash_table_insert(client_conn_hash,GINT_TO_POINTER(socket),datas);
	/* need to create entry in ip hash */
	ipsockets = g_hash_table_lookup(client_ip_hash,GINT_TO_POINTER(c_session->addr));
	ipsockets = g_slist_prepend(ipsockets,c_session->tls);
	g_hash_table_replace (client_ip_hash, GINT_TO_POINTER(c_session->addr), ipsockets);
}

char delete_client_by_socket(int c)
{
	GSList * ipsockets;
	user_session * session; 
	/* get addr of of client 
	 *  get element
	 *  get addr field
	 */
	session = (user_session*)( 
			g_hash_table_lookup(client_conn_hash ,GINT_TO_POINTER(c)));

	/* walk on IP based struct to find the socket */
	ipsockets = g_hash_table_lookup(client_ip_hash ,GINT_TO_POINTER(session->addr));
	/* destroy entry */
	ipsockets = g_slist_remove(ipsockets , session->tls);
	/* update hash */
	g_hash_table_replace (client_ip_hash, GINT_TO_POINTER(session->addr), ipsockets);
	/* remove entry from hash */
	g_hash_table_remove(client_conn_hash,GINT_TO_POINTER(c));
	return 0;
}

inline user_session * get_client_datas_by_socket(int c)
{
	return g_hash_table_lookup(client_conn_hash ,GINT_TO_POINTER(c));
}

inline GSList * get_client_sockets_by_ip(uint32_t ip)
{
	return g_hash_table_lookup(client_ip_hash ,GINT_TO_POINTER(ip));
}

static gboolean look_for_username_callback (gpointer key,
                                             gpointer value,
                                             gpointer user_data)
{
	if(! strcmp(
				((user_session*)value)->userid,
			user_data)){
		return TRUE;
	} else {
		return FALSE;
	}
}

inline user_session* look_for_username(const gchar* username)
{
	return	g_hash_table_find(client_conn_hash,look_for_username_callback,(void*)username);
}

char warn_clients(struct msg_addr_set * global_msg) 
{
	GSList* ipsockets=NULL;
#if DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER)){
		struct in_addr saddress;
		saddress.s_addr=htonl(global_msg->addr);
		g_message("need to warn client on %s",inet_ntoa(saddress));
	}
#endif
	ipsockets=g_hash_table_lookup(client_ip_hash,GINT_TO_POINTER(ntohl(global_msg->addr)));
	if (ipsockets) {
		global_msg->found=TRUE;
		while (ipsockets) {
			gnutls_record_send(*(gnutls_session*)(ipsockets->data),
					global_msg->msg,
					ntohs(global_msg->msg->length)
					);
			ipsockets=ipsockets->next;
		}
		return 1;
	} else 
		return 0;
}

void close_clients(int signal)
{
	g_hash_table_destroy(client_conn_hash);
}

gboolean   is_expired_client (gpointer key,
                             gpointer value,
                             gpointer user_data)
{
        if ( ((user_session*)value)->expire < *((time_t*)user_data) ){
                return TRUE;
        } else {
                return FALSE;
        }
}

void kill_expired_clients_session()
{
        time_t current_time=time(NULL);
        g_hash_table_foreach_remove (
                        client_conn_hash,
                        is_expired_client,
                        &current_time
                        );
}

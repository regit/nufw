/*
 ** Copyright(C) 2005-2006 INL
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
#include <jhash.h>

/** global lock for client hash. */
GMutex* client_mutex;
/** Client structure */
GHashTable* client_conn_hash;
GHashTable* client_ip_hash;

static uint32_t hash_ipv6(struct in6_addr *addr)
{
    return jhash2(addr->s6_addr32, sizeof(*addr)/4, 0);
}

#define IPV6_TO_POINTER(addr) GUINT_TO_POINTER(hash_ipv6(addr))

void clean_session(user_session_t * c_session)
{
    if (c_session->tls){
        gnutls_deinit(*(c_session->tls));
        g_free(c_session->tls);
    }
    g_free(c_session->user_name);
    g_slist_free(c_session->groups);

    g_free(c_session->sysname);
    g_free(c_session->release);
    g_free(c_session->version);

    g_mutex_free(c_session->tls_lock);

    if (c_session){
        g_free(c_session); 
    }
}

static void hash_clean_session(user_session_t * c_session)
{
    int socket = (int)gnutls_transport_get_ptr(*c_session->tls);
    clean_session(c_session);
    shutdown(socket, SHUT_RDWR); 
    close(socket); 
}


void init_client_struct()
{
    /* build client hash */
    client_conn_hash = g_hash_table_new_full(NULL, NULL, NULL,
            (GDestroyNotify)hash_clean_session);

    /* build client hash */
    client_ip_hash = g_hash_table_new(NULL, NULL);
    client_mutex = g_mutex_new();
}

void add_client(int socket, gpointer datas)
{
    user_session_t * c_session = (user_session_t *) datas;
    GSList * ipsockets;

    g_mutex_lock (client_mutex);

    g_hash_table_insert(client_conn_hash,GINT_TO_POINTER(socket),datas);
    /* need to create entry in ip hash */
    ipsockets = g_hash_table_lookup(client_ip_hash, IPV6_TO_POINTER(&c_session->addr));
    ipsockets = g_slist_prepend(ipsockets,c_session->tls);

    g_hash_table_replace (client_ip_hash, IPV6_TO_POINTER(&c_session->addr), ipsockets);

    g_mutex_unlock (client_mutex);
}

void delete_client_by_socket(int socket)
{
    GSList * ipsockets;
    user_session_t * session; 

    g_mutex_lock(client_mutex);

    /* get addr of of client 
     *  get element
     *  get addr field
     */
    session = (user_session_t*)(g_hash_table_lookup(client_conn_hash ,GINT_TO_POINTER(socket)));
    if (session) {
        /* walk on IP based struct to find the socket */
        ipsockets = g_hash_table_lookup(client_ip_hash, IPV6_TO_POINTER(&session->addr));
        /* destroy entry */
        ipsockets = g_slist_remove(ipsockets , session->tls);
        /* update hash */
        g_hash_table_replace (client_ip_hash, IPV6_TO_POINTER(&session->addr), ipsockets);
        /* remove entry from hash */
        g_hash_table_remove(client_conn_hash,GINT_TO_POINTER(socket));
    } else {
        log_message(WARNING,AREA_USER,"Could not found user session in hash");
    }

    g_mutex_unlock(client_mutex);
}

inline user_session_t * get_client_datas_by_socket(int socket)
{
    void * ret;

    g_mutex_lock(client_mutex);
    ret = g_hash_table_lookup(client_conn_hash ,GINT_TO_POINTER(socket));
    g_mutex_unlock(client_mutex);
    return ret;
}

inline GSList* get_client_sockets_by_ip(struct in6_addr *ip)
{
    void * ret;

    g_mutex_lock(client_mutex);
    ret = g_hash_table_lookup(client_ip_hash ,IPV6_TO_POINTER(ip));
    g_mutex_unlock(client_mutex);
    return ret;
}

inline guint get_number_of_clients()
{
    return g_hash_table_size(client_conn_hash);
}

static gboolean look_for_username_callback (gpointer key,
        gpointer value, gpointer user_data)
{
    if(strcmp(((user_session_t*)value)->user_name, user_data) != 0)
    {
        return TRUE;
    } else {
        return FALSE;
    }
}

inline user_session_t* look_for_username(const gchar* username)
{
    void * ret;
    g_mutex_lock(client_mutex);
    ret = g_hash_table_find(client_conn_hash,look_for_username_callback,(void*)username);
    g_mutex_unlock(client_mutex);
    return ret;
}

char warn_clients(struct msg_addr_set * global_msg) 
{
    GSList* ipsockets=NULL;
#if DEBUG_ENABLE
    char addr_ascii[INET6_ADDRSTRLEN];

    if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER)
        /* @@@HAYPO@@@ check endian */
        && inet_ntop(AF_INET6, &global_msg->addr, addr_ascii, sizeof(addr_ascii)) != NULL)
    {
        g_message("Warn client(s) on IP %s", addr_ascii);
    }
#endif

    g_mutex_lock(client_mutex);
    ipsockets=g_hash_table_lookup(client_ip_hash, IPV6_TO_POINTER(&global_msg->addr));
    if (ipsockets) {
        global_msg->found=TRUE;
        while (ipsockets) {
            int ret = gnutls_record_send(*(gnutls_session*)(ipsockets->data),
                    global_msg->msg,
                    ntohs(global_msg->msg->length));
            if (ret < 0)
                log_message(WARNING,AREA_USER,
                        "Fails to send warning to client(s).");
            ipsockets=ipsockets->next;
        }
        g_mutex_unlock(client_mutex);
        return 1;
    } else {
        g_mutex_unlock(client_mutex);
        return 0;
    }
}

void close_clients(int signal)
{
    g_hash_table_destroy(client_conn_hash);
}

gboolean   is_expired_client (gpointer key,
        gpointer value,
        gpointer user_data)
{
    if ( ((user_session_t*)value)->expire < *((time_t*)user_data) ){
        return TRUE;
    } else {
        return FALSE;
    }
}

void kill_expired_clients_session()
{
    time_t current_time=time(NULL);
    g_hash_table_foreach_remove (
            client_conn_hash, is_expired_client, &current_time);
}

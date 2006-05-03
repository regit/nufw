/*
 ** Copyright(C) 2005 INL
 **             written by Eric Leblond <regit@inl.fr>
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

#include "auth_srv.h"

/** \ingroup Nuauth
 *  \defgroup NuauthConntrack Fixed timeout connections handling
 *  @{
 */

/** 
 * \file nuauth/conntrack.c
 * \brief Conntrack handling (used for fixed timeout)
 */

static gboolean get_nufw_server_by_addr(gpointer key,gpointer value,gpointer user_data)
{
    if ( (((nufw_session_t*)value)->peername).s_addr 
            == 
            ((struct in_addr*)user_data)->s_addr ){
        return TRUE;
    } else {
        return FALSE;
    }
}

static void send_conntrack_message(struct limited_connection * lconn,unsigned char msgtype)
{
    nufw_session_t* session=NULL;

    debug_log_message(VERBOSE_DEBUG, AREA_GW, "going to send conntrack message");
    g_mutex_lock(nufw_servers_mutex);
    if (nufw_servers){
        session = g_hash_table_find (nufw_servers,
                get_nufw_server_by_addr,
                &(lconn->gwaddr));
        g_mutex_unlock(nufw_servers_mutex);
        if (session){
            struct nu_conntrack_message_t message;
            /* send message */
            message.protocol_version = PROTO_VERSION;
            message.msg_type = msgtype;
            if (lconn->expire != -1) {
                message.timeout = htonl(lconn->expire - time(NULL));
            } else {
                debug_log_message(WARNING, AREA_PACKET, "not modifying fixed timeout");
                message.timeout = 0;
            }
            message.ipv4_protocol = lconn->tracking.protocol;
            message.ipv4_src = htonl(lconn->tracking.saddr);
            message.ipv4_dst = htonl(lconn->tracking.daddr);
            if (message.ipv4_protocol == IPPROTO_ICMP){
                message.src_port = lconn->tracking.type;
                message.dest_port = lconn->tracking.code;
            } else {
                message.src_port = htons(lconn->tracking.source);
                message.dest_port = htons(lconn->tracking.dest);
            }
            g_mutex_lock(session->tls_lock);
            gnutls_record_send( *(session->tls) , &message, sizeof(message));
            g_mutex_unlock(session->tls_lock);
        } else {
            log_message(WARNING, AREA_GW, "correct session not found among nufw servers");
        }
    } else {
        g_mutex_unlock(nufw_servers_mutex);
    }
}

void  send_destroy_message_and_free(gpointer user_data)
{
    struct limited_connection* data=(struct limited_connection*)user_data;
    debug_log_message(VERBOSE_DEBUG, AREA_USER, "connection will be destroyed");
    /* look for corresponding nufw tls session */
    send_conntrack_message(data,AUTH_CONN_DESTROY);
    /* free */
    g_free(data);
}

/** 
 * get old entry
 */

static gboolean get_old_entry(gpointer key,gpointer value,gpointer user_data)
{
    if (((struct limited_connection *)value)->expire < GPOINTER_TO_INT(user_data)){
        debug_log_message(VERBOSE_DEBUG, AREA_USER, "found connection to be destroyed");
        return TRUE;
    } else {
        return FALSE;
    }
}

/** 
 * search and destroy expired connections 
 */

void destroy_expired_connection(GHashTable* lim_conn_list)
{

    g_hash_table_foreach_remove     (lim_conn_list,
            get_old_entry,
            GUINT_TO_POINTER(time(NULL)));
}



/**
 * Thread waiting for message
 *
 * Only thread to be able to access to list of connections to expire.
 */
void* limited_connection_handler(GMutex *mutex)
{
    GHashTable* lim_conn_list;
    struct internal_message *message=NULL;
    struct limited_connection* elt;
    GTimeVal tv;

    nuauthdatas->limited_connections_queue = g_async_queue_new();
    /* initialize packets list */
    lim_conn_list = g_hash_table_new_full ((GHashFunc)hash_connection,
            compare_connection,
            NULL,
            (GDestroyNotify) send_destroy_message_and_free); 
    g_async_queue_ref (nuauthdatas->limited_connections_queue);

    while (g_mutex_trylock(mutex)) 
    {
        g_mutex_unlock(mutex);

        /* wait for message */
        g_get_current_time (&tv);
        g_time_val_add(&tv, 1000);
        message = g_async_queue_timed_pop(nuauthdatas->limited_connections_queue, &tv);
        if (message == NULL)
            continue;

        switch (message->type) {
            case INSERT_MESSAGE:
                g_hash_table_insert(lim_conn_list,&(((struct limited_connection*)message->datas)->tracking),message->datas);
                break;

            case REFRESH_MESSAGE:
                destroy_expired_connection(lim_conn_list);
                break;

            case FREE_MESSAGE:
                elt = (struct limited_connection*)g_hash_table_lookup(lim_conn_list,message->datas);
                if (elt){
                    elt->expire=0;
                    g_hash_table_remove(lim_conn_list,message->datas);
                } 
#ifdef DEBUG_ENABLE
                else {
                    log_message(VERBOSE_DEBUG, AREA_USER, "connection not found can not be destroyed");
                }
#endif
                g_free(message->datas);
                break;

            case UPDATE_MESSAGE:
                /** here we get message from nufw kernel connection is ASSURED 
                 * we have to limit it if needed and log the state change if needed */
                debug_log_message(VERBOSE_DEBUG, AREA_GW, "received update message for a conntrack entry");
                elt = (struct limited_connection*)g_hash_table_lookup(lim_conn_list,message->datas);
                if (elt == NULL){
                    debug_log_message(VERBOSE_DEBUG, AREA_GW, "Can't find conntrack entry to update");
                } else {
                    send_conntrack_message(elt,AUTH_CONN_UPDATE);
                    /* this has to be removed from hash */
                    g_hash_table_steal(lim_conn_list,message->datas);
                    g_free(elt);
                }
                break;

            default:
                break;
        }
        g_free(message);
    }
    g_async_queue_unref (nuauthdatas->limited_connections_queue);
    g_hash_table_destroy(lim_conn_list); 
    return NULL;
}

/** @} */

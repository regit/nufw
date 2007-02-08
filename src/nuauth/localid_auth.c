/*
 ** Copyright(C) 2005 Eric Leblond <regit@inl.fr>
 **                  INL : http://www.inl.fr/
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


#include <auth_srv.h>

/** \ingroup Nuauth
 * \defgroup NuauthHello Hello Authentication
 * @{
 */

char localid_authenticated_protocol(int protocol)
{
    if (protocol != IPPROTO_TCP){
        return TRUE;
    }
    return FALSE;
}

/**
 * Insert a packet in localid hash table:
 *    - Connection state #AUTH_STATE_AUTHREQ: Generate an unique identifier,
 *      add the connection to the hash table, and then call warn_clients()
 *    - State #AUTH_STATE_USERPCKT: Add connection to acl_checkers queue (see
 *      acl_check_and_decide())
 */
void localid_insert_message(connection_t *pckt,
        GHashTable *localid_auth_hash,
        struct msg_addr_set *global_msg)
{
    connection_t *element = NULL;
    u_int32_t randomid;

    switch (pckt->state){
        case AUTH_STATE_AUTHREQ:
            /* add in struct */

            /* generete an unique identifier (32 bits) */
            randomid = random();
            while(g_hash_table_lookup(localid_auth_hash,GINT_TO_POINTER(randomid))){
                randomid++;
            }
            /* send message to clients */
            ((struct nu_srv_helloreq*)global_msg->msg)->helloid = randomid;
            global_msg->addr = pckt->tracking.saddr;
            global_msg->found = FALSE;
            /* if return is 1 we have somebody connected */
            if (warn_clients(global_msg)){
                /* add element to hash with computed key */
                g_hash_table_insert(localid_auth_hash,GINT_TO_POINTER(randomid),pckt);
            } else {
                free_connection(pckt);
            }
            break;
        case AUTH_STATE_USERPCKT:
            /* search in struct */
            element = (connection_t*) g_hash_table_lookup (localid_auth_hash,(GSList*)(pckt->packet_id)->data);
            /* if found ask for completion */
            if (element){
                /* TODO : do a check on saddr */
                if (memcmp(&element->tracking.saddr, &pckt->tracking.saddr, sizeof(pckt->tracking.saddr)) == 0)
                {
                    element->state=AUTH_STATE_HELLOMODE;
                    element->user_id=pckt->user_id;
                    element->mark=pckt->mark;
                    element->username=pckt->username;
                    element->user_groups=pckt->user_groups;
                    pckt->user_groups = NULL;
                    /* do asynchronous call to acl check */
                    g_thread_pool_push (nuauthdatas->acl_checkers, element, NULL);
                    /* remove element from hash without destroy */
                    g_hash_table_steal(localid_auth_hash,GINT_TO_POINTER(pckt->packet_id));
                } else {
                    log_message(WARNING, AREA_USER,
                            "Looks like a spoofing attempt from %s.",pckt->username);
                    /* TODO : kill bad guy */
                }
                pckt->user_groups=NULL;
                pckt->username=NULL;
                /* free pckt */
                free_connection(pckt);

            } else {
                free_connection(pckt);
                g_warning("Bad user packet.");
            }
            break;

        case AUTH_STATE_HELLOMODE:
            take_decision(pckt,PACKET_ALONE);
            break;

        case AUTH_STATE_DONE:
            /* packet has already been dropped, need only cleaning */
            free_connection(pckt);
            break;

        default:
            g_warning("Should not have this at %s:%d.\n",__FILE__,__LINE__);
    }
}

/**
 * Local id auth. Process messages on localid_auth_queue queue:
 *    - #INSERT_MESSAGE: insert a packet with localid_insert_message()
 *    - #REFRESH_MESSAGE: delete all old messages, use get_old_conn() to check
 *      if a connection is expired or not.
 *
 * Thread running until mutex (function argument) is locked.
 *
 * \param mutex Mutex used to stop the thread
 * \return NULL
 */
void* localid_auth(GMutex *mutex)
{
    connection_t *pckt = NULL;
    struct msg_addr_set global_msg;
    struct nu_srv_helloreq *msg = g_new0(struct nu_srv_helloreq,1);
    GHashTable *localid_auth_hash;
    struct internal_message *message=NULL;
    long current_timestamp;
    GTimeVal tv;

/** \todo
 * protocol v3 compatibility */

    global_msg.msg = (struct nu_srv_message*) msg;
    msg->type = SRV_REQUIRED_HELLO;
    msg->option = 0;
    msg->length = htons(sizeof(struct nu_srv_helloreq));

    /* init hash table */
    localid_auth_hash=g_hash_table_new(NULL,NULL);

    g_async_queue_ref (nuauthdatas->localid_auth_queue);
    g_async_queue_ref (nuauthdatas->tls_push_queue);
    while (g_mutex_trylock(mutex))
    {
        g_mutex_unlock(mutex);

        /* wait a message during 1000ms */
        g_get_current_time (&tv);
        g_time_val_add(&tv, 1000);
        message = g_async_queue_timed_pop(nuauthdatas->localid_auth_queue, &tv);
        if (message == NULL)
            continue;

        switch (message->type) {
            case INSERT_MESSAGE:
                pckt=message->datas;
                g_free(message);
                localid_insert_message(pckt, localid_auth_hash, &global_msg);
                break;

            case REFRESH_MESSAGE:
                g_free(message);
                current_timestamp=time(NULL);
                g_hash_table_foreach_remove(localid_auth_hash,get_old_conn,GINT_TO_POINTER(current_timestamp));
                break;

            default:
                g_warning("Should not have this at %s:%d.\n",__FILE__,__LINE__);
                g_free(message);
        }
    }
    g_async_queue_unref (nuauthdatas->localid_auth_queue);
    g_async_queue_unref (nuauthdatas->tls_push_queue);
    g_hash_table_destroy(localid_auth_hash);
    return NULL;
}

/** @} */

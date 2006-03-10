#include "auth_srv.h"
#include <jhash.h>

/* should never be called !!! */
void search_and_fill_catchall(connection_t *new, connection_t *element)
{
    if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
        g_warning("%s:%d Should not have this. Please email Nufw developpers!\n",__FILE__,__LINE__);
        g_message("state of pckt: %d, state of element: %d",new->state, element->state);
    }
    free_connection(new);
}

/**
 * Compute the key (hash) of a connection tracking.
 * 
 * \param headers IPv4 tracking headers (of type tracking_t) of a connection 
 * \return Comptuted hash
 */
inline guint hash_connection(gconstpointer headers)
{
    return (jhash_3words(((tracking_t *)headers)->saddr,
                (((tracking_t *)headers)->daddr ^ ((tracking_t *)headers)->protocol),
                (((tracking_t *)headers)->dest | ((tracking_t *)headers)->source << 16),
                32));
}

/**
 * Check if two connections are equal.
 * 
 * \param a Tracking headers (type ::tracking_t) compared with b
 * \param b Tracking headers (type ::tracking_t) compared with a
 * \return TRUE is IPv4 headers are equal, FALSE otherwise
 */
gboolean compare_connection(gconstpointer a, gconstpointer b)
{
    tracking_t *trck1 = (tracking_t *)a;
    tracking_t *trck2 = (tracking_t *)b;

    /* compare IPheaders */
    if (trck1->saddr != trck2->saddr) 
        return FALSE;

    /* compare proto */
    if (trck1->protocol != trck2->protocol) 
        return FALSE;

    /* compare proto headers */
    switch ( trck1->protocol) {
        case IPPROTO_TCP:
            if (trck1->source == trck2->source 
                && trck1->daddr == trck2->daddr
                && trck1->dest == trck2->dest)
                return TRUE;
            else
                return FALSE;

        case IPPROTO_UDP:
            if (trck1->dest == trck2->dest
                && trck1->source == trck2->source
                && trck1->daddr == trck2->daddr)
                return TRUE;
            else
                return FALSE;

        case IPPROTO_ICMP:
            if (trck1->type == trck2->type
                && trck1->code == trck2->code
                && trck1->daddr == trck2->daddr)
                return TRUE;
            else
                return FALSE;

        default:
            return FALSE;
    }
}

void search_and_push(connection_t *new) 
{
    /* push data to sender */ 
    struct internal_message *message = g_new0(struct internal_message, 1);
    if (!message){
        log_message (CRITICAL, AREA_USER, "Couldn't g_new0(). No more memory?");
        return;
    }
    debug_log_message (VERBOSE_DEBUG, AREA_USER, "need to warn client");
    /* duplicate tracking */
    message->type = WARN_MESSAGE;
    message->datas = g_memdup(&(new->tracking), sizeof(new->tracking));
    if (message->datas){
        g_async_queue_push (nuauthdatas->tls_push_queue, message);
    }else{
        g_free(message);
        log_message (CRITICAL, AREA_USER, "g_memdup returned NULL");
    }
}

inline void search_and_fill_complete_of_authreq(connection_t *new, connection_t *element) 
{
    switch (new->state){
        case  AUTH_STATE_AUTHREQ:
            debug_log_message (DEBUG, AREA_MAIN, "Adding a packet_id to a connection\n");
            element->packet_id =
                g_slist_prepend(element->packet_id, GINT_TO_POINTER((new->packet_id)->data));
            free_connection(new);
            break;

        case AUTH_STATE_USERPCKT:
            debug_log_message (VERBOSE_DEBUG, AREA_MAIN,
                    "Filling user data for %s\n", new->username);
            new->state = AUTH_STATE_COMPLETING;

            element->user_groups = new->user_groups;
            element->user_id = new->user_id;
            element->username = new->username;
            /* application */
            element->app_name = new->app_name;
            element->app_md5 = new->app_md5;
            /* system */
            element->os_sysname = new->os_sysname;
            element->os_release = new->os_release;
            element->os_version = new->os_version;
            /* user cache system */
            element->cacheduserdatas = new->cacheduserdatas;
            element->state = AUTH_STATE_COMPLETING;

            g_thread_pool_push (nuauthdatas->acl_checkers, new, NULL);
            break;

        default:
            search_and_fill_catchall(new, element);
    }
}

inline void search_and_fill_complete_of_userpckt(connection_t *new, connection_t *element) 
{
    switch (new->state){
        case  AUTH_STATE_AUTHREQ:
            element->state = AUTH_STATE_COMPLETING;

            /* Copy element members needed by ACL checker into new.
             * We don't use strdup/free because it's slow. 
             * So clean_connections_list() don't remove connection 
             * in state AUTH_STATE_COMPLETING :-)
             */
            new->state = AUTH_STATE_COMPLETING;
            /* application */
            new->app_name = element->app_name ;
            new->app_md5 =  element->app_md5 ;
            /* system */
            new->os_sysname = element->os_sysname ;
            new->os_release = element->os_release ;
            new->os_version = element->os_version ;

            g_thread_pool_push (nuauthdatas->acl_checkers,
                    new,
                    NULL);
            element->packet_id = new->packet_id;
            element->socket = new->socket;
            element->tls = new->tls;
            break;
            
        case AUTH_STATE_USERPCKT:
            debug_log_message (VERBOSE_DEBUG, AREA_MAIN,
                    "Found a duplicate user packet\n");
            free_connection(new);
            break;

        default:
            search_and_fill_catchall(new, element);
    }
}

inline void search_and_fill_done(connection_t *new, connection_t *element) 
{    
    /* if new is a nufw request respond with correct decision */
    switch (new->state){
        case AUTH_STATE_AUTHREQ:
            { 
                struct auth_answer answer = {element->decision, element->user_id, element->socket, element->tls} ;
                g_slist_foreach(new->packet_id,
                        (GFunc) send_auth_response,
                        &answer);
                free_connection(new);
                break;
            }

        case AUTH_STATE_USERPCKT:
            free_connection(new);
            break;

        default:
            search_and_fill_catchall(new, element);
    }
}

inline void search_and_fill_completing(connection_t *new, connection_t *element) 
{
    switch (new->state){
        case  AUTH_STATE_COMPLETING:
            /* fill acl this is a return from acl search */
            element->acl_groups = new->acl_groups;
            g_free(new);
            element->state = AUTH_STATE_READY;
            take_decision(element,PACKET_IN_HASH);
            break;

        case  AUTH_STATE_AUTHREQ:
            debug_log_message (DEBUG, AREA_MAIN,
                    "Adding a packet_id to a completing connection\n");
            element->packet_id =
                g_slist_prepend(element->packet_id, GINT_TO_POINTER((new->packet_id)->data));
            free_connection(new);
            break;
            
        case AUTH_STATE_USERPCKT:
            log_message (DEBUG, AREA_MAIN, "User packet in state completing\n");
            free_connection(new);
            break;
            
        default:
            search_and_fill_catchall(new, element);
    }
}

inline void search_and_fill_ready(connection_t *new, connection_t *element)
{
    debug_log_message (DEBUG, AREA_MAIN,
            "Element is in state %d but we received packet state %d\n",
            element->state,
            new->state);
    switch (new->state){
        case  AUTH_STATE_AUTHREQ:
            debug_log_message (DEBUG, AREA_MAIN,
                    "Adding a packet_id to a connection\n");
            element->packet_id =
                g_slist_prepend(element->packet_id, GUINT_TO_POINTER((new->packet_id)->data));
            free_connection(new);
            break;
            
        case AUTH_STATE_USERPCKT:
            debug_log_message (VERBOSE_DEBUG, AREA_MAIN,
                    "Need only cleaning\n");
            free_connection(new);
            break;           

        default:
            search_and_fill_catchall(new, element);
    }
}

inline void search_and_fill_update(connection_t *new, connection_t *element)
{
    switch (element->state){
        case AUTH_STATE_AUTHREQ:
            search_and_fill_complete_of_authreq(new, element);
            break;

        case AUTH_STATE_USERPCKT:
            search_and_fill_complete_of_userpckt(new, element);
            break;
            
        case AUTH_STATE_DONE:
            search_and_fill_done(new, element);
            break;
            
        case AUTH_STATE_COMPLETING:
            search_and_fill_completing(new, element);
            break;
            
        case AUTH_STATE_READY: 
            search_and_fill_ready(new, element);
            break;
            
        default:
            search_and_fill_catchall(new, element);
    }
}

/**
 * Thread created in init_nuauthdatas()
 * Try to insert a connection in Struct
 * Fetch datas in connections queue.
 */
void search_and_fill() 
{
    /* GRYZOR warning : it seems we g_free() on pckt only on some conditions in this function */
    connection_t *element;
    connection_t *new;

    g_async_queue_ref (nuauthdatas->connections_queue);
    g_async_queue_ref (nuauthdatas->tls_push_queue);
    /* wait for message */
    while ( (new = g_async_queue_pop(nuauthdatas->connections_queue)) ) {
        /* search pckt */
        g_static_mutex_lock (&insert_mutex);
        debug_log_message (VERBOSE_DEBUG, AREA_MAIN,
                "Starting search and fill\n");
        element = (connection_t *)g_hash_table_lookup(conn_list,&(new->tracking));
        if (element == NULL) {
            debug_log_message (DEBUG, AREA_MAIN, "Creating new element\n");
            g_hash_table_insert (conn_list, &(new->tracking), new);
            g_static_mutex_unlock (&insert_mutex);
            if (nuauthconf->push && new->state == AUTH_STATE_AUTHREQ) {
                search_and_push(new);
            }
        } else { 
            search_and_fill_update(new, element);
            g_static_mutex_unlock (&insert_mutex);
        }
    }
    g_async_queue_unref (nuauthdatas->connections_queue);
    g_async_queue_unref (nuauthdatas->tls_push_queue);
}


/*
 ** Copyright(C) 2003-2006 Eric Leblond <regit@inl.fr>
 **		     Vincent Deffontaines <vincent@gryzor.com>
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

#include "auth_srv.h"
#include <netinet/ip.h>

/** \file auth_common.c
 *  \brief Various functions used in NuAuth.
 */


static gint apply_decision(connection_t *element);

#ifdef PERF_DISPLAY_ENABLE
/* Subtract the `struct timeval' values X and Y,
 *         storing the result in RESULT.
 *                 Return 1 if the difference is negative, otherwise 0.  */

int timeval_substract (struct timeval *result,struct timeval *x,struct timeval *y)
{
    /* Perform the carry for the later subtraction by updating y. */
    if (x->tv_usec < y->tv_usec) {
        int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
        y->tv_usec -= 1000000 * nsec;
        y->tv_sec += nsec;
    }
    if (x->tv_usec - y->tv_usec > 1000000) {
        int nsec = (x->tv_usec - y->tv_usec) / 1000000;
        y->tv_usec += 1000000 * nsec;
        y->tv_sec -= nsec;
    }

    /* Compute the time remaining to wait.
     *           tv_usec is certainly positive. */
    result->tv_sec = x->tv_sec - y->tv_sec;
    result->tv_usec = x->tv_usec - y->tv_usec;

    /* Return 1 if result is negative. */
    return x->tv_sec < y->tv_sec;
}
#endif

/**
 * Display connection parameters using g_message(): IP+TCP/UDP headers,
 * OS name, OS release and OS version, and application name.
 *
 * Only display the connection if ::debug_level is #DEBUG_LEVEL_VERBOSE_DEBUG
 * or greater.
 *
 * \return Returns -1 if an error occurs, 1 else.
 */
gint print_connection(gpointer data,gpointer userdata)
{
    struct in_addr src,dest;
    connection_t * conn=(connection_t *) data;
    if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
    {
        gchar* firstfield;

        src.s_addr = ntohl(conn->tracking.saddr);
        dest.s_addr = ntohl(conn->tracking.daddr);
        firstfield=g_strdup(inet_ntoa(src));
        if (! firstfield){
            g_message("Couldn't strdup(). No more memory?");
            return -1;
        }
        g_message( "Connection: src=%s dst=%s proto=%u", firstfield, inet_ntoa(dest),
                conn->tracking.protocol);
        if (conn->tracking.protocol == IPPROTO_TCP){
            g_message("sport=%d dport=%d", conn->tracking.source,
                    conn->tracking.dest);
        }
        if (conn->os_sysname && conn->os_release && conn->os_version ){
            g_message("OS: %s %s %s",conn->os_sysname ,conn->os_release , conn->os_version );
        }
        if (conn->app_name){
            g_message("Application: %s",conn->app_name);
        }
        g_free(firstfield);
    }
    return 1;
}

/**
 * Send authentification response (decision of type ::decision_t) to the NuFW. 
 *
 * Use ::nuauth_decision_response_t structure to build the packet.
 * 
 * \param packet_id_ptr NetFilter packet unique identifier (32 bits)
 * \param userdata Pointer to an answer of type ::auth_answer
 */
void send_auth_response(gpointer packet_id_ptr, gpointer userdata)
{
    connection_t * element = (connection_t *) userdata;
    nuauth_decision_response_t* response = NULL;
    uint32_t packet_id = GPOINTER_TO_UINT(packet_id_ptr);
    uint16_t uid16;
    int payload_size = 0;
    int total_size;

    if (0xFFFF < element->user_id) {
        log_message(WARNING, AREA_MAIN,
                "User identifier don't fit in 16 bits, not to truncate the value.");
    }
    uid16 = (element->user_id & 0xFFFF);

#ifdef GRYZOR_HACKS
    if (element->decision == DECISION_REJECT){
        payload_size = 20+8;
    }
#endif    
    /* allocate */
    total_size = sizeof(nuauth_decision_response_t)+payload_size;
    response=g_alloca(total_size);
    response->protocol_version = PROTO_VERSION;
    response->msg_type = AUTH_ANSWER;
    response->user_id = htons(uid16);
    response->decision = element->decision;
    response->priority = 1;
    response->padding = 0;
    response->packet_id = htonl(packet_id);
    response->payload_len = htons(payload_size);
#ifdef GRYZOR_HACKS
    if (element->decision == DECISION_REJECT){
        char payload[28];
        struct iphdr *ip = (struct iphdr *)payload;

        /* create ip header */
        memset(payload, 0, 20);
        ip->version = 4;
        ip->ihl = 5;
        ip->tot_len = htons(20+8);
        ip->ttl = 64; /* write dummy ttl */
        ip->protocol = element->tracking.protocol;
        ip->saddr = htonl(element->tracking.saddr);
        ip->daddr = htonl(element->tracking.daddr);

        /* write transport layer */
        memcpy(payload+20, element->tracking.icmp_reject, 8);

        /* write icmp reject packet */
        memcpy((char*)response+sizeof(nuauth_decision_response_t), payload, payload_size);
    }
#endif        

    debug_log_message (DEBUG, AREA_MAIN, 
            "Sending auth answer %d for packet %u on socket %p",
            element->decision, packet_id, element->tls);
    if (element->tls->alive){
        g_mutex_lock(element->tls->tls_lock);
        gnutls_record_send(*(element->tls->tls), response, total_size);
        g_mutex_unlock(element->tls->tls_lock);
        g_atomic_int_dec_and_test(&(element->tls->usage));
    } else {
        if (g_atomic_int_dec_and_test(&(element->tls->usage))){
            clean_nufw_session(element->tls);			
        }
    }
}

void free_connection_callback(gpointer conn, gpointer unused)
{
    free_connection((connection_t *)conn);
}

void free_connection_list(GSList *list)
{
    if (list == NULL)
        return;
    g_slist_foreach(list, free_connection_callback, NULL);
    g_slist_free(list);
}

/**
 * Delete a connection and all of its memory.
 *
 * May call log_user_packet() with #TCP_STATE_DROP state if connection was
 * waiting its authentification.
 * 
 * \param conn Pointer to a connection
 */
void free_connection(connection_t *conn)
{
    g_assert (conn != NULL );

    /* log if necessary (only state authreq) with user log module
     * AUTH_STATE_COMPLETING is reached when no acl is found for packet */
    if (conn->state == AUTH_STATE_AUTHREQ){
        /* copy message */
        log_user_packet(conn,TCP_STATE_DROP);
    }
    /* 
     * tell cache we don't use the ressource anymore
     */
    if (conn->acl_groups && nuauthconf->acl_cache){
        struct cache_message * message=g_new0(struct cache_message,1);
        debug_log_message (VERBOSE_DEBUG, AREA_MAIN,
                "Sending free to acl cache");
        message->key=acl_create_and_alloc_key(conn);
        message->type=FREE_MESSAGE;
        message->datas=conn->acl_groups;
        g_async_queue_push(nuauthdatas->acl_cache->queue,message);
    }
    /* free user group */
    if (conn->cacheduserdatas){
        if(conn->username){
            struct cache_message * message=g_new0(struct cache_message,1);
            if (!message){
                log_message(CRITICAL, AREA_MAIN, "Could not g_new0(). No more memory?");
                /* GRYZOR should we do something special here? */
            } else {
                debug_log_message (VERBOSE_DEBUG, AREA_MAIN,
                        "Sending free to user cache");
                message->key=g_strdup(conn->username);
                message->type=FREE_MESSAGE;
                message->datas=conn->cacheduserdatas;
                g_async_queue_push(nuauthdatas->user_cache->queue,message);
            }
        } else {
            debug_log_message (VERBOSE_DEBUG, AREA_MAIN,
                    "Can not free user cache, username is null");
        }
    } else {
        g_free(conn->username);
    }
    if (conn->packet_id != NULL )
        g_slist_free (conn->packet_id);

    g_free(conn->app_name);
    g_free(conn->app_md5);
    g_free(conn->os_sysname);
    g_free(conn->os_release);
    g_free(conn->os_version);
    g_free(conn);
}

/** used for logging purpose 
 * it DOES NOT duplicate internal data 
 */

connection_t* duplicate_connection(connection_t* element)
{
    connection_t * conn_copy=g_memdup(element, sizeof(*element));
    if (conn_copy == NULL){
        log_message(WARNING, AREA_MAIN, "memory duplication falied");
        return NULL;
    }
    conn_copy->username = g_strdup(element->username);
    conn_copy->app_name = g_strdup(element->app_name);
    conn_copy->app_md5 = g_strdup(element->app_md5);
    conn_copy->os_sysname = g_strdup(element->os_sysname);
    conn_copy->os_release = g_strdup(element->os_release);
    conn_copy->os_version = g_strdup(element->os_version);

    /* Nullify needed internal field */
    conn_copy->acl_groups=NULL;
    conn_copy->user_groups=NULL;
    conn_copy->packet_id=NULL;
    conn_copy->cacheduserdatas=NULL;
    conn_copy->state=AUTH_STATE_DONE;
    return conn_copy;
}



/**
 * remove element from hash table
 */

inline int conn_cl_remove(gconstpointer conn)
{
  if (!  g_hash_table_steal (conn_list,
                &(((connection_t *)conn)->tracking)) ){
        log_message(WARNING, AREA_MAIN, "Removal of conn in hash failed\n");
        return 0;
    }
    return 1;
}

/**
 * Remove a connection from the connection hash table (::conn_list)
 * and free its memory using free_connection().
 *
 * \param conn A connection
 * \return Returns 1 if succeeded, 0 otherwise
 */

int conn_cl_delete(gconstpointer conn) 
{
    g_assert (conn != NULL);

    if (conn_cl_remove(conn)==0){
        return 0;
    }

    /* free isolated structure */ 
    free_connection((connection_t *)conn);
    return 1;
}

/**
 * This function is used by clean_connections_list() to check if a
 * connection is 'old' (outdated) or not. It checks timeout with current
 * timestamp (see member packet_timeout of ::nuauthconf) and skip connection
 * in state ::AUTH_STATE_COMPLETING (because of an evil hack in 
 * search_and_fill_complete_of_userpckt() :-)).
 * 
 * \param key Key in hash of the connection (not used in the function)
 * \param value Pointer to the connection
 * \param user_data Current timestamp (get by time(NULL))
 * \return TRUE if the connection is old, FALSE else
 */
gboolean get_old_conn (gpointer key, gpointer value, gpointer user_data)
{
    long current_timestamp = GPOINTER_TO_INT(user_data);

    /* Don't remove connection in state AUTH_STATE_COMPLETING because of
     * an evil hack in search_and_fill_complete_of_userpckt() :-)  
     */ 
    if (
            ( current_timestamp - ((connection_t *)value)->timestamp > nuauthconf->packet_timeout)  
            &&
            (((connection_t *)value)->state!=AUTH_STATE_COMPLETING)		    
       ){
        return TRUE;
    }
    return FALSE;
}

/**
 * Delete a connection from the hash table ::conn_list by its key.
 * Log the message with ::TCP_STATE_DROP state.
 *
 * \param key Key of connection which have to be deleted
 * \return If the connection is suppressed returns 1, otherwise returns 0
 */
int conn_key_delete(gconstpointer key)
{
    connection_t* element = (connection_t*)g_hash_table_lookup (conn_list, key);
    if (element){
        /* need to log drop of packet if it is a nufw packet */
        if (element->state == AUTH_STATE_AUTHREQ) {
            log_user_packet(element,TCP_STATE_DROP); 
        }
        g_hash_table_remove (conn_list,key);
        return 1;
    }
    return 0;
}

void clean_connection_list_callback(gpointer key, gpointer value, gpointer data)
{
    GSList **list_ptr = (GSList **)data;
    long current_timestamp = time(NULL);
    if (get_old_conn(key, value, GINT_TO_POINTER(current_timestamp)))
    {
        *list_ptr = g_slist_prepend(*list_ptr, key);
    }
}


/**
 * Find old connection and delete them.
 * It uses get_old_conn() to check if a connection is 'old' or not.
 */
void clean_connections_list ()
{
    GSList *old_keyconn_list = NULL;
    GSList *old_conn_list = NULL;
    GSList *iterator;
    int conn_list_size, nb_deleted;
    
    /* extract the list of old connections */
    g_static_mutex_lock (&insert_mutex);
    conn_list_size = g_hash_table_size(conn_list);
    g_hash_table_foreach(conn_list, clean_connection_list_callback, &old_keyconn_list);

    /* remove old connections from connection list */
    nb_deleted = 0;
    for (iterator = old_keyconn_list; iterator != NULL; )
    {
        gpointer key = iterator->data;
        gpointer value = g_hash_table_lookup(conn_list, key);
        g_hash_table_steal(conn_list, key);
        old_conn_list = g_slist_prepend(old_conn_list, value);        
        iterator = iterator->next;
        nb_deleted += 1;
    }
    g_static_mutex_unlock (&insert_mutex);
    g_slist_free(old_keyconn_list);

    /* reject all old connections */
    for (iterator = old_conn_list; iterator != NULL; )
    {
        connection_t *element = iterator->data;
        iterator = iterator->next;
        if (nuauthconf->reject_after_timeout != 0)
            element->decision = DECISION_REJECT;
        else
            element->decision = DECISION_DROP;
        apply_decision(element);
        free_connection(element);
    }
    g_slist_free(old_conn_list);
   
    /* display number of deleted elements */
    if (0 < nb_deleted) {
        log_message(INFO, AREA_MAIN, 
                "Clean connection list: %d connection(s) suppressed", nb_deleted);
    }
}

typedef enum {
    TEST_NODECIDE,
    TEST_DECIDED
} test_t;

/**
 * Take a decision of a connection authentification, and send it to NuFW.
 *
 * The process may be asynchronous (using decisions_workers,
 * member of ::nuauthdatas)
 * 
 * \param element A connection
 * \param place Place where the connection is stored
 *              (PACKET_ALONE or PACKET_IN_HASH
 * \return Returns -1 if fails, 1 otherwise
 */
gint take_decision(connection_t *element, packet_place_t place) 
{
    GSList * parcours=NULL;
    decision_t answer = DECISION_NODECIDE;
    test_t test;
    GSList * user_group=element->user_groups;
    time_t expire=-1; /* no expiration by default */

    debug_log_message (DEBUG, AREA_MAIN,
            "Trying to take decision on %p", element);

    /*even firster we check if we have an actual element*/
    if (element == NULL)
        return -1;

    /* first check if we have found acl */
    if ( element->acl_groups == NULL ){
        answer = DECISION_DROP;
    } else {
        decision_t start_test,stop_test;
        if (nuauthconf->prio_to_nok == 1){
            start_test=DECISION_ACCEPT;
            stop_test=DECISION_DROP;
        } else {
            start_test=DECISION_DROP;
            stop_test=DECISION_ACCEPT;
        }
        test=TEST_NODECIDE;
        for  ( parcours = element->acl_groups; 
                ( parcours != NULL  && test == TEST_NODECIDE ); 
                parcours = g_slist_next(parcours) ) {
            /* for each user  group */
            if (parcours->data != NULL) {
                for ( user_group = element->user_groups;
                        user_group != NULL && test == TEST_NODECIDE;
                        user_group =  g_slist_next(user_group)) {
                    /* search user group in acl_groups */
                    g_assert(((struct acl_group *)(parcours->data))->groups);
                    if (g_slist_find(((struct acl_group *)(parcours->data))->groups,(gconstpointer)user_group->data)) {
                        answer = ((struct acl_group *)(parcours->data))->answer ;
                        if (nuauthconf->prio_to_nok == 1){
                            if ((answer == DECISION_DROP) 
#ifdef GRYZOR_HACKS 
                                    || (answer == DECISION_REJECT)
#endif
                                    ){
                                test=TEST_DECIDED;
                            }
                        } else {
                            if (answer == DECISION_ACCEPT){
                                test=TEST_DECIDED;
                            }
                        }
                        if (answer == DECISION_ACCEPT){
                            if ( (expire == -1) || 
                                    ( (((struct acl_group *)(parcours->data))->expire != -1)
                                      &&
                                      (expire !=-1) 
                                      &&
                                      (expire > ((struct acl_group *)(parcours->data))->expire 
                                      )
                                    )) {
                                expire =  ((struct acl_group *)(parcours->data))->expire;
                            }
                        }
                    }
                }
            } else {
                debug_log_message(DEBUG, AREA_MAIN, "Empty acl : bad things ...");
                answer=DECISION_DROP;
                test=TEST_DECIDED;
            }
        }
    }
    /* answer is DECISION_NODECIDE if we did not found any matching group */
    if(answer == DECISION_NODECIDE){
        answer=DECISION_DROP;
    }
    if (expire == 0){
        answer=DECISION_DROP;
    }
    element->decision=answer;

    if ((element->expire != -1) && (element->expire < expire)){
        expire=element->expire;
    }
    /* we must put element in expire list if needed before decision is taken */
    if(expire>0){
        struct limited_connection* datas=g_new0(struct limited_connection,1);
        struct internal_message  *message=g_new0(struct internal_message,1);
        memcpy(&(datas->tracking),&(element->tracking),sizeof(tracking_t));
        datas->expire=expire;
        datas->gwaddr.s_addr=(element->tls)->peername.s_addr;
        message->datas=datas;
        message->type=INSERT_MESSAGE;
        g_async_queue_push (nuauthdatas->limited_connections_queue, message);
    }

    if (nuauthconf->log_users_sync) {
        /* copy current element */
        if (place == PACKET_IN_HASH){
            conn_cl_remove(element);
        }
        /* push element to decision workers */
        g_thread_pool_push (nuauthdatas->decisions_workers,
                element,
                NULL);
    } else {
        apply_decision(element);
        element->packet_id=NULL;
        if (place == PACKET_IN_HASH){
            conn_cl_delete(element);
        } else {
            free_connection(element);
        }

    }
    return 1;
}

/** 
 * Log (using log_user_packet()) and send answer (using send_auth_response())
 * for a given connection.
 * 
 * \param element A connection
 * \return Returns 1
 */
gint apply_decision(connection_t *element)
{
    decision_t decision=element->decision;
#ifdef PERF_DISPLAY_ENABLE
    struct timeval leave_time,elapsed_time;
#endif

    if (decision == DECISION_ACCEPT){
        log_user_packet(element,TCP_STATE_OPEN);
    } else {
        log_user_packet(element,TCP_STATE_DROP);
    }

    g_slist_foreach(element->packet_id,
            send_auth_response,
            element);
#ifdef PERF_DISPLAY_ENABLE
    gettimeofday(&leave_time,NULL);
    timeval_substract (&elapsed_time,&leave_time,&(element->arrival_time));
    log_message(INFO, AREA_MAIN, 
            "Treatment time for conn : %ld.%03ld sec",
            elapsed_time.tv_sec,elapsed_time.tv_usec);
#endif

    /* free packet_id */
    if (element->packet_id != NULL ){
        g_slist_free (element->packet_id);
        element->packet_id=NULL;
    }
    return 1;
}

/**
 * This is a callback to apply a decision from the decision thread 
 * pool (decisions_workers member of ::nuauthdatas).
 *
 * The queue is feeded by take_decision().
 * 
 * \param userdata Pointer to a connection (of type ::connection_t)
 * \param data NULL pointer (unused)
 */
void decisions_queue_work (gpointer userdata, gpointer data)
{
    connection_t* element=(connection_t *)userdata;

    block_on_conf_reload();
    apply_decision(element);

    free_connection(element);
}

/**
 * Suppress domain from "user\@domain" string (returns "user").
 *
 * \return Username which need to be freeded
 */
char * get_rid_of_domain(const char* user_domain)
{
    char *username=NULL;
    char **user_realm;
    user_realm=g_strsplit(user_domain, "@", 2);
    if (user_realm[0] != NULL){
        username = g_strdup(user_realm[0]);
    } else {
        username = g_strdup(user_domain);
    }
    g_strfreev(user_realm);
    return username;
}

/**
 * Free a ::tls_buffer_read buffer and all of its memory.
 */
void free_buffer_read(struct tls_buffer_read* datas)
{
    g_free(datas->os_sysname);
    g_free(datas->os_release);
    g_free(datas->os_version);
    g_free(datas->buffer);
    g_free(datas->user_name);
    if (datas->groups != NULL){
        g_slist_free(datas->groups);
    }
    g_free(datas);
}

/**
 * Function snprintf() which check buffer overflow, and always write a '\\0'
 * to the end of the buffer.
 *
 * \param buffer Buffer where characters are written
 * \param buffer_size Buffer size (in bytes), usually equals to sizeof(buffer)
 * \param format Format string (see printf() documentation)
 * \return Returns FALSE if a buffer overflow occurs, TRUE is everything goes fine.
 */
gboolean secure_snprintf(char *buffer, unsigned int buffer_size, char *format, ...)
{
    va_list args;  
    int ret;
    va_start(args, format);
    ret = g_vsnprintf(buffer, buffer_size, format, args);
    va_end(args);
    buffer[buffer_size-1] = '\0';
    if (0 <= ret && ret <= ((int)buffer_size-1))
        return TRUE;
    else
        return FALSE;
}    


/*
 ** Copyright(C) 2003-2005 Eric Leblond <regit@inl.fr>
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

static gint apply_decision(connection_t element);

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
 * Debug  function used to print ip headers of 
 * received packets.
 */

gint print_connection(gpointer data,gpointer userdata)
{
    struct in_addr src,dest;
    connection_t * conn=(connection_t *) data;
    src.s_addr = ntohl(conn->tracking.saddr);
    dest.s_addr = ntohl(conn->tracking.daddr);
    if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
    {
        gchar* firstfield=g_strdup(inet_ntoa(src));
        if (! firstfield){
            g_message("Couldn't strdup(). No more memory?");
            return -1;
        }
        g_message( "Connection : src=%s dst=%s proto=%u", firstfield, inet_ntoa(dest),
                conn->tracking.protocol);
        if (conn->tracking.protocol == IPPROTO_TCP){
            g_message("sport=%d dport=%d", conn->tracking.source,
                    conn->tracking.dest);
        }
        if (conn->os_sysname && conn->os_release && conn->os_version ){
            g_message("OS : %s %s %s",conn->os_sysname ,conn->os_release , conn->os_version );
        }
        if (conn->app_name){
            g_message("Application : %s",conn->app_name);
        }
        g_message(" ");
        g_free(firstfield);
    }
    return 1;
}

/**
 * Send auth response to the gateway.
 * 
 * - Argument 1 : packet_id
 * - Argument 2 : answer
 */

void send_auth_response(gpointer data, gpointer userdata)
{
    unsigned long  packet_id = GPOINTER_TO_UINT(data);
    struct auth_answer * aanswer = (struct auth_answer *) userdata;
    u_int8_t answer = aanswer->answer;
    uint8_t prio=1;
    uint8_t proto_version=PROTO_VERSION,answer_type=AUTH_ANSWER;
    char datas[512];
    char *pointer;

    aanswer->user_id=htons(aanswer->user_id);
    packet_id=htonl(packet_id);
    /* for each packet_id send a response */

    memset(datas,0,sizeof datas);
    memcpy(datas,&proto_version,sizeof proto_version);
    pointer=datas+sizeof proto_version;
    memcpy(pointer,&answer_type,sizeof answer_type);
    pointer+=sizeof answer_type;
    memcpy(pointer,&(aanswer->user_id),sizeof( u_int16_t));
    pointer+=sizeof (u_int16_t);
    /* ANSWER and Prio */
    memcpy(pointer,&answer,sizeof answer);
    pointer+=sizeof answer;
    memcpy(pointer,&prio,sizeof prio);
    pointer+=sizeof prio;
    pointer+=2;
    /* packet_id */
    memcpy(pointer,&(packet_id),sizeof(packet_id));
    pointer+=sizeof (packet_id);

    debug_log_message (DEBUG, AREA_MAIN, 
            "Sending auth answer %d for %lu on %p ... ",
            answer, packet_id, aanswer->tls);
    if (aanswer->tls->alive){
        gnutls_record_send(*(aanswer->tls->tls),datas,pointer-datas);
        g_atomic_int_dec_and_test(&(aanswer->tls->usage));
    } else {
        if (g_atomic_int_dec_and_test(&(aanswer->tls->usage))){
            clean_nufw_session(aanswer->tls);			
        }
    }
    debug_log_message (DEBUG, AREA_MAIN, "done\n");
}


/**
 * free structure associated to a connection.
 * 
 * Argument : A connection
 * Return 1
 */
int free_connection(connection_t * conn)
{
    g_assert (conn != NULL );

#ifdef DEBUG_ENABLE
    if (conn->packet_id != NULL) {
        log_message (VERBOSE_DEBUG, AREA_MAIN, 
                "freeing connection %p with %lu\n",
                conn,
                (long unsigned int)GPOINTER_TO_UINT(conn->packet_id->data));
    }
#endif
    /* log if necessary (only state authreq) with user log module
     * AUTH_STATE_COMPLETING is reached when no acl is found for packet */
    if (conn->state == AUTH_STATE_AUTHREQ){
        /* copy message */
        log_user_packet(*conn,TCP_STATE_DROP);
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
                if (DEBUG_OR_NOT(DEBUG_LEVEL_CRITICAL,DEBUG_AREA_MAIN))
                    g_warning("Could not g_new0(). No more memory?");
                //GRYZOR should we do something special here?
            }else{
                debug_log_message (VERBOSE_DEBUG, AREA_MAIN,
                        "Sending free to user cache");
                message->key=g_strdup(conn->username);
                message->type=FREE_MESSAGE;
                message->datas=conn->cacheduserdatas;
                g_async_queue_push(nuauthdatas->user_cache->queue,message);
            }
        } 
        else {
            debug_log_message (VERBOSE_DEBUG, AREA_MAIN,
                    "Can not free user cache, username is null");
        }
    } else {
        if ( (conn->user_groups != ALLGROUP)  && (conn->user_groups != NULL)){
            /* free ressource */
            g_slist_free (conn->user_groups);
        }
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
    return 1;
}


/**
 * remove a connection from connection hash and free it.
 *
 * Argument : a connection
 * Return : 1 if succeeded, 0 otherwise
 */

int conn_cl_delete(gconstpointer conn) 
{
    g_assert (conn != NULL);

    if (!  g_hash_table_steal (conn_list,
                &(((connection_t *)conn)->tracking)) ){
        if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
            g_warning("Removal of conn in hash failed\n");
        return 0;
    }
    /* free isolated structure */ 
    free_connection((connection_t *)conn);
    return 1;
}

/**
 * test if a a  connection is old 
 * 
 * Argument 1 :  key in hash of the connection
 * Argument 2 : pointer to the connection
 * Argument 3 : current timestamp
 * Return : None
 *
 * used by clean_connections_list() 
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
 * delete a element given its key.
 *
 * Argument : a key
 * Return : 1 if element suppressed, 0 otherwise
 */

int conn_key_delete(gconstpointer key)
{
    connection_t* element = (connection_t*)g_hash_table_lookup ( conn_list,key);
    if (element){
        /* need to log drop of packet if it is a nufw packet */
        if (element->state == AUTH_STATE_AUTHREQ) {
            log_user_packet(*element,TCP_STATE_DROP); 
        }
        g_hash_table_remove (conn_list,key);
        return 1;
    }
    return 0;
}

/**
 * find old elements in connection hash and delete them.
 *
 * Argument : None
 * Return : None
 */

void clean_connections_list ()
{
    int conn_list_size=g_hash_table_size(conn_list); /* not acccurate but we don't abuse of the lock */
    long current_timestamp=time(NULL);

    g_static_mutex_lock (&insert_mutex);
    /* go through table and  stock keys associated to old packets */
    g_hash_table_foreach_remove(conn_list,get_old_conn,GINT_TO_POINTER(current_timestamp));
    /* work is done we release lock */
    g_static_mutex_unlock (&insert_mutex);
    if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN)) {
        int conn_list_size_now=g_hash_table_size(conn_list);
        if (conn_list_size_now != conn_list_size)
            g_message("%d connection(s) suppressed from list\n",conn_list_size-conn_list_size_now);
    }
}


/**
 * find answer for a connection and send it.
 * 
 * Argument : a connection
 * Return : 1
 * Return : -1 if parameter is NULL
 */

gint take_decision(connection_t * element,gchar place) 
{
    GSList * parcours=NULL;
    decision_t answer = DECISION_NODECIDE;
    decision_t test;
    GSList * user_group=element->user_groups;
    time_t expire=-1; /* no expiration by default */

    debug_log_message (DEBUG, AREA_MAIN,
            "Trying to take decision on %p\n", element);

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
        test=DECISION_NODECIDE;
        for  ( parcours = element->acl_groups; 
                ( parcours != NULL  && test == DECISION_NODECIDE ); 
                parcours = g_slist_next(parcours) ) {
            /* for each user  group */
            if (parcours->data != NULL) {
                for ( user_group = element->user_groups;
                        user_group != NULL && test == DECISION_NODECIDE;
                        user_group =  g_slist_next(user_group)) {
                    /* search user group in acl_groups */
                    g_assert(((struct acl_group *)(parcours->data))->groups);
                    if (g_slist_find(((struct acl_group *)(parcours->data))->groups,(gconstpointer)user_group->data)) {
                        answer = ((struct acl_group *)(parcours->data))->answer ;
                        if (nuauthconf->prio_to_nok == 1){
                            if (answer == DECISION_DROP){
                                test=DECISION_ACCEPT;
                            }
                        } else {
                            if (answer == DECISION_ACCEPT){
                                test=DECISION_ACCEPT;
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
#ifdef DEBUG_ENABLE
                if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
                    g_warning("Empty acl : bad things ...");
#endif
                answer=DECISION_DROP;
                test=DECISION_ACCEPT;
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
        connection_t * copy_of_element=(connection_t *)g_memdup(element,sizeof(connection_t));

        /* need to free acl and user group */
        copy_of_element->acl_groups=NULL;
        copy_of_element->user_groups=NULL;
        if (element->cacheduserdatas){
            copy_of_element->username=g_strdup(element->username);
        } else	{
            copy_of_element->username=element->username;
            element->username = NULL;
        }
        if (nuauthconf->acl_cache) {
            copy_of_element->app_name=g_strdup(element->app_name);
            copy_of_element->app_md5=g_strdup(element->app_md5);
            copy_of_element->os_sysname=g_strdup(element->os_sysname);
            copy_of_element->os_release=g_strdup(element->os_release);
            copy_of_element->os_version=g_strdup(element->os_version);
        } else {
            copy_of_element->app_name=element->app_name;
            element->app_name=NULL;
            copy_of_element->app_md5=element->app_md5;
            element->app_md5=NULL;
            copy_of_element->os_sysname=element->os_sysname;
            element->os_sysname=NULL;
            copy_of_element->os_release=element->os_release;
            element->os_release=NULL;
            copy_of_element->os_version=element->os_version;
            element->os_version=NULL;
        }
        copy_of_element->user_id=element->user_id;
        /* push element to decision workers */
        g_thread_pool_push (nuauthdatas->decisions_workers,
                copy_of_element,
                NULL);
    } else {
        apply_decision(*element);
    }

    element->packet_id=NULL;
    if (place == PACKET_IN_HASH){
        conn_cl_delete(element);
    } else {
        free_connection(element);
    }
    return 1;
}

/** 
 * log and send answer for a given connection.
 * 
 * Argument : a connection
 * Return : 1
 */

gint apply_decision(connection_t element)
{
    decision_t answer=element.decision;
    struct auth_answer aanswer ={ answer , element.user_id ,element.socket, element.tls } ;
#ifdef PERF_DISPLAY_ENABLE
    struct timeval leave_time,elapsed_time;
#endif

    if (answer == DECISION_ACCEPT){
        log_user_packet(element,TCP_STATE_OPEN);
    } else {
        log_user_packet(element,TCP_STATE_DROP);
    }

    g_slist_foreach(element.packet_id,
            send_auth_response,
            &aanswer);
    /* free packet_id */
#ifdef PERF_DISPLAY_ENABLE
    gettimeofday(&leave_time,NULL);
    timeval_substract (&elapsed_time,&leave_time,&(element.arrival_time));
    g_message("Treatment time for conn : %ld.%06ld",elapsed_time.tv_sec,elapsed_time.tv_usec);
#endif

    if (element.packet_id != NULL ){
        g_slist_free (element.packet_id);
        element.packet_id=NULL;
    }
    return 1;
}

/**
 * interface for apply_decision compliant with queue system.
 * 
 * - Argument 1  : a connection
 * - Argument 2 : unused
 * - Return : None
 */

void decisions_queue_work (gpointer userdata, gpointer data)
{
    connection_t* element=(connection_t *)userdata;

    block_on_conf_reload();
    apply_decision( * element);

    if (element)
        g_free(element->username);
    g_free(element);
}

/**
 * suppress domain from user\@domain string.
 *
 * Return user.
 */

char * get_rid_of_domain(const char* user)
{
    char *username=NULL;
    char **user_realm;
    user_realm=g_strsplit(user,"@",2);
    if (*user_realm){
        username=g_strdup(*user_realm);
    }
    g_strfreev(user_realm);
    return username;
}

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


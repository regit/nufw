/*
 ** Copyright(C) 2003-2004 Eric Leblond <eric@inl.fr>
 **		     Vincent Deffontaines <vincent@gryzor.com>
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
#include <jhash.h>

static gint apply_decision(connection element);

void bail (const char *on_what){
    perror(on_what);
    exit(1);
}
/*
 * Args : a connection and a state
 */

inline char change_state(connection *elt, char state){
    elt->state = state;
    return  elt->state;
}

  guint
hash_connection(gconstpointer headers)
{
  //  tracking *tracking_hdrs = (tracking *)headers;

  return (jhash_3words(((tracking *)headers)->saddr,
        (((tracking *)headers)->daddr ^ ((tracking *)headers)->protocol),
        (((tracking *)headers)->dest | ((tracking *)headers)->source << 16),
        32));
}


gboolean compare_connection(gconstpointer tracking_hdrs1, gconstpointer tracking_hdrs2){
    /* compare IPheaders */
    if ( ( ((tracking *) tracking_hdrs1)->daddr ==
          ((tracking *) tracking_hdrs2)->daddr ) &&
        ( ((tracking *) tracking_hdrs1)->saddr ==
          ((tracking *) tracking_hdrs2)->saddr ) ){

        /* compare proto */
        if (((tracking *) tracking_hdrs1)->protocol ==
            ((tracking *) tracking_hdrs2)->protocol) {

            /* compare proto headers */
            switch ( ((tracking *) tracking_hdrs1)->protocol) {
              case IPPROTO_TCP:
                if ( ( ((tracking *) tracking_hdrs1)->dest ==
                      ((tracking *) tracking_hdrs2)->dest )   &&
                    ( ((tracking *) tracking_hdrs1)->source ==
                      ((tracking *) tracking_hdrs2)->source ) ){

                    return TRUE;

                }
                break;
              case IPPROTO_UDP:
                if ( ( ((tracking *)tracking_hdrs1)->dest ==
                      ((tracking *)tracking_hdrs2)->dest )   &&
                    ( ((tracking *)tracking_hdrs1)->source ==
                      ((tracking *)tracking_hdrs2)->source ) ){
                    return TRUE;
                }
                break;
              case IPPROTO_ICMP:
                if ( ( ((tracking *)tracking_hdrs1)->type ==
                      ((tracking *)tracking_hdrs2)->type )   &&
                    ( ((tracking *)tracking_hdrs1)->code ==
                      ((tracking *)tracking_hdrs2)->code ) ){
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

/* 
 * Try to insert a connection in Struct
 * Argument : a connection
 * Return : pointer to the connection list element
 */

void search_and_fill () {
    connection * element = NULL;
    connection * pckt = NULL;

    g_async_queue_ref (connexions_queue);
    /* wait for message */
    while ( (pckt = g_async_queue_pop(connexions_queue)) ) {
        /* search pckt */
        g_static_mutex_lock (&insert_mutex);
        if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
            g_message("Starting search and fill\n");
        element = (connection *) g_hash_table_lookup(conn_list,&(pckt->tracking_hdrs));
        if (element == NULL) {
            if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
                g_message("Creating new element\n");
            g_hash_table_insert (conn_list,
                &(pckt->tracking_hdrs),
                pckt);
            /* as we append the new one is at the end */
            g_static_mutex_unlock (&insert_mutex);
        } else { 
            switch (((connection *)element)->state){
              case STATE_AUTHREQ:
                switch (pckt->state){
                  case  STATE_AUTHREQ:
                    if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
                        g_message("Adding a packet_id to a connexion\n");
                    ((connection *)element)->packet_id =
                      g_slist_prepend(((connection *)element)->packet_id, GINT_TO_POINTER((pckt->packet_id)->data));
                    free_connection(pckt);
                    /* and return */
                    break;
                  case STATE_USERPCKT:
                    if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
                        g_message("Fill user datas\n");
                    ((connection *)element)->user_groups = pckt->user_groups;
                    ((connection *)element)->user_id = pckt->user_id;
                        g_free(pckt);
                    /* change STATE */

                    change_state(((connection *)element),STATE_READY);
                    /* going to take decision ? */
                    take_decision(element);
                    break;
                }
                break;
              case STATE_USERPCKT:
                switch (pckt->state){
                  case  STATE_AUTHREQ:
                    if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
                        g_message("Fill acl datas\n");
                    ((connection *)element)->acl_groups = pckt->acl_groups;
                    ((connection *)element)->packet_id = pckt->packet_id;

                        g_free(pckt);
                    change_state(((connection *)element),STATE_READY);
                    /* going to take decision ? */
                        take_decision(element);
                    break;
                  case STATE_USERPCKT:
                    if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
                        g_message("Duplicate user packet\n");
                    free_connection(pckt);
                    break;
                  default:
                    g_assert("Should not have this\n");
                }
                break;
              case STATE_DONE:
                if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
                    g_warning("Element in state DONE and receive packet state %d\n",
                        pckt->state);
                /* if pckt is a nufw request respond with correct decision */
                switch (pckt->state){
                  case  STATE_AUTHREQ:
                    { struct auth_answer aanswer ={ element->decision , element->user_id } ;
                        g_slist_foreach(pckt->packet_id,
                            (GFunc) send_auth_response,
                            &aanswer
                            );
                    }
                    free_connection(pckt);
                    break;
                }
                break;
              case STATE_READY:
                if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
                    g_warning("Element in state %d and receive packet state %d\n",
                        ((connection *)element)->state,
                        pckt->state);
                switch (pckt->state){
                  case  STATE_AUTHREQ:
                    if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
                        g_message("Adding a packet_id to a connexion\n");
                    ((connection *)element)->packet_id =
                      g_slist_prepend(((connection *)element)->packet_id, GUINT_TO_POINTER((pckt->packet_id)->data));
                    free_connection(pckt);
                    /* and return */
                    break;
                  case STATE_USERPCKT:
                    if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
                        g_message("Need only cleaning\n");
                    free_connection(pckt);
                    break;           
                }
            }
            g_static_mutex_unlock (&insert_mutex);
        }
    }
}

/*
 * print connection
 */

/* TODO : restore lock after DEBUG's done */
gint print_connection(gpointer data,gpointer userdata){
    struct in_addr src,dest;
    connection * conn=(connection *) data;
    src.s_addr = ntohl(conn->tracking_hdrs.saddr);
    dest.s_addr = ntohl(conn->tracking_hdrs.daddr);
    if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
    {
        gchar* firstfield=strdup(inet_ntoa(src));
        g_message( "Connection : src=%s dst=%s proto=%u", firstfield, inet_ntoa(dest),
            conn->tracking_hdrs.protocol);
        if (conn->tracking_hdrs.protocol == IPPROTO_TCP){
            g_message("sport=%d dport=%d\n", conn->tracking_hdrs.source,
                conn->tracking_hdrs.dest);
        }
        g_free(firstfield);
    }
    return 1;
}

gint free_struct(gpointer data,gpointer userdata){
    g_free((struct acl_group *)data);
    if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
        g_message("Free acl_groups at %p\n",data);
    return 1;
}

/*
 * Send auth response to the gateway
 */

void send_auth_response(gpointer data, gpointer userdata){
    unsigned long  packet_id = GPOINTER_TO_UINT(data);
    struct auth_answer * aanswer = (struct auth_answer *) userdata;
    u_int8_t answer = aanswer->answer;
    uint8_t prio=1;
    uint8_t proto_version=PROTO_VERSION,answer_type=AUTH_ANSWER;
    char datas[512];
    char *pointer;

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
    /* TODO id gw */
    pointer+=2;
    /* packet_id */
    memcpy(pointer,&(packet_id),sizeof(packet_id));
    pointer+=sizeof (packet_id);

    if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)) {
        g_message("Sending auth answer %d for %lu on %d ... ",answer,packet_id,sck_auth_reply);
        fflush(stdout);
    }
    if (sendto(sck_auth_reply,
          datas,
          pointer-datas,
          MSG_DONTWAIT,
          (struct sockaddr *)&adr_srv,
          sizeof adr_srv) < 0) {
        if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
            g_warning("failure when sending auth response\n");
    }
    if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
        g_message("done\n");
    }
}



int free_connection(connection * conn){
    GSList *acllist;
    g_assert (conn != NULL );

        if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
            if (conn->packet_id != NULL)
                if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN))
                    g_message("freeing connection %p with %lu\n",conn,(long unsigned int)GPOINTER_TO_UINT(conn->packet_id->data));
        }
        acllist=conn->acl_groups;
        if ( (acllist  != DUMMYACLS) && (acllist  != NULL) ){
            g_slist_foreach(acllist,(GFunc) free_struct,NULL);
            g_slist_free (acllist);
            if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
                g_message ("acl_groups freed %p\n",acllist);
        }
        if ( (conn->user_groups != ALLGROUP)  && (conn->user_groups != NULL))
            g_slist_free (conn->user_groups);
        if (conn->packet_id != NULL )
            g_slist_free (conn->packet_id);
	if (conn->username != NULL)
		g_free(conn->username);
        g_free(conn);
    return 1;
}



int conn_cl_delete(gconstpointer conn) {
    g_assert (conn != NULL);

    if (!  g_hash_table_steal (conn_list,
          &(((connection *)conn)->tracking_hdrs)) ){
        if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
            g_warning("Removal of conn in hash failed\n");
        return 0;
    }
    /* free isolated structure */ 
    free_connection((connection *)conn);
    return 1;
}

GSList * old_conn_list;

void  get_old_conn (gpointer key,
    gpointer value,
    gpointer user_data){
    long current_timestamp = GPOINTER_TO_INT(user_data);
    if ( current_timestamp - ((connection *)value)->timestamp > packet_timeout) {
        old_conn_list = (gpointer) g_slist_prepend( old_conn_list,key);
    }
}

int conn_key_delete(gconstpointer key) {
    connection* element = (connection*)g_hash_table_lookup ( conn_list,key);
    /* test for lock */
    if (element){
            /* need to log drop of packet if it is a nufw packet */
            if (element->state == STATE_AUTHREQ) {
                log_user_packet(*element,STATE_DROP); 
            }
            g_hash_table_remove (conn_list,key);
            return 1;
    }
    return 0;
}


void clean_connections_list (){
    int conn_list_size=g_hash_table_size(conn_list);
    long current_timestamp=time(NULL);
    old_conn_list=NULL;

    if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
        g_message("Start cleaning of connection older than %d seconds",packet_timeout);
    g_static_mutex_lock (&insert_mutex);
    /* go through table and  stock keys associated to old packets */
    g_hash_table_foreach(conn_list,get_old_conn,GINT_TO_POINTER(current_timestamp));
    if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
        g_message("Finish searching old connections");
    /* go through stocked keys to suppres old element */
    g_slist_foreach(old_conn_list,(GFunc)conn_key_delete,NULL);
    if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
        g_message("Finish to delete old connections");
    /* work is done we release lock */
    g_static_mutex_unlock (&insert_mutex);
    if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN)) {
        int conn_list_size_now=g_hash_table_size(conn_list);
        if (conn_list_size_now != conn_list_size)
            g_message("%d connection(s) suppressed from list\n",conn_list_size-conn_list_size_now);
    }
    if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
        g_message("Cleaning of connections finished");
}

gint take_decision(connection * element) {
    GSList * parcours=NULL;
    int answer = NODECIDE;
    char test;
    GSList * user_group=element->user_groups;

    if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
        g_message("Trying to take decision on %p\n",element);
    /* first check if we have found acl */
    if ( element->acl_groups == NULL ){
        answer = NOK;
    } else {
        int start_test,stop_test;
        if (nuauth_prio_to_nok == 1){
            start_test=OK;
            stop_test=NOK;
        } else {
            start_test=NOK;
            stop_test=OK;
        }
        test=NODECIDE;
        for  ( parcours = element->acl_groups; 
            ( parcours != NULL  && test == NODECIDE ); 
            parcours = g_slist_next(parcours) ) {
            /* for each user  group */

            if (parcours->data != NULL) {
                for ( user_group = element->user_groups;
                    user_group != NULL && test == NODECIDE;
                    user_group =  g_slist_next(user_group)) {
                    /* search user group in acl_groups */
                    g_assert(((struct acl_group *)(parcours->data))->groups);
                    if (g_slist_find(((struct acl_group *)(parcours->data))->groups,(gconstpointer)user_group->data)) {
                        answer = ((struct acl_group *)(parcours->data))->answer ;
                        if (nuauth_prio_to_nok == 1){
                            if (answer == NOK)
                                test=OK;
                        } else {
                            if (answer == OK)
                                test=OK;
                        }
                    }
                }
            } else {
                if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
                    g_warning("Empty acl bad things ...");
                answer=NOK;
                test=OK;
            }
        }
    }
       
    element->decision=answer;

    if (nuauth_log_users_sync) {
        /* copy current element */
        connection * copy_of_element=(connection *)g_memdup(element,sizeof(connection));
       
        /* need to free acl and user group */
         copy_of_element->acl_groups=NULL;
         copy_of_element->user_groups=NULL;
         /* push element to decision workers */
         g_thread_pool_push (decisions_workers,
                        copy_of_element,
                        NULL);
    } else {
        apply_decision(*element);
    }
    
    element->packet_id=NULL;
    conn_cl_delete(element);
    return 1;
}

gint apply_decision(connection element){
	int answer=element.decision;
        struct auth_answer aanswer ={ answer , element.user_id } ;

         if (answer == OK){
                log_user_packet(element,STATE_OPEN);
            } else {
                log_user_packet(element,STATE_DROP);
            }

            g_slist_foreach(element.packet_id,
                send_auth_response,
                &aanswer);
	    /* free packet_id */

        if (element.packet_id != NULL ){
            g_slist_free (element.packet_id);
            element.packet_id=NULL;
        }
	return 1;
}

void decisions_queue_work (gpointer userdata, gpointer data){
    connection* element=(connection *)userdata;

    apply_decision( * element);

    g_free(element);
}

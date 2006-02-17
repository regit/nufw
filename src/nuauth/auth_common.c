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


#include <auth_srv.h>
#include <jhash.h>


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



static gint apply_decision(connection element);

/*
 * Args : a connection and a state
 */

inline void change_state(connection *elt, char state)
{
        if (elt != NULL){
        	elt->state = state;
        }
}

/**
 * Function used for connection hash.
 * 
 * - Params : Ipv4header of a connection 
 * - Return : the associated key
 */

inline  guint hash_connection(gconstpointer headers)
{
	return (jhash_3words(((tracking *)headers)->saddr,
				(((tracking *)headers)->daddr ^ ((tracking *)headers)->protocol),
				(((tracking *)headers)->dest | ((tracking *)headers)->source << 16),
				32));
}

/**
 * Find if two connections are equal.
 * 
 * - Params : two ip headers
 * - Return : TRUE is ip headers are equal, FALSE otherwise
 */

gboolean compare_connection(gconstpointer tracking_hdrs1, gconstpointer tracking_hdrs2){
      /* Note from Gryzor : this might be optimized by comparing daddr first? 
       * daddr may have greater chances of being different when working on connections from a LAN*/
	/* compare IPheaders */
	if (        ( ((tracking *) tracking_hdrs1)->saddr ==
				((tracking *) tracking_hdrs2)->saddr ) ){

		/* compare proto */
		if (((tracking *) tracking_hdrs1)->protocol ==
				((tracking *) tracking_hdrs2)->protocol) {

			/* compare proto headers */
			switch ( ((tracking *) tracking_hdrs1)->protocol) {
				case IPPROTO_TCP:
					if ( ( ((tracking *) tracking_hdrs1)->source ==
								((tracking *) tracking_hdrs2)->source )
							&&
							( ((tracking *) tracking_hdrs1)->dest ==
							  ((tracking *) tracking_hdrs2)->dest )   
					   ){
						if ( ((tracking *) tracking_hdrs1)->daddr ==
								((tracking *) tracking_hdrs2)->daddr ) 
							return TRUE;

					}
					break;
				case IPPROTO_UDP:
					if ( ( ((tracking *)tracking_hdrs1)->dest ==
								((tracking *)tracking_hdrs2)->dest )   &&
							( ((tracking *)tracking_hdrs1)->source ==
							  ((tracking *)tracking_hdrs2)->source ) ){

						if ( ((tracking *) tracking_hdrs1)->daddr ==
								((tracking *) tracking_hdrs2)->daddr ) 
							return TRUE;
					}
					break;
				case IPPROTO_ICMP:
					if ( ( ((tracking *)tracking_hdrs1)->type ==
								((tracking *)tracking_hdrs2)->type )   &&
							( ((tracking *)tracking_hdrs1)->code ==
							  ((tracking *)tracking_hdrs2)->code ) ){
						if ( ((tracking *) tracking_hdrs1)->daddr ==
								((tracking *) tracking_hdrs2)->daddr ) 
							return TRUE;
					}
			}
		}
	}
	return FALSE;
}

/**
 * Try to insert a connection in Struct
 * Fetch datas in connections queue.
 * 
 * - Argument : None
 * - Return : None
 */

void search_and_fill () 
{
	connection * element = NULL;
        //GRYZOR warning : it seems we g_free() on pckt only on some conditions in this function
	connection * pckt = NULL;

	g_async_queue_ref (nuauthdatas->connexions_queue);
	g_async_queue_ref (nuauthdatas->tls_push_queue);
	/* wait for message */
	while ( (pckt = g_async_queue_pop(nuauthdatas->connexions_queue)) ) {
		/* search pckt */
		g_static_mutex_lock (&insert_mutex);
#ifdef DEBUG_ENABLE
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
			g_message("Starting search and fill\n");
#endif
		element = (connection *) g_hash_table_lookup(conn_list,&(pckt->tracking_hdrs));
		if (element == NULL) {
#ifdef DEBUG_ENABLE
			if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
				g_message("Creating new element\n");
#endif
			g_hash_table_insert (conn_list,
					&(pckt->tracking_hdrs),
					pckt);
			g_static_mutex_unlock (&insert_mutex);
			if (nuauthconf->push){
				/* push data to sender */
				if (pckt->state == STATE_AUTHREQ){
					struct internal_message *message=g_new0(struct internal_message,1);
                                        if (!message){
                                            //GRYZOR asks if we should clean conn_list since we filled it before
                                            if (DEBUG_OR_NOT(DEBUG_LEVEL_CRITICAL,DEBUG_AREA_USER))
                                                g_message("Couldn't g_new0(). No more memory?");
                                            return;
                                        }
#ifdef DEBUG_ENABLE
					if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
						g_message("need to warn client");
#endif
					/* duplicate tracking_hdrs */
					message->type=WARN_MESSAGE;
					message->datas=g_memdup(&(pckt->tracking_hdrs),sizeof(tracking));
					if (message->datas){
						g_async_queue_push (nuauthdatas->tls_push_queue, message);
					}else{
                                            //GRYZOR asks if we should clean conn_list since we filled it before
                                            if (DEBUG_OR_NOT(DEBUG_LEVEL_CRITICAL,DEBUG_AREA_USER))
                                                g_message("g_memdup returned NULL");
                                            return;
                                        }
				}
			}
		} else { 
			switch (((connection *)element)->state){
				case STATE_AUTHREQ:
					switch (pckt->state){
						case  STATE_AUTHREQ:
#ifdef DEBUG_ENABLE
							if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
								g_message("Adding a packet_id to a connection\n");
#endif
							((connection *)element)->packet_id =
								g_slist_prepend(((connection *)element)->packet_id, GINT_TO_POINTER((pckt->packet_id)->data));
							free_connection(pckt);
							/* and return */
							break;
						case STATE_USERPCKT:
#ifdef DEBUG_ENABLE
							if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
								g_message("Filling user data for %s\n",pckt->username);
#endif
							((connection *)element)->user_groups = pckt->user_groups;
							((connection *)element)->user_id = pckt->user_id;
							((connection *)element)->username = pckt->username;
							/* application */
							((connection *)element)->appname = pckt->appname;
							((connection *)element)->appmd5 = pckt->appmd5;
							/* system */
							((connection *)element)->sysname = pckt->sysname;
							((connection *)element)->release = pckt->release;
							((connection *)element)->version = pckt->version;
							/* user cache system */
							((connection *)element)->cacheduserdatas = pckt->cacheduserdatas;
							/* going to take decision ? */

							if (nuauthconf->aclcheck_state_ready){
								change_state(((connection *)pckt),STATE_COMPLETING);
								change_state(((connection *)element),STATE_COMPLETING);
								g_thread_pool_push (nuauthdatas->acl_checkers,
										pckt,
										NULL);
							} else {
								/* change STATE */
								change_state(((connection *)element),STATE_READY);
								take_decision(element,PACKET_IN_HASH);
							}
							break;
					}
					break;
				case STATE_USERPCKT:
					switch (pckt->state){
						case  STATE_AUTHREQ:
							change_state(((connection *)element),STATE_COMPLETING);
							if (nuauthconf->aclcheck_state_ready){
								change_state(((connection *)pckt),STATE_COMPLETING);
								/* application */
								pckt->appname =  ((connection *)element)->appname ;
								pckt->appmd5 =   ((connection *)element)->appmd5 ;
								/* system */
								pckt->sysname =  ((connection *)element)->sysname ;
								pckt->release =  ((connection *)element)->release ;
								pckt->version =  ((connection *)element)->version ;

								g_thread_pool_push (nuauthdatas->acl_checkers,
										pckt,
										NULL);
								((connection *)element)->packet_id = pckt->packet_id;
								((connection *)element)->socket = pckt->socket;
								((connection *)element)->tls = pckt->tls;


							} else {
#ifdef DEBUG_ENABLE
								if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
									g_message("Filling acl data\n");
#endif
								((connection *)element)->acl_groups = pckt->acl_groups;
								/* now we don't care about pckt acl_group */
								pckt->acl_groups=NULL;
								((connection *)element)->packet_id = pckt->packet_id;
								((connection *)element)->socket = pckt->socket;
								((connection *)element)->tls = pckt->tls;

								g_free(pckt);
								/* going to take decision ? */
								take_decision(element,PACKET_IN_HASH);
							}
							break;
						case STATE_USERPCKT:
#ifdef DEBUG_ENABLE
							if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
								g_message("Found a duplicate user packet\n");
#endif
							free_connection(pckt);
							break;
						default:
							if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
								g_warning("%s:%d Should not have this. Please email Nufw developpers!\n",__FILE__,__LINE__);
								g_message("state of packet is %d/USERPCKT",pckt->state);
							}
					}
					break;
				case STATE_DONE:
					/* if pckt is a nufw request respond with correct decision */
					switch (pckt->state){
						case  STATE_AUTHREQ:
							{ struct auth_answer aanswer ={ element->decision , element->user_id ,element->socket, element->tls} ;
								g_slist_foreach(pckt->packet_id,
										(GFunc) send_auth_response,
										&aanswer
									       );
							}
							free_connection(pckt);
							break;
						case STATE_USERPCKT:
							free_connection(pckt);
							break;
							/* packet has been drop cause no acl was found */
						default:
							if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
								g_message("packet is in state %d",pckt->state);
								g_message("%s:%d Should not be here. Please email Nufw developpers!\n",__FILE__,__LINE__);
							}
					}
					break;
				case STATE_COMPLETING:
					switch (pckt->state){
						case  STATE_COMPLETING:
							if (nuauthconf->aclcheck_state_ready){
								/* fill acl this is a return from acl search */
								((connection *)element)->acl_groups = pckt->acl_groups;
								g_free(pckt);
								change_state(((connection *)element),STATE_READY);
								take_decision(element,PACKET_IN_HASH);
							}
							break;
						case  STATE_AUTHREQ:
#ifdef DEBUG_ENABLE
							if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
								g_message("Adding a packet_id to a completing connection\n");
#endif
							((connection *)element)->packet_id =
								g_slist_prepend(((connection *)element)->packet_id, GINT_TO_POINTER((pckt->packet_id)->data));
							free_connection(pckt);
							/* and return */
							break;
						case STATE_USERPCKT:
							if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
								g_message("User packet in state completing\n");
							free_connection(pckt);
							break;
						default:
							if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
								g_message("%s:%d Should not be here. Please email Nufw developpers!\n",__FILE__,__LINE__);

					}
					break;
				case STATE_READY: 
#ifdef DEBUG_ENABLE
					if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
						g_message("Element is in state %d but we received packet state %d\n",
								((connection *)element)->state,
								pckt->state);
#endif
					switch (pckt->state){
						case  STATE_AUTHREQ:
#ifdef DEBUG_ENABLE
							if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
								g_message("Adding a packet_id to a connection\n");
#endif
							((connection *)element)->packet_id =
								g_slist_prepend(((connection *)element)->packet_id, GUINT_TO_POINTER((pckt->packet_id)->data));
							free_connection(pckt);
							/* and return */
							break;
						case STATE_USERPCKT:
#ifdef DEBUG_ENABLE
							if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
								g_message("Need only cleaning\n");
#endif
							free_connection(pckt);
							break;           
					}
			}
			g_static_mutex_unlock (&insert_mutex);
		}
	}
}

/**
 * Debug  function used to print ip headers of 
 * received packets.
 */

gint print_connection(gpointer data,gpointer userdata)
{
	struct in_addr src,dest;
	connection * conn=(connection *) data;
	src.s_addr = ntohl(conn->tracking_hdrs.saddr);
	dest.s_addr = ntohl(conn->tracking_hdrs.daddr);
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
	{
		gchar* firstfield=strdup(inet_ntoa(src));
                if (! firstfield){
                    g_message("Couldn't strdup(). No more memory?");
                    return -1;
                }
		g_message( "Connection : src=%s dst=%s proto=%u", firstfield, inet_ntoa(dest),
				conn->tracking_hdrs.protocol);
		if (conn->tracking_hdrs.protocol == IPPROTO_TCP){
			g_message("sport=%d dport=%d", conn->tracking_hdrs.source,
					conn->tracking_hdrs.dest);
		}
		if (conn->sysname && conn->release && conn->version ){
			g_message("OS : %s %s %s",conn->sysname ,conn->release , conn->version );
		}
		if (conn->appname){
			g_message("Application : %s",conn->appname);
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
 * - Return : None
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

#ifdef DEBUG_ENABLE
        if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)) {
            g_message("Sending auth answer %d for %lu on %p ... ",answer,packet_id,aanswer->tls);
        }
#endif
        if (aanswer->tls->alive){
            gnutls_record_send(*(aanswer->tls->tls),datas,pointer-datas);
            g_atomic_int_dec_and_test(&(aanswer->tls->usage));
        } else {
            if (g_atomic_int_dec_and_test(&(aanswer->tls->usage))){
                clean_nufw_session(aanswer->tls);			
            }
        }
#ifdef DEBUG_ENABLE
        if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
            g_message("done\n");
        }
#endif
}


/**
 * free structure associated to a connection.
 * 
 * Argument : A connection
 * Return 1
 */
int free_connection(connection * conn)
{
	g_assert (conn != NULL );

#ifdef DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
		if (conn->packet_id != NULL) {
			g_message("freeing connection %p with %lu\n",
					conn,
					(long unsigned int)GPOINTER_TO_UINT(conn->packet_id->data));
		}
	}
#endif
	/* log if necessary (only state authreq) with user log module
	 * STATE_COMPLETING is reached when no acl is found for packet */
	if (conn->state == STATE_AUTHREQ){
		/* copy message */
		log_user_packet(*conn,STATE_DROP);
	}
	/* 
	 * tell cache we don't use the ressource anymore
	 */
	if (conn->acl_groups && nuauthconf->acl_cache){
		struct cache_message * message=g_new0(struct cache_message,1);
#ifdef DEBUG_ENABLE
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
			g_message("Sending free to acl cache");
		}
#endif
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
#ifdef DEBUG_ENABLE
			  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
				g_message("Sending free to user cache");
			  }
#endif
			  message->key=g_strdup(conn->username);
			  message->type=FREE_MESSAGE;
			  message->datas=conn->cacheduserdatas;
			  g_async_queue_push(nuauthdatas->user_cache->queue,message);
                        }
		} 
#ifdef DEBUG_ENABLE
		else {
			if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
				g_message("Can not free user cache, username is null");
			}
		}
#endif
	} else {
		if ( (conn->user_groups != ALLGROUP)  && (conn->user_groups != NULL)){
			/* free ressource */
			g_slist_free (conn->user_groups);
		}
//		if (conn->username != NULL)
			g_free(conn->username);
	}
	if (conn->packet_id != NULL )
		g_slist_free (conn->packet_id);

//	if (conn->appname != NULL)
		g_free(conn->appname);

//	if (conn->appmd5 != NULL)
		g_free(conn->appmd5);

//	if (conn->sysname != NULL)
		g_free(conn->sysname);
//	if (conn->release != NULL)
		g_free(conn->release);
//	if (conn->version != NULL)
		g_free(conn->version);

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
				&(((connection *)conn)->tracking_hdrs)) ){
		if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
			g_warning("Removal of conn in hash failed\n");
		return 0;
	}
	/* free isolated structure */ 
	free_connection((connection *)conn);
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
 * used for connection hash cleaning purpose
 * 
 */

gboolean  get_old_conn (gpointer key,
		gpointer value,
		gpointer user_data)
{
	long current_timestamp = GPOINTER_TO_INT(user_data);
	if (
			( current_timestamp - ((connection *)value)->timestamp > nuauthconf->packet_timeout)  
			&&
			(((connection *)value)->state!=STATE_COMPLETING)		    
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
	connection* element = (connection*)g_hash_table_lookup ( conn_list,key);
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

gint take_decision(connection * element,gchar place) 
{
	GSList * parcours=NULL;
	int answer = NODECIDE;
	char test;
	GSList * user_group=element->user_groups;
        time_t expire=-1; /* no expiration by default */

#ifdef DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN))
		g_message("Trying to take decision on %p\n",element); 
#endif
        /*even firster we check if we have an actual element*/
        if (element == NULL)
            return -1;

	/* first check if we have found acl */
	if ( element->acl_groups == NULL ){
		answer = NOK;
	} else {
		int start_test,stop_test;
		if (nuauthconf->prio_to_nok == 1){
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
						if (nuauthconf->prio_to_nok == 1){
							if (answer == NOK){
								test=OK;
							}
						} else {
							if (answer == OK){
								test=OK;
							}
						}
						if (answer == OK){
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
				answer=NOK;
				test=OK;
			}
		}
        }
        /* answer is NODECIDE if we did not found any matching group */
        if(answer == NODECIDE){
          answer=NOK;
        }
	if (expire == 0){
		answer=NOK;
	}
	element->decision=answer;

	if ((element->expire != -1) && (element->expire < expire)){
		expire=element->expire;
	}
	/* we must put element in expire list if needed before decision is taken */
        if(expire>0){
                struct limited_connection* datas=g_new0(struct limited_connection,1);
                struct internal_message  *message=g_new0(struct internal_message,1);
	        memcpy(&(datas->tracking_hdrs),&(element->tracking_hdrs),sizeof(tracking));
                datas->expire=expire;
                datas->gwaddr.s_addr=(element->tls)->peername.s_addr;
                message->datas=datas;
                message->type=INSERT_MESSAGE;
		g_async_queue_push (nuauthdatas->limited_connexions_queue, message);
        }
        
	if (nuauthconf->log_users_sync) {
		/* copy current element */
		connection * copy_of_element=(connection *)g_memdup(element,sizeof(connection));

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
			copy_of_element->appname=g_strdup(element->appname);
			copy_of_element->appmd5=g_strdup(element->appmd5);
			copy_of_element->sysname=g_strdup(element->sysname);
			copy_of_element->release=g_strdup(element->release);
			copy_of_element->version=g_strdup(element->version);
		} else {
			copy_of_element->appname=element->appname;
			element->appname=NULL;
			copy_of_element->appmd5=element->appmd5;
			element->appmd5=NULL;
			copy_of_element->sysname=element->sysname;
			element->sysname=NULL;
			copy_of_element->release=element->release;
			element->release=NULL;
			copy_of_element->version=element->version;
			element->version=NULL;
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

gint apply_decision(connection element)
{
	int answer=element.decision;
	struct auth_answer aanswer ={ answer , element.user_id ,element.socket, element.tls } ;
#ifdef PERF_DISPLAY_ENABLE
	struct timeval leave_time,elapsed_time;
#endif

	if (answer == OK){
		log_user_packet(element,STATE_OPEN);
	} else {
		log_user_packet(element,STATE_DROP);
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
	connection* element=(connection *)userdata;

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
	char *username,**user_realm;
	user_realm=g_strsplit(user,"@",2);
	username=g_strdup(*user_realm);
	g_strfreev(user_realm);
	return username;
}

void free_buffer_read(struct buffer_read* datas)
{
	if (datas->sysname){
		g_free(datas->sysname);
	}
	if (datas->release){
		g_free(datas->release);
	}
	if (datas->version){
		g_free(datas->version);
	}
	if (datas->buf){
		g_free(datas->buf);
	}
	if (datas->userid){
		g_free(datas->userid);
	}
	if (datas->groups){
		g_slist_free(datas->groups);
	}
	g_free(datas);
}


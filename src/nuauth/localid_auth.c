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

char localid_authenticated_protocol(int protocol)
{
	if (protocol != IPPROTO_TCP){
		return TRUE;
	}
	return FALSE;
}

void localid_auth()
{
	connection * pckt = NULL;
	connection * element = NULL;
	u_int32_t randomid;
	struct msg_addr_set *global_msg = g_new0(struct msg_addr_set,1);
	struct nuv2_srv_helloreq *msg = g_new0(struct nuv2_srv_helloreq,1);
	GHashTable *localid_auth_hash;
	struct internal_message *message=NULL;


	global_msg->msg = (struct nuv2_srv_message*) msg;
	msg->type = SRV_REQUIRED_HELLO;
	msg->option = 0;
	msg->length = htons(sizeof(struct nuv2_srv_helloreq));

	/* init hash table */
	localid_auth_hash=g_hash_table_new(NULL,NULL);
	
	g_async_queue_ref (nuauthdatas->localid_auth_queue);
	g_async_queue_ref (nuauthdatas->tls_push_queue);
	/* wait for message */
	while ( (message = g_async_queue_pop(nuauthdatas->localid_auth_queue)) ) {
		switch (message->type) { 
			case INSERT_MESSAGE:
				pckt=message->datas;
				g_free(message);
				switch ( pckt->state){
					case STATE_AUTHREQ:
						/* add in struct */
						/* compute random u32 integer  and test if 
						 * iter if it exists in hash, increment it if needed
						 */
						randomid = random();
						while(g_hash_table_lookup(localid_auth_hash,GINT_TO_POINTER(randomid))){
							randomid++;
						}
						/* add element to hash with computed key */
						g_hash_table_insert(localid_auth_hash,GINT_TO_POINTER(randomid),pckt);
						/* send message to clients */
						((struct nuv2_srv_helloreq*)global_msg->msg)->helloid = randomid;
						global_msg->addr = pckt->tracking_hdrs.saddr;
						global_msg->found = FALSE;
						g_static_mutex_lock (&client_mutex);
						warn_clients(global_msg);
						g_static_mutex_unlock (&client_mutex);
						break;
					case STATE_USERPCKT:
						/* search in struct */
						element = (connection*) g_hash_table_lookup (localid_auth_hash,(GSList*)(pckt->packet_id)->data);
						/* if found ask for completion */
						if (element){
							/* TODO : do a check on saddr */
							if ( (element->tracking_hdrs.saddr == pckt->tracking_hdrs.saddr ) || 1 ){	

								element->state=STATE_HELLOMODE;	
								element->user_id=pckt->user_id;
								element->username=pckt->username;
								element->user_groups=pckt->user_groups;
								pckt->user_groups=NULL;
								pckt->username=NULL;
								/* do asynchronous call to acl check */
								g_thread_pool_push (nuauthdatas->acl_checkers, element, NULL);
								/* remove element from hash without destroy */
								g_hash_table_steal(localid_auth_hash,pckt->packet_id);
							} else {
								g_warning("looks like a spoofing attempt.");
								/* TODO : kill bad guy */
							}
							/* free pckt */
							free_connection(pckt);

						} else {
							free_connection(pckt);
							g_warning("Bad user packet.");
						}
						break;
					case STATE_HELLOMODE:
						take_decision(pckt,PACKET_ALONE);
						break;
					case STATE_DONE:
						/* packet has already been dropped, need only cleaning */
						free_connection(pckt);
						break;
					default:
						g_warning("Should not have this at %s:%d.\n",__FILE__,__LINE__);
				} 
				break;
			case REFRESH_MESSAGE:
				{
					long current_timestamp=time(NULL);
					g_free(message);
					g_hash_table_foreach_remove(localid_auth_hash,get_old_conn,GINT_TO_POINTER(current_timestamp));
				}
				break;
			default:
				g_warning("Should not have this at %s:%d.\n",__FILE__,__LINE__);

		}
	}

}


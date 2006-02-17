/*
** Copyright(C) 2003-2005 Eric Leblond <regit@inl.fr>
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

/*
 * check packet contained in element against
 * an external base (ldap,radius,...)
 */

/**
 * Fill in acl_groups of a connection by calling external module.
 * 
 * Argument : a connection
 * Return : 1 if OK, 0 otherwise
 */

int external_acl_groups (connection * element){
  GSList * acl_groups=NULL;

  /* query external authority */

  acl_groups = acl_check(element);

  element->acl_groups=acl_groups;
  if (acl_groups != NULL){
	return 1;
  }
  return 0;
}


/**
 * (acl_ckeckers function).
 * Treat a connection from insertion to decision 
 * 
 * - Argument 1 : a connection 
 * - Argument 2 : unused
 * - Return : None
 */

void acl_check_and_decide (gpointer userdata, gpointer data)
{
	connection * conn_elt = userdata;
	int initialstate = conn_elt->state;
#ifdef DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_PACKET))
		g_message("entering acl_check\n");
#endif
        block_on_conf_reload();
	if (conn_elt == NULL){
		if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_PACKET)){
			g_message("This is no good : elt is NULL\n");
		}
	} else {
		if (nuauthconf->aclcheck_state_ready || (nuauthconf->hello_authentication && (! (initialstate == STATE_HELLOMODE)) )){
			/* if STATE_COMPLETING packet comes from search and fill 
			 * research need to be done
			 * */
			if (conn_elt->state == STATE_COMPLETING){
				if (nuauthconf->acl_cache){
					get_acls_from_cache(conn_elt);
				} else {
					external_acl_groups(conn_elt);
				}
			} else {
				conn_elt->acl_groups=NULL;
			}
		} else {
			if (nuauthconf->acl_cache){
					get_acls_from_cache(conn_elt);
			} else {
					external_acl_groups(conn_elt);
			}
#ifdef DEBUG_ENABLE
			if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
				g_message("getting acl for:");
				print_connection(conn_elt,NULL);
			}
#endif
			if (conn_elt->acl_groups==NULL){
#if IAMAWARRIOR
				/* no acl found so packet has to be dropped */
				struct auth_answer aanswer ={ NOK , conn_elt->user_id ,conn_elt->socket,conn_elt->tls } ;
#endif

#ifdef DEBUG_ENABLE
				if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_PACKET)){
					g_message("No ACL, packet dropped %p with state %d\n",conn_elt,conn_elt->state);
				}
#endif
#if IAMAWARRIOR
				send_auth_response(GUINT_TO_POINTER(conn_elt->packet_id->data),&aanswer);
				/* we can get rid of packet_id because we have sent an answer */
				conn_elt->packet_id=g_slist_remove(conn_elt->packet_id,conn_elt->packet_id->data);
#endif
			}

		}
		/* transmit data we get to the next step */
		if (nuauthconf->hello_authentication && (initialstate == STATE_HELLOMODE)){
			struct internal_message *message = g_new0(struct internal_message,1);
			message->type=INSERT_MESSAGE;
			message->datas=conn_elt;
			/* well this is an localid auth packet */
			g_async_queue_push (nuauthdatas->localid_auth_queue,message);
		} else {
			/* give packet to search and fill */
			g_async_queue_push (nuauthdatas->connexions_queue,conn_elt);
		}
	}
#ifdef DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_PACKET))
		g_message("leaving acl_check\n");
#endif
}



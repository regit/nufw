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

/**
 * \addtogroup NuauthCore
 * @{
 */

/**
 * \file check_acls.c
 * \brief check packet contained in element against an external base 
 */

/**
 * Fill in acl_groups of a connection by calling external module.
 * 
 * Argument : a connection
 * Return : 1 if OK, 0 otherwise
 */

int external_acl_groups (connection_t * element){
  GSList * acl_groups=NULL;

  /* query external authority */

  acl_groups = modules_acl_check(element);

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
 *  We use this function when :
 *  - decision is ready to be taken for the connection
 *  - 
 * 
 * - Argument 1 : a connection 
 * - Argument 2 : unused
 * - Return : None
 */

void acl_check_and_decide (gpointer userdata, gpointer data)
{
	connection_t * conn_elt = userdata;
	debug_log_message(VERBOSE_DEBUG, AREA_PACKET, "entering acl_check");
        block_on_conf_reload();
	if (conn_elt == NULL){
		log_message(WARNING, AREA_PACKET, "This is no good : elt is NULL at %s:%d",__FILE__,__LINE__);
        } else {
            /* if AUTH_STATE_COMPLETING packet comes from search and fill 
             * research need to be done, same if state is AUTH_STATE_HELLOMODE
             * but here this is a packet from localid_auth_queue
             * */
            if ((conn_elt->state == AUTH_STATE_COMPLETING) ||
                    (nuauthconf->hello_authentication && (conn_elt->state == AUTH_STATE_HELLOMODE)) 
               ){
                if (nuauthconf->acl_cache){
                    get_acls_from_cache(conn_elt);
                } else {
                    external_acl_groups(conn_elt);
                }
                switch(conn_elt->state){
                    /* packet is coming from hello authentication, sending it back */
                  case AUTH_STATE_HELLOMODE:
                      {
                          struct internal_message *message = g_new0(struct internal_message,1);
                          message->type=INSERT_MESSAGE;
                          message->datas=conn_elt;
                          /* well this is an localid auth packet */
                          g_async_queue_push (nuauthdatas->localid_auth_queue,message);
                      }
                      break;
                      /* give packet to search and fill */
                  case AUTH_STATE_COMPLETING:
                      {
                          g_async_queue_push (nuauthdatas->connections_queue,conn_elt);
                      }
                      break;
                  default:
                      log_message(WARNING, AREA_PACKET, "This is no good : conn state is unvalid at %s:%d",__FILE__,__LINE__);
                }
            }
        }
	debug_log_message(VERBOSE_DEBUG, AREA_PACKET, "leaving acl_check");
}

/** @} */

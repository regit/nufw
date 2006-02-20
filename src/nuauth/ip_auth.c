/*
 ** Copyright(C) 2004 INL
 ** Written by Eric Leblond <regit@inl.fr>
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
 * check given ip for ip authentication.
 *
 * Use module to check if we can found the user logged on ip. 
 *
 * Algorithm :
 *  - Send request to module provided function
 *  - if a username is returned
 *    - get groups for user
 *    - build corresponding connection structure
 *    - feed search_and_fill with it
 *  - else free header (userdata)
 * 
 */
void external_ip_auth(gpointer userdata, gpointer data)
{
        char* username=NULL;
        
        block_on_conf_reload();
        username=ip_auth(userdata);
        if (username){
            GSList* groups=NULL;
	    uint16_t uid;
            /**
	     * \todo 
             *  switch to a list of modules
             *  set a cache for such query 
             */
            /* get groups by calling user_check module with a empty password */
	     
            if(user_check(username,NULL,0,&uid,&groups)!=SASL_OK)
                  groups=NULL;
            /* if search succeed process to packet transmission */
            if (groups){
                connection_t* connection=g_new0(connection_t,1);
                connection->state=STATE_USERPCKT;
                connection->user_groups=groups;
		connection->user_id=uid;
                connection->username=username;
                connection->sysname=NULL;
                connection->appname=NULL;
                /* copy ipv4 header */
                memcpy(&(connection->tracking_hdrs),userdata,sizeof(tracking));
		g_async_queue_push (nuauthdatas->connections_queue,connection);
            } 
        } 
        g_free(userdata);
}

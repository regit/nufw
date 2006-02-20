/*
 ** Copyright(C) 2005 INL
 **             written by Eric Leblond <regit@inl.fr>
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

static gboolean get_nufw_server_by_addr(gpointer key,gpointer value,gpointer user_data)
{
  if ( (((nufw_session*)value)->peername).s_addr 
                  == 
                  ((struct in_addr*)user_data)->s_addr ){
      return TRUE;
  } else {
      return FALSE;
  }
}

static void send_conntrack_message(struct limited_connection * lconn,unsigned char msgtype)
{
  nufw_session* session=NULL;
  g_mutex_lock(nufw_servers_mutex);
  if (nufw_servers){
      session = g_hash_table_find (nufw_servers,
              get_nufw_server_by_addr,
              &(lconn->gwaddr));
      g_mutex_unlock(nufw_servers_mutex);
      if (session){
          struct nuv2_conntrack_message message;
          /* send message */
          message.protocol=1;
          message.type=msgtype;
          if (lconn->expire != -1) {
              message.timeout=htonl(lconn->expire-time(NULL));
          } else {
              message.timeout=0;
          }
          message.ipproto=lconn->tracking_hdrs.protocol;
          message.src=htonl(lconn->tracking_hdrs.saddr);
          message.dst=htonl(lconn->tracking_hdrs.daddr);
          if (message.ipproto == IPPROTO_ICMP){
              message.sport=lconn->tracking_hdrs.type;
              message.dport=lconn->tracking_hdrs.code;
          } else {
              message.sport=htons(lconn->tracking_hdrs.source);
              message.dport=htons(lconn->tracking_hdrs.dest);
          }
          gnutls_record_send(
                  *(session->tls) ,
                  &message,
                  sizeof(struct nuv2_conntrack_message)
                  );
      } else {
          if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_USER)){
              g_message("correct session not found among nufw servers");
          }
      }
  } else {
      g_mutex_unlock(nufw_servers_mutex);
  }
}

void  send_destroy_message_and_free(gpointer user_data)
{
  struct limited_connection* data=(struct limited_connection*)user_data;
#ifdef DEBUG_ENABLE
      if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER)){
          g_message("connection will be destroyed");
      }
#endif
  /* look for corresponding nufw tls session */
  send_conntrack_message(data,AUTH_CONN_DESTROY);
  /* free */
  g_free(data);
}

/** 
 * get old entry
 */

static gboolean get_old_entry(gpointer key,gpointer value,gpointer user_data)
{
  if (((struct limited_connection *)value)->expire < GPOINTER_TO_UINT(user_data)){
#ifdef DEBUG_ENABLE
      if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER)){
          g_message("found connection to be destroyed");
      }
#endif

      return TRUE;
  } else {
      return FALSE;
  }
}

/** 
 * search and destroy expired connections 
 */

void destroy_expired_connection(GHashTable* conn_list)
{

  g_hash_table_foreach_remove     (conn_list,
                  get_old_entry,
                  GUINT_TO_POINTER(time(NULL)));
}



/**
 * thread waiting for message
 *
 * only thread to be able to access to list of connections
 * to expire
 */

void* limited_connection_handler()
{
  GHashTable* conn_list;
  struct internal_message *message=NULL;

  nuauthdatas->limited_connections_queue = g_async_queue_new();
  /* initialize packets list */
  conn_list = g_hash_table_new_full ((GHashFunc)hash_connection,
                  compare_connection,
                  NULL,
                  (GDestroyNotify) send_destroy_message_and_free); 

  g_async_queue_ref (nuauthdatas->limited_connections_queue);
  /* wait for message */
  while ( (message = g_async_queue_pop(nuauthdatas->limited_connections_queue)) ) {
      switch (message->type) {
        case INSERT_MESSAGE:
                g_hash_table_insert(conn_list,&(((struct limited_connection*)message->datas)->tracking_hdrs),message->datas);
                break;
        case REFRESH_MESSAGE:
#ifdef DEBUG_ENABLE
#if 0
                if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER)){
                    g_message("expire conn list size : %d",g_hash_table_size (conn_list));
                }
#endif
#endif
                destroy_expired_connection(conn_list);
                break;
        case FREE_MESSAGE:
                {
                    struct limited_connection* elt=(struct limited_connection*)g_hash_table_lookup(conn_list,message->datas);
                    if (elt){
                        elt->expire=0;
                        g_hash_table_remove(conn_list,message->datas);
                    } 
#ifdef DEBUG_ENABLE
                    else {
                        if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER)){
                            g_message("connection not found can not be destroyed");
                        }
                    }
#endif
                    g_free(message->datas);
                }
                break;
                /** here we get message from nufw kernel connection is ASSURED 
                 * we have to limit it if needed and log the state change if needed */
        case UPDATE_MESSAGE:
                {
                        struct limited_connection* elt=(struct limited_connection*)g_hash_table_lookup(conn_list,message->datas);
                        if (elt == NULL){
                                /* TODO need only to log */
                        } else {
                                send_conntrack_message(elt,AUTH_CONN_UPDATE);
                        }
                }
      }
      g_free(message);

  }
  return NULL;
}

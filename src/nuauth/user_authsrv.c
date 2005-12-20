/*
 * Copyright(C) 2004-2005 INL http://www.inl.fr/
 ** written by  Eric Leblond <regit@inl.fr>
 **             Vincent Deffontaines <vincent@inl.fr>
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

#define _GNU_SOURCE
#include <auth_srv.h>
#include <crypt.h>
#include <sys/time.h>
#include <sasl/saslutil.h>


static GSList * userpckt_decode(struct buffer_read * datas);

/**
 * get user datas (containing datagram) and goes till inclusion (or decision) on packet.
 *
 * - Argument 1 : datagram
 * - Argument 2 : unused
 * - Return : None
 */

void user_check_and_decide (gpointer userdata, gpointer data)
{
  GSList * conn_elts=NULL;
  GSList* conn_elt_l;
  connection* conn_elt;
#ifdef DEBUG_ENABLE
  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
      g_message("entering user_check\n");
#endif
  /* reload condition */
  block_on_conf_reload();
  conn_elts = userpckt_decode(userdata);
  /* if OK search and fill */
  if ( conn_elts != NULL ) {
      for (conn_elt_l=conn_elts;conn_elt_l!=NULL;conn_elt_l=conn_elt_l->next){
          conn_elt=conn_elt_l->data;
#ifdef DEBUG_ENABLE
          if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_PACKET)){
              g_message("User : %s",conn_elt->username);
              print_connection(conn_elt,NULL);
          }
#endif
          if (conn_elt->packet_id){
              struct internal_message *message = g_new0(struct internal_message,1);
              message->type=INSERT_MESSAGE;
              message->datas=conn_elt;
              g_async_queue_push (nuauthdatas->localid_auth_queue,message);
          } else {
              g_async_queue_push (nuauthdatas->connexions_queue,conn_elt);
          }
      }
  }
  else {
      if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER)){
          g_message("User packet decoding failed\n");
      }
  }
          /* free userdata, packet is parsed now */
          g_free(((struct buffer_read *)userdata)->buf);
          g_free(((struct buffer_read *)userdata)->userid);
          g_free(((struct buffer_read *)userdata)->sysname);
          g_free(((struct buffer_read *)userdata)->release);
          g_free(((struct buffer_read *)userdata)->version);
          g_slist_free(((struct buffer_read *)userdata)->groups);
          g_free(userdata);

#ifdef DEBUG_ENABLE
  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
      g_message("leaving user_check\n");
#endif
}

/**
 *decode user dgram packet and fill a connection with datas.
 *
 * - Argument 1 : datagram
 * - Argument 2 : size of datagram
 * - Return : pointer to newly allocated connection
 */

static GSList * userpckt_decode(struct buffer_read * datas)
{
  char * dgram = datas->buf;
  connection* connexion=NULL;
  struct nuv2_header* header=(struct nuv2_header*)dgram;
  gboolean multiclient_ok=FALSE;
  GSList* conn_elts=NULL;


  /* decode dgram */
  switch (header->proto) {
    case 0x2:
      {
#ifdef WORDS_BIGENDIAN	
          header->length=swap16(header->length);
#endif
          if(header->length>BUFSIZE){
              if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_USER))
                  g_message("Improper length signaled in packet header");
              free_buffer_read(datas);
              return NULL;

          }
          switch (header->msg_type){
            case USER_REQUEST :
              { 
                  char* start=dgram+4;
          
                  while (start<dgram+header->length){
                      struct nuv2_authreq* authreq=(struct nuv2_authreq* )start;
                      char *req_start=start;

                      connexion = g_new0( connection,1);
                      connexion->acl_groups=NULL;
                      connexion->user_groups=NULL;
                      connexion->appname=NULL;
                      connexion->appmd5=NULL;
                      connexion->username=NULL;
                      connexion->cacheduserdatas=NULL;
                      connexion->packet_id=NULL;


                      req_start+=4;

#ifdef WORDS_BIGENDIAN	
                      authreq->packet_length=swap16(authreq->packet_length);
#endif
                      if((start+authreq->packet_length>
                            dgram+header->length) || (authreq->packet_length == 0)){
                          if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_USER))
                              g_message("Improper length signaled in authreq header : %d",authreq->packet_length);
                          free_connection(connexion);
                          free_buffer_read(datas);
                          return NULL;

                      }

#ifdef DEBUG_ENABLE
                      if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
                          g_message("Authreq start");
#endif

                      while(req_start-start<authreq->packet_length){
                          struct nuv2_authfield* field=(struct nuv2_authfield* )req_start;

#ifdef WORDS_BIGENDIAN	
                          field->length=swap16(field->length);
#endif
                          if( (req_start+field->length >
                                start+authreq->packet_length) || (field->length == 0)){
                              if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_USER))
                                  g_message("Improper field length signaled : %d",field->length);
                              free_connection(connexion);
                              free_buffer_read(datas);
                              return NULL;
                          }


                          switch (field->type) {
                            case IPV4_FIELD:
                              {
                                  struct nuv2_authfield_ipv4 * ipfield=(struct nuv2_authfield_ipv4 * )req_start; 


#ifdef WORDS_BIGENDIAN	
                                  connexion->tracking_hdrs.saddr=swap32(ipfield->src);
                                  connexion->tracking_hdrs.daddr=swap32(ipfield->dst);
#else
                                  connexion->tracking_hdrs.saddr=ipfield->src;
                                  connexion->tracking_hdrs.daddr=ipfield->dst;
#endif
                                  connexion->tracking_hdrs.protocol=ipfield->proto;

#ifdef DEBUG_ENABLE
                                  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
                                      g_message("\tgot IPV4 field");
#endif
                                  switch (connexion->tracking_hdrs.protocol) {
                                    case IPPROTO_TCP:

#ifdef WORDS_BIGENDIAN	
                                      connexion->tracking_hdrs.source=swap16(ipfield->sport);
                                      connexion->tracking_hdrs.dest=swap16(ipfield->dport);
#else
                                      connexion->tracking_hdrs.source=ipfield->sport;
                                      connexion->tracking_hdrs.dest=ipfield->dport;
#endif
                                      connexion->tracking_hdrs.type=0;
                                      connexion->tracking_hdrs.code=0;
                                      break;
                                    case IPPROTO_UDP:
#ifdef WORDS_BIGENDIAN	
                                      connexion->tracking_hdrs.source=swap16(ipfield->sport);
                                      connexion->tracking_hdrs.dest=swap16(ipfield->dport);
#else
                                      connexion->tracking_hdrs.source=ipfield->sport;
                                      connexion->tracking_hdrs.dest=ipfield->dport;
#endif

                                      connexion->tracking_hdrs.type=0;
                                      connexion->tracking_hdrs.code=0;
                                      break;
                                    case IPPROTO_ICMP:
                                      connexion->tracking_hdrs.source=0;
                                      connexion->tracking_hdrs.dest=0;
                                      connexion->tracking_hdrs.type=ipfield->sport;
                                      connexion->tracking_hdrs.code=ipfield->dport;
                                      break;
                                  }
                              }
                              break;
                            case APP_FIELD:
                              {
                                  struct nuv2_authfield_app * appfield=(struct nuv2_authfield_app* )req_start; 
#ifdef DEBUG_ENABLE
                                  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
                                      g_message("\tgot APP field");
#endif
                                  switch (appfield->option) {
                                    default:
                                      {
                                          unsigned int reallen=0;
                                          gchar* dec_appname=NULL;
#ifdef WORDS_BIGENDIAN	
                                          unsigned int len;
                                          //appfield->length=swap16(appfield->length);
                                          len=appfield->length-4;

#else
                                          unsigned int len=appfield->length-4;
#endif
                                          /* this has to be smaller than field size */
                                          if(appfield->length >
                                              authreq->packet_length+start-req_start){
                                              if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_USER))
                                                  g_message("Improper application field length signaled in authreq header");
                                              free_connection(connexion);
                                              free_buffer_read(datas);
                                              return NULL;

                                          }

                                          if (8*len > 2048){
                                              /* it is reaaally long, we ignore packet (too lasy to kill client) */
                                              if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER))
                                                  g_warning("user packet announced a too long app name\n");
                                              free_connection(connexion);
                                              free_buffer_read(datas);
                                              return NULL;
                                          }
                                          dec_appname =	g_new0(gchar,8*len);
                                          if (sasl_decode64((char*)appfield+4,len, dec_appname,8*len,&reallen) 
                                              ==
                                              SASL_BUFOVER) {
                                              dec_appname=g_try_realloc(dec_appname,reallen+1);
                                              if (dec_appname)
                                                  sasl_decode64((char*)appfield+4,len, dec_appname,reallen,&reallen) ;
                                          } else {
                                              dec_appname=g_try_realloc(dec_appname,reallen+1);
                                          }
                                          dec_appname[reallen]=0;

                                          if (dec_appname != NULL)
                                          {
                                              connexion->appname= string_escape(dec_appname);
                                              if (connexion->appname == NULL)
                                                  if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_USER))
                                                      g_warning("user packet received an invalid app name\n");
                                          }else{
                                              connexion->appname=NULL;
                                          }
                                          g_free(dec_appname);
                                          connexion->appmd5=NULL;

                                      }

                                  }
                              }
                              break;
                            case USERNAME_FIELD:
                              {
                                  struct nuv2_authfield_username * usernamefield=(struct nuv2_authfield_username* )req_start; 
#ifdef DEBUG_ENABLE
                                  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
                                      g_message("\tgot Username field");
#endif
                                  if (header->option == 0x1) {
                                      switch (usernamefield->option) {
                                        default:
                                          {
                                              unsigned int reallen=0;
                                              gchar* dec_fieldname=NULL;

#ifdef WORDS_BIGENDIAN	
                                              unsigned int len;
                                              usernamefield->length=swap16(usernamefield->length);
                                              len=usernamefield->length-4;
#else
                                              unsigned int len=usernamefield->length-4;
#endif
                                              if (8*len > 2048){
                                                  /* it is reaaally long, we ignore packet (too lasy to kill client) */
                                                  if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER))
                                                      g_warning("user packet announced a too long user name\n");
                                                  free_connection(connexion);
                                                  free_buffer_read(datas);
                                                  return NULL;
                                              }
                                              dec_fieldname =	g_new0(gchar,8*len);
                                              if (sasl_decode64((char*)usernamefield+4,len, dec_fieldname,8*len,&reallen) 
                                                  ==
                                                  SASL_BUFOVER) {
                                                  dec_fieldname=g_try_realloc(dec_fieldname,reallen+1);
                                                  if (dec_fieldname)
                                                      sasl_decode64((char*)usernamefield+4,len, dec_fieldname,reallen,&reallen) ;
                                              } else {
                                                  dec_fieldname=g_try_realloc(dec_fieldname,reallen+1);
                                              }
                                              dec_fieldname[reallen]=0;

                                              if (dec_fieldname != NULL)
                                              {
                                                  connexion->username= string_escape(dec_fieldname);
                                                  if (connexion->username == NULL)
                                                      if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_USER))
                                                          g_warning("user packet received an invalid username\n");
                                              }else {
                                                  g_free(dec_fieldname);
                                                  free_connection(connexion);
                                                  if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER)){
                                                      g_message("rejected packet, invalid username field");
                                                  }
                                                  free_buffer_read(datas);
                                                  return NULL;
                                              }
                                              g_free(dec_fieldname);
                                          }
                                      }
                                      multiclient_ok=TRUE;
                                  } else {
                                      /* should not be here */
                                      free_connection(connexion);
                                      if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER)){
                                          g_message("not multiuser client but sent username field");
                                      }
                                      free_buffer_read(datas);
                                      return NULL;
                                  }

                              }
                              break;
                            case HELLO_FIELD:
                              {
                                  struct nuv2_authfield_hello* hellofield = (struct nuv2_authfield_hello*)req_start;
                                  g_message("got hello field");
                                  connexion->packet_id=g_slist_prepend(NULL,GINT_TO_POINTER(hellofield->helloid));
                              }
                              break;
                            default:
                              if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER))
                                  g_message("unknown field type : %d",field->type);
                              free_connection(connexion);
                              free_buffer_read(datas);
                              return NULL;
                          }
                          req_start+=field->length;
                      }
                      /* here all packet related information are filled-in */
                      if (connexion->username == NULL){	
                          connexion->username=g_strdup(datas->userid);
                      }
                      connexion->user_id=datas->uid;
                      connexion->user_groups = g_slist_copy(datas->groups);
                      connexion->sysname=g_strdup(datas->sysname);
                      connexion->release=g_strdup(datas->release);
                      connexion->version=g_strdup(datas->version);
                      if (connexion->user_groups == NULL) {
                          if ((header->option == 0x1) && multiclient_ok) {
                              if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER))
                                  g_message("Get users info");
                              /* group is not fill in multi users mode
                               * need to be done now */
                              if ( nuauthconf->user_cache ){
                                  get_users_from_cache(connexion);
                              } else {
                                  if (user_check(connexion->username,NULL,0,&(connexion->user_id),&(connexion->user_groups))!=SASL_OK){
                                      if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_PACKET)){
                                          g_message("User not found");
                                      }

                                  }
                              }
                          } else {
                              if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER))
                                  g_message("User_check return is bad");
                              free_connection(connexion);
                              return NULL;
                          }
                      }
                      /* first reset timestamp to now */
                      connexion->timestamp=time(NULL);
                      connexion->state=STATE_USERPCKT;
                      /* acl part is NULL */
                      connexion->acl_groups=NULL;

                      conn_elts=g_slist_prepend(conn_elts,connexion);
#ifdef DEBUG_ENABLE
                                  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
                                      g_message("Authreq end");
#endif

                      start+=authreq->packet_length;
                  }
                  /* Tadaaa */
                  return conn_elts;
              }
              break;
            default:
              free_buffer_read(datas);
              if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER)){
                  g_message("unsupported message type");
              }
          }
      }
      return NULL;
    default:
      free_buffer_read(datas);
      if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER))
          g_message("unsupported protocol, got protocol %d (msg %d) with option %d (length %d)",header->proto,
              header->msg_type,header->option,header->length);
      return NULL;
  }
  return NULL;
}

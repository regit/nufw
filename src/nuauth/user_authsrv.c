
/*
** Copyright(C) 2003 Eric Leblond <eric@regit.org>
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

#define _GNU_SOURCE
#include <auth_srv.h>
#include <proto.h>
#include <crypt.h>

#if 0
struct up_datas {
  u_int32_t ip_client;
  char * dgram;
  };
#endif

void* user_authsrv(){
  int z;
  int sck_inet;
  struct sockaddr_in addr_inet,addr_clnt;
  int len_inet;
  char dgram[512];
#if 0
  struct up_datas userdatas;
#endif

  //open the socket
  sck_inet = socket (AF_INET,SOCK_DGRAM,0);

  if (sck_inet == -1)
  {
    g_error("socket()");
    exit(-1);
  }
	
  memset(&addr_inet,0,sizeof addr_inet);

  addr_inet.sin_family= AF_INET;
  addr_inet.sin_port=htons(userpckt_port);
  addr_inet.sin_addr.s_addr=INADDR_ANY;

  len_inet = sizeof addr_inet;

  z = bind (sck_inet,
	    (struct sockaddr *)&addr_inet,
	    len_inet);
  if (z == -1)
  {
    g_error ("user bind()");
    exit(-1);
  }

	
  for(;;){
    len_inet = sizeof addr_clnt;
    z = recvfrom(sck_inet,
		 dgram,
		 sizeof dgram,
		 0,
		 (struct sockaddr *)&addr_clnt,
		 &len_inet);
    if (z<0)
    {
      g_error("recvfrom()");
      exit(-1); /*useless*/
    }
#if 0
    /* prepare data */
    userdatas.dgram=dgram;
    userdatas.ip_client=addr_clnt.sin_addr.s_addr;
#endif
    /* send packet to thread */
    g_thread_pool_push (user_checkers,
		dgram,	
			NULL
			);
  }
  close(sck_inet);

  return NULL;
}

void user_check_and_decide (gpointer userdata, gpointer data){
  connection * conn_elt=NULL;
  connection * element;


  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
    g_message("entering user_check\n");
  conn_elt = userpckt_decode((char *)userdata, 
			     512);
  /* if OK search and fill */
  if ( conn_elt != NULL ) {
    element = search_and_fill (conn_elt);
    if ( element != NULL ) {
      LOCK_CONN(element);
      if ( element == NULL ) {
	return;
      }
      /* check state of the packet */
      if ( ((connection *)element)->state >= STATE_READY ){
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
	  g_message("trying to decide after userpckt\n"); 
	take_decision(element);
      } else {
	UNLOCK_CONN(element);
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
	  g_message("User packet before auth packet\n");
      }
    } else {
      if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_USER))
	g_message("Unwanted user packet\n");
    }
  } else {
    if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_USER))
      g_message("User packet decoding failed\n");
  }

  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER))
   g_message("leaving user_check\n");
}

connection * userpckt_decode(char* dgram,int dgramsiz){
  u_int16_t userid;
  long u_packet_id;
  char *pointer;
  connection* connexion;
  char passwd[128];
  char md5datas[512];
  char *usermd5datas;
  struct in_addr oneip;
  char onaip[16];
  char *result;
  u_int16_t firstf,lastf;
  struct crypt_data * crypt_internal_datas=g_private_get (crypt_priv);
  /* decode dgram */
  switch (*dgram) {
  case 0x1:
    if ( *(dgram+1) == USER_REQUEST) {
      /* allocate connection */
      connexion = g_new0( connection,1);
      if (connexion == NULL){
	if (DEBUG_OR_NOT(DEBUG_LEVEL_MESSAGE,DEBUG_AREA_USER)){
	  g_message("Can not allocate connexion\n");
	}
	return NULL;
      }
      /* parse packet */
      pointer=dgram+2;
      userid=*(u_int16_t *)(pointer);
      pointer+=sizeof (u_int16_t);
      connexion->tracking_hdrs.saddr=(*(u_int32_t * )(pointer));
#if 0
      if ( connexion->tracking_hdrs.saddr != ntohl(addr_clnt) ){
	g_warning("client addr (%lu) != source addr (%lu) !\n",connexion->tracking_hdrs.saddr, addr_clnt);
	return NULL;
      } 
#endif
      pointer+=sizeof (u_int32_t);
      connexion->tracking_hdrs.daddr=(*(u_int32_t * )(pointer));
      pointer+=sizeof (u_int32_t);
      connexion->tracking_hdrs.protocol=*(u_int8_t *)(pointer);
      pointer+= sizeof (u_int8_t);
      /* PROV : swap FLAGS as no client use it ...*/
      pointer+=3 * sizeof (u_int8_t);
      switch (connexion->tracking_hdrs.protocol) {
      case IPPROTO_TCP:
	connexion->tracking_hdrs.source=(*(u_int16_t *)pointer);
	pointer+=sizeof (u_int16_t);
	connexion->tracking_hdrs.dest=(*(u_int16_t *)pointer);
	pointer+=sizeof (u_int16_t);
	connexion->tracking_hdrs.type=0;
	connexion->tracking_hdrs.code=0;
	break;
      case IPPROTO_UDP:
	connexion->tracking_hdrs.source=(*(u_int16_t *)pointer);
	pointer+=sizeof (u_int16_t);
	connexion->tracking_hdrs.dest=(*(u_int16_t *)pointer);
	pointer+=sizeof (u_int16_t);
	connexion->tracking_hdrs.type=0;
	connexion->tracking_hdrs.code=0;
	break;
      case IPPROTO_ICMP:
	connexion->tracking_hdrs.source=0;
	connexion->tracking_hdrs.dest=0;
	connexion->tracking_hdrs.type=*(u_int8_t *)(pointer);
	pointer+=sizeof(u_int8_t);
	connexion->tracking_hdrs.code=*(u_int8_t *)(pointer);
	pointer+=3;
	break;
      }
      /* get timestamp */
      connexion->timestamp=*(long *)(pointer);
      pointer+=sizeof(long);
      /* get random number */
      u_packet_id=*(long *)(pointer);
      pointer+=sizeof(long);
      /* get user md5datas */
      usermd5datas=strndup(pointer,34);

      if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_USER)){
	  g_message("User "); 
	  print_connection(connexion,NULL);
	}

      /* get user datas : password, groups (filled in) */
      connexion->user_groups = (*module_user_check) (userid,passwd);
      if (connexion->user_groups == NULL) {
	if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_USER))
	  g_message("ldap_user_check return bad\n");
	free_connection(connexion);
	return NULL;
      }

      /*
       * check MD5 crypt 
       */
      
      /* construct md5datas */
      oneip.s_addr=htonl(connexion->tracking_hdrs.saddr);
      strncpy(onaip,inet_ntoa(oneip),16);
      oneip.s_addr=htonl(connexion->tracking_hdrs.daddr);

      if (connexion->tracking_hdrs.protocol != IPPROTO_ICMP) {
	firstf=connexion->tracking_hdrs.source;
	lastf=connexion->tracking_hdrs.dest;
      } else {
	firstf=connexion->tracking_hdrs.type;
	lastf=connexion->tracking_hdrs.code;
      }

      snprintf(md5datas,512,
	       "%s%u%s%u%ld%ld%s",
	       onaip,
	       firstf,
	       inet_ntoa(oneip),
	       lastf,
	       connexion->timestamp,
	       u_packet_id,
	       passwd);
     
      /* initialisation stuff */
      if (crypt_internal_datas == NULL){
	crypt_internal_datas=g_new0(struct crypt_data,1);
	g_private_set(crypt_priv,crypt_internal_datas);
	if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_USER))
	  g_message("Initiating crypt internal structure");
      }
      /* crypt datas */
      result = crypt_r(md5datas,usermd5datas,crypt_internal_datas);
      /* compare the two crypted datas */
      if ( strcmp (result, usermd5datas) != 0 ) {
	/* bad sig dropping user packet ! */
	if (DEBUG_OR_NOT(DEBUG_LEVEL_MESSAGE,DEBUG_AREA_USER))
	  g_message("wrong md5 sig for packet %s\n",usermd5datas);
	free(usermd5datas);
	free_connection(connexion);
	return NULL;
      } else {
	free(usermd5datas);
	/* 
	 * md5 done !
	 */

	 /* Is it a try to spoof MD5 ? */
	      
	/* set some default on connexion */
	if (check_fill_user_counters(userid,connexion->timestamp,u_packet_id,connexion->tracking_hdrs.saddr)){	
	  /* first reset timestamp to now */
	  connexion->timestamp=time(NULL);
	  connexion->state=STATE_USERPCKT;
	  /* acl part is NULL */
	  connexion->packet_id=NULL;
	  connexion->acl_groups=NULL;
	  /* Tadaaa */
	  return connexion;
	} else {
		if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_USER))
	  		g_message("non increasing counters for packet\n");
		free_connection(connexion);
		return NULL;
	}
      }
    }
  }
  /* FIXME : free dgram see over */
  return NULL;
}




  
  


/*
** Copyright(C) 2003 Eric Leblond <eric@regit.org>
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
#include <proto.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h> 

/* 
 * return offset to next type of headers 
 */
int get_ip_headers(connection *connexion,char * dgram){
  struct iphdr * iphdrs = (struct iphdr *) dgram;
  /* check IP version */
  if (iphdrs->version == 4){
    connexion->tracking_hdrs.saddr=htonl(iphdrs->saddr);
    connexion->tracking_hdrs.daddr=htonl(iphdrs->daddr);
    /* get protocol */
    connexion->tracking_hdrs.protocol=iphdrs->protocol;
    return 4*iphdrs->ihl;
  }
  return 0;
}

int get_udp_headers(connection *connexion, char * dgram){
  struct udphdr * udphdrs=(struct udphdr *)dgram;
  connexion->tracking_hdrs.source=htons(udphdrs->source);
  connexion->tracking_hdrs.dest=htons(udphdrs->dest);
  connexion->tracking_hdrs.type=0;
  connexion->tracking_hdrs.code=0;
  return 0;
}

int get_tcp_headers(connection *connexion, char * dgram){
  struct tcphdr * tcphdrs=(struct tcphdr *) dgram;
  connexion->tracking_hdrs.source=htons(tcphdrs->source);
  connexion->tracking_hdrs.dest=htons(tcphdrs->dest);
  connexion->tracking_hdrs.type=0;
  connexion->tracking_hdrs.code=0;
  /* test if fin ack or syn */
  /* if fin ack return 0 end of connection */
  if (tcphdrs->fin)
      return 0;
      /* if syn return 1 */
  if (tcphdrs->syn)
        return 1;
  return -1;
}

int get_icmp_headers(connection *connexion, char * dgram){
  struct icmphdr * icmphdrs= (struct icmphdr *)dgram;
   connexion->tracking_hdrs.source=0;
   connexion->tracking_hdrs.dest=0;
   connexion->tracking_hdrs.type=icmphdrs->type;
   connexion->tracking_hdrs.code=icmphdrs->code;
  return 0;
}

void* packet_authsrv(){
  int z;
  int sck_inet;
  struct sockaddr_in addr_inet,addr_clnt;
  int len_inet;
  char dgram[512];
  connection * current_conn;

  //open the socket
  sck_inet = socket (AF_INET,SOCK_DGRAM,0);

  if (sck_inet == -1)
  {
    g_error("socket()");
    exit (-1); /*useless*/
  }
	
  memset(&addr_inet,0,sizeof addr_inet);

  addr_inet.sin_family= AF_INET;
  addr_inet.sin_port=htons(authreq_port);
  addr_inet.sin_addr.s_addr=INADDR_ANY;

  len_inet = sizeof addr_inet;

  z = bind (sck_inet,
	    (struct sockaddr *)&addr_inet,
	    len_inet);
  if (z == -1)
  {
    g_error ("pckt bind()");
    exit (-1); /*useless*/
  }
  if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_PACKET)){
    g_message("Pckt Server Listening\n");
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
      exit (-1); /*useless*/
    }
    //	pckt_rx++;
    /* decode packet and create connection */
    current_conn = authpckt_decode(dgram, sizeof dgram);
    if (current_conn == NULL){
      if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_PACKET)){
	g_message("Can't parse packet, that's bad !\n");
      }
    } else {
      /* gonna feed the birds */
      current_conn->state = STATE_AUTHREQ;
      /* put gateway addr in struct */
      g_thread_pool_push (acl_checkers,
			  current_conn,
			  NULL);
    }
  }
  close(sck_inet);
}

/*
 * Treat a connection from insertion to decision 
 * Arg : a connection 
 * Return : 
 */

void acl_check_and_decide (gpointer userdata, gpointer data){
  connection * element;
  connection * conn_elt = userdata;

  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_PACKET))
    g_message("entering acl_check\n");
  if (conn_elt == NULL){
    if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_PACKET)){
      g_message("that's not good : elt is NULL\n");
    }
  } else {
    /* external check of acl */
    if (external_acl_groups(conn_elt)) {
      if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_PACKET)){
	g_message("Going to search entry\n");
      }
      /* search and fill */
      element = search_and_fill (conn_elt);
      if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_PACKET)){
	g_message("new entry at %p\n",element);
      }
      if (element != NULL) {
	LOCK_CONN(element);
	/* in case we get the lock but lock is on empty packet */
	if ( element == NULL ) return;
	/* search if ALL in acl group list 
       	* This is a answer speed against overhead in CPU
       	* because check is done twice (one looking for ALLGROUP one when packet is ready)
       	*/
      	take_decision(element);
      } else {
	if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_PACKET))
	  g_warning("Something Wrong : element is NULL\n");
      }
    } else {
      /* no acl found so packet has to be dropped */
      send_auth_response(GUINT_TO_POINTER(conn_elt->packet_id),NOK);
      /* if we don't wait for the user packet we free the connection */
      if (conn_elt->state == STATE_READY)
	free_connection(conn_elt);
      else
	change_state(conn_elt,STATE_DONE);
    }
  }
  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_PACKET))
    g_message("leaving acl_check\n");
}


connection*  authpckt_decode(char * dgram, int  dgramsiz){
  int offset; 
  char *pointer;
  connection*  connexion = NULL;

  switch (*dgram) {
  case 0x1:
    if ( *(dgram+1) == AUTH_REQUEST) {
      /* allocate connection */
      connexion = g_new0( connection,1);
      if (connexion == NULL){
	if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_PACKET)){
	  g_message("Can not allocate connexion\n");
	}
	return NULL;
      }
      /* parse packet */
      pointer=dgram+2;
      connexion->id_srv=*(u_int16_t *)(pointer);
      pointer+=2;
      connexion->packet_id=NULL;
      connexion->packet_id=g_slist_append(connexion->packet_id, GUINT_TO_POINTER(*(unsigned long * )pointer));
      if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_PACKET)) {
	g_message("Working on  %lu\n",(long unsigned int)GPOINTER_TO_UINT(connexion->packet_id->data));
      }
      pointer+=sizeof (unsigned long);
      connexion->timestamp=*( long * )(pointer);
      pointer+=sizeof ( long);
      /* get ip headers till tracking is filled */
      offset = get_ip_headers(connexion, pointer);
      if ( offset) {
	pointer+=offset;
	/* get saddr and daddr */
	switch (connexion->tracking_hdrs.protocol) {
	case IPPROTO_TCP:
          switch (get_tcp_headers(connexion, pointer)){
            case 1:
              break; 
            case 0:
	      (*module_user_logs)(connexion,0);
              break;
            case -1:
	         if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_PACKET))
	                  g_warning ("Can't parse TCP headers\n");
	        free_connection(connexion);
	        return NULL;
          }
	  break;
	case IPPROTO_UDP:
	  if ( get_udp_headers(connexion, pointer) ){
	    if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_PACKET))
	      g_warning ("Can't parse UDP headers\n");
	    free_connection(connexion);
	    return NULL;
	  }
	  break;
	case IPPROTO_ICMP:
	  if ( get_icmp_headers(connexion, pointer)){
	    if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_PACKET))
	      g_message ("Can't parse ICMP headers\n");
	    free_connection(connexion);
	    return NULL;
	  }
	  break;
	default:
	  free_connection(connexion);
	  return NULL;
	}
      }
      else {
	if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_PACKET))
	  g_message ("Can't parse IP headers\n");
	free_connection(connexion);
	return NULL;
      }
      connexion->user_groups = ALLGROUP;
      /* have look at timestamp */
      if ( connexion->timestamp == 0 ){
	      connexion->timestamp=time(NULL);
      }
      if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_PACKET)){
	      g_message("Packet : ");
	      print_connection(connexion,NULL);
      }
      return connexion;
    } else {
      if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_PACKET)) {
	g_message("Not for us\n");
      }
      
      return NULL;
    }
  }
  return NULL;
}


  


/*
** Copyright (C) 2002 by Eric Leblond <eric@regit.org>
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


/* TCP/IP function */
#if DEBUG
void convert_addr(long address){
    unsigned char bloc[4],i;
    for(i=0;i<4;i++){
        bloc[i]=address%256;
	address-=bloc[i];
        address/=256;
    }
    printf("%d.%d.%d.%d",bloc[0],bloc[1],bloc[2],bloc[3]);
}
#endif

/* IP header parser */
struct iphdr *  get_iphdr_t(char* payload){
  /* we should only put  the payload in the ipheader, offset is 0*/
  return (struct iphdr *) payload;
}
/* TCP header parser */
struct tcphdr * get_tcphdr_t(char* payload){
  /* shift from header length */
   return (struct tcphdr *) (payload+4*((struct ip *)payload)->ip_hl);
}
/* UDP header parser */
struct udphdr * get_udphdr_t(void* payload){
  /* shift from header length */
  return (struct udphdr *) (payload+4*((struct ip *)payload)->ip_hl);
}

/* ICMP header parser */
/* not for the moment, equality for everyone in face of the ping ;-)  */

/* transform ipq message in connection, auth part need to be filled  */

connection* ipq_packet_to_conn(ipq_packet_msg_t *msg){
  connection* packet;
  /* allocate struct */
  packet = (connection *) calloc ( 1 ,sizeof (connection) );
  if (packet == NULL)
    return NULL;
  /* copy fields from ipq_packet */
  packet->packet_id=msg->packet_id;
  packet->timestamp_sec=msg->timestamp_sec;             
  packet->timestamp_usec=msg->timestamp_usec;   
  /* Only IPV4 by netfilter*/
  packet->headers.ip_hdr=get_iphdr_t(msg->payload);  
  /* for each supported protocol */
  if (packet->headers.ip_hdr->version == 4) {
   
#if DEBUG
    printf ("it's IP ");
    printf("source ");
    convert_addr((packet->headers.ip_hdr)->saddr);
    printf(" dest ");
    convert_addr((packet->headers.ip_hdr)->daddr);
    printf("\n");
#endif
    switch ((packet->headers.ip_hdr)->protocol){
    case IPPROTO_TCP : 
      packet->headers.tcp_hdr=get_tcphdr_t(msg->payload);
      packet->headers.udp_hdr=NULL;
#if DEBUG
      printf ("it's TCP  : sport %d dport %d\n",ntohs((packet->headers.tcp_hdr)->source), ntohs((packet->headers.tcp_hdr)->dest));
#endif
      break;
    case IPPROTO_UDP : 
      packet->headers.udp_hdr=get_udphdr_t(msg->payload);
      packet->headers.tcp_hdr=NULL;
#if DEBUG
     printf ("it's UDP  : sport %d dport %d\n",ntohs((packet->headers.udp_hdr)->source), ntohs((packet->headers.udp_hdr)->dest));
#endif
     break;
    }
  }
  return packet;
}


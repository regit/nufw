/* $Id: packetsrv.c,v 1.1 2003/09/15 22:20:29 gryzor Exp $ */

/*
** Copyright (C) 2002 Eric Leblond <eric@regit.org>
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

#include <string.h>
#include <structure.h>


void* packetsrv(){
  unsigned char buffer[BUFSIZ];
  int size;
  unsigned long pcktid;
  ipq_packet_msg_t *msg_p = NULL ;

 
  for (;;){
    //printf ("Waiting packet !\n");
    size = ipq_read(hndl,buffer,sizeof(buffer),0);
    
    if (size != -1){
      //  printf("packetsrv at work\n");
      if (size < BUFSIZ ){
	if (ipq_message_type(buffer) == NLMSG_ERROR ){
#if DEBUG
	  printf("Got error message\n");
#endif 
	} else {
	  if ( ipq_message_type (buffer) == IPQM_PACKET ) {
	    pckt_rx++ ;
	    //printf("Working on IP packet\n");
	    msg_p = ipq_get_packet(buffer);
	    /* lock packet list mutex */
	    pthread_mutex_lock(&packets_list_mutex);
	    /* Adding packet to list  */
	    pcktid=padd(msg_p->packet_id,msg_p->timestamp_sec);
	    /* unlock datas */
	    pthread_mutex_unlock(&packets_list_mutex);
	    if (pcktid && (msg_p->packet_id != pcktid)){
	      IPQ_SET_VERDICT( msg_p->packet_id, NF_DROP);
	    }
	    /* send an auth request packet */
	    auth_request_send(msg_p->packet_id,msg_p->payload,msg_p->data_len,msg_p->timestamp_sec);
	  } else {
#if DEBUG
	    printf ("non IP packet Dropping");
#endif
	    IPQ_SET_VERDICT(msg_p->packet_id, NF_DROP);
	  }
	}
      }
    } else {
#if DEBUG
      printf("BUFSIZ too small, size = %d\n",size);
#endif
    }
  }
  ipq_destroy_handle( hndl );  
}   

int auth_request_send(unsigned long packet_id,char* payload,int data_len,long timestamp){
  char datas[512];
  char *pointer;
  int auth_len,total_data_len=512;
  uint8_t version=PROTO_VERSION,type=AUTH_REQUEST;
  
  memset(datas,0,sizeof datas);
  memcpy(datas,&version,sizeof version);
  pointer=datas+sizeof version;
  memcpy(pointer,&type,sizeof type);
  pointer+=sizeof type;
  memcpy(pointer,&id_srv,sizeof id_srv);
  pointer+=sizeof id_srv;
  memcpy(pointer,&packet_id,sizeof packet_id);
  pointer+=sizeof packet_id;
  memcpy(pointer,&timestamp,sizeof timestamp);
  pointer+=sizeof timestamp;
  auth_len=pointer-datas;
  if ( ((struct iphdr *)payload)->version == 4) {
    
    /* memcpy header to datas + offset */
    if (data_len<512-auth_len) {
      memcpy(pointer,payload,data_len);
      total_data_len=data_len+auth_len;
    } else {
      printf("Very long packet : truncating !\n");
      memcpy(pointer,payload,511-auth_len);
    }

  } else {
    printf ("NON IP packet dropping\n");
  }
  
  if (debug){
    printf("Sending request for %lu\n",packet_id);
  }
  if (sendto(sck_auth_request,
	     datas,
	     total_data_len,
	     0,
	     (struct sockaddr *)&adr_srv,
	     sizeof adr_srv) < 0)
    printf ("failure when sending\n");
  return 1;
}

/* $Id: packetsrv.c,v 1.8 2003/12/23 15:58:44 uid68721 Exp $ */

/*
** Copyright (C) 2002-2003 Eric Leblond <eric@regit.org>
**		      Vincent Deffontaines <vincent@gryzor.com>
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
#include <debug.h>

/* 
 * return offset to next type of headers 
 */
int look_for_flags(char* dgram){
  struct iphdr * iphdrs = (struct iphdr *) dgram;
  /* check IP version */
  if (iphdrs->version == 4){
    if (iphdrs->protocol == IPPROTO_TCP){
      struct tcphdr * tcphdrs=(struct tcphdr *) (dgram+4*iphdrs->ihl);
      if (tcphdrs->fin || tcphdrs->ack || tcphdrs->rst ){
	return 1;
      }
    }
  }
  return 0;
}

void* packetsrv(){
  unsigned char buffer[BUFSIZ];
  int size;
  unsigned long pcktid;
  ipq_packet_msg_t *msg_p = NULL ;
  packet_idl * current;
 
  for (;;){
    size = ipq_read(hndl,buffer,sizeof(buffer),0);
    if (size != -1){
      if (size < BUFSIZ ){
	if (ipq_message_type(buffer) == NLMSG_ERROR ){
          if (DEBUG_OR_NOT(DEBUG_LEVEL_MESSAGE,DEBUG_AREA_MAIN)){
            if (log_engine == LOG_TO_SYSLOG) {
              syslog(SYSLOG_FACILITY(DEBUG_LEVEL_MESSAGE),"Got error message");
            }else {
	      printf("[%i] Got error message\n",getpid());
	    }
	  }
	} else {
	  if ( ipq_message_type (buffer) == IPQM_PACKET ) {
	    pckt_rx++ ;
	    /* printf("Working on IP packet\n"); */
	    msg_p = ipq_get_packet(buffer);
	    /* need to parse to see if it's an end connection packet */
	    if (look_for_flags(msg_p->payload)){
	      auth_request_send(AUTH_CONTROL,msg_p->packet_id,msg_p->payload,msg_p->data_len,msg_p->timestamp_sec);
	      IPQ_SET_VERDICT( msg_p->packet_id,NF_ACCEPT);
	    } else {
	    current=calloc(1,sizeof( packet_idl));
	    if (current == NULL){
	      if (DEBUG_OR_NOT(DEBUG_LEVEL_MESSAGE,DEBUG_AREA_MAIN)){
		if (log_engine == LOG_TO_SYSLOG) {
		  syslog(SYSLOG_FACILITY(DEBUG_LEVEL_MESSAGE),"Can not allocate packet_id");
		} else {
		  printf("[%i] Can not allocate packet_id\n",getpid());
		} 
	      }
	      return 0;
	    }
	    current->id=msg_p->packet_id;
#ifdef HAVE_LIBIPQ_MARK
	    current->nfmark=msg_p->mark;
#endif
	    current->timestamp=msg_p->timestamp_sec;
	    /* lock packet list mutex */
	    pthread_mutex_lock(&packets_list_mutex);
	    /* Adding packet to list  */
	    pcktid=padd(current);
	    /* unlock datas */
	    pthread_mutex_unlock(&packets_list_mutex);

	    if (pcktid){
	    /* send an auth request packet */
	    auth_request_send(AUTH_REQUEST,msg_p->packet_id,msg_p->payload,msg_p->data_len,msg_p->timestamp_sec);
	    }
            }
          } else {
            if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
              if (log_engine == LOG_TO_SYSLOG) {
                syslog(SYSLOG_FACILITY(DEBUG_LEVEL_DEBUG),"non IP packet Dropping");
              }else {
	        printf ("[%i] non IP packet Dropping\n",getpid());
 	      }
	    }
	    IPQ_SET_VERDICT(msg_p->packet_id, NF_DROP);
	  }
	}
      }
    } else {
      if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
        if (log_engine == LOG_TO_SYSLOG) {
          syslog(SYSLOG_FACILITY(DEBUG_LEVEL_DEBUG),"BUFSIZ too small, size = %d",size);
        }else {
          printf("[%i] BUFSIZ too small, size = %d\n",getpid(),size);
        }
      }
    }
  }
  ipq_destroy_handle( hndl );  
}   

int auth_request_send(uint8_t type,unsigned long packet_id,char* payload,int data_len,long timestamp){
  char datas[512];
  char *pointer;
  int auth_len,total_data_len=512;
  uint8_t version=PROTO_VERSION;
  
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
      if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
        if (log_engine == LOG_TO_SYSLOG) {
          syslog(SYSLOG_FACILITY(DEBUG_LEVEL_DEBUG),"Very long packet : truncating !");
        }else {
          printf("[%i] Very long packet : truncating !\n",getpid());
	}
      }
      memcpy(pointer,payload,511-auth_len);
    }

  } else {

    if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
      if (log_engine == LOG_TO_SYSLOG) {
        syslog(SYSLOG_FACILITY(DEBUG_LEVEL_WARNING),"NON IP packet dropping");
      }else {
        printf ("[%i] NON IP packet dropping\n",getpid());
      }
    }
  }
  

  if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN)){
    if (log_engine == LOG_TO_SYSLOG) {
      syslog(SYSLOG_FACILITY(DEBUG_LEVEL_DEBUG),"Sending request for %lu",packet_id);
    }else {
      printf("[%i] Sending request for %lu\n",getpid(),packet_id);
    }
  }
  if (sendto(sck_auth_request,
	     datas,
	     total_data_len,
	     0,
	     (struct sockaddr *)&adr_srv,
	     sizeof adr_srv) < 0)

  if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
    if (log_engine == LOG_TO_SYSLOG) {
      syslog(SYSLOG_FACILITY(DEBUG_LEVEL_CRITICAL),"failure when sending");
    }else {
      printf ("[%i] failure when sending\n",getpid());
    }
  }
  return 1;
}

/*
** Copyright (C) 2002, Éric Leblond <eric@regit.org>
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <decode.h>
#include <structure.h>

static void 
bail (const char *on_what){
  perror(on_what);
  exit(1);
}

int main(){
  int z;
  int sck_inet;
  struct sockaddr_in addr_inet,addr_clnt;
  int len_inet;
  char dgram[512];

 /* create socket for sending auth request */
    sck_auth_request = socket (AF_INET,SOCK_DGRAM,0);
    
  adr_srv.sin_family= AF_INET;
  adr_srv.sin_port=htons(AUTHSRV_PORT);
  adr_srv.sin_addr.s_addr=inet_addr("192.168.1.1");
  
  if (adr_srv.sin_addr.s_addr == INADDR_NONE )
    printf("Bad Address.");

  //open the socket
  sck_inet = socket (AF_INET,SOCK_DGRAM,0);

  if (sck_inet == -1)
    bail("socket()"); 
	
  memset(&addr_inet,0,sizeof addr_inet);

  addr_inet.sin_family= AF_INET;
  addr_inet.sin_port=htons(AUTHREQ_PORT);
  addr_inet.sin_addr.s_addr=INADDR_ANY;

  len_inet = sizeof addr_inet;

  z = bind (sck_inet,
	    (struct sockaddr *)&addr_inet,
	    len_inet);
  if (z == -1)
    bail ("bind()");

	
  for(;;){
    len_inet = sizeof addr_clnt;
    z = recvfrom(sck_inet,
		 dgram,
		 sizeof dgram,
		 0,
		 (struct sockaddr *)&addr_clnt,
		 &len_inet);
    if (z<0)
      bail("recvfrom()");
    // decode packet
    auth_packet_to_decision(dgram,sizeof dgram);
  }
  close(sck_inet);

  return 1;
}

int auth_packet_to_decision(char* dgram,int dgramsize){
  unsigned long packet_id;
  uint8_t answer=OK;
  uint8_t prio=1;
  uint8_t version=PROTO_VERSION,type=AUTH_ANSWER;
  char datas[512];
  int total_data_len=12;
  char *pointer;

  switch (*dgram) {
  case 0x1:
    if ( *(dgram+1) == AUTH_REQUEST) {
      packet_id=*(unsigned long * )(dgram+4);
#if DEBUG
      printf("That's our job, authorizing  %lu\n",packet_id);
#endif
      memset(datas,0,sizeof datas);
      memcpy(datas,&version,sizeof version);
      pointer=datas+sizeof version;
      memcpy(pointer,&type,sizeof type);
      pointer+=sizeof type;
      /* TODO id authsrv */
      pointer+=2;
      /* ANSWER and Prio */
      memcpy(pointer,&answer,sizeof answer);
      pointer+=sizeof answer;
      memcpy(pointer,&prio,sizeof prio);
      pointer+=sizeof prio;
      /* TODO id gw */
      pointer+=2;
      /* packet_id */
      memcpy(pointer,&packet_id,sizeof packet_id);
      pointer+=sizeof packet_id;
    } else {
#if DEBUG
      printf("Not for us\n");
      break;
#endif
    }
#if DEBUG
    printf("Sending auth answer for %lu ... ", packet_id);
    fflush(stdout);
#endif
    if (sendto(sck_auth_request,
	       datas,
	       total_data_len,
	       0,
	       (struct sockaddr *)&adr_srv,
	       sizeof adr_srv) < 0)
      printf ("failure when sending\n");
#if DEBUG
    printf("done\n");
#endif
  }
return 1;
}



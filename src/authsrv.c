
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
#include <structure.h>


static void 
bail (const char *on_what){
  perror(on_what);
  exit(1);
}


void* authsrv(){
  int z;
  int sck_inet;
  struct sockaddr_in addr_inet,addr_clnt;
  int len_inet;
  char dgram[512];

  //open the socket
  sck_inet = socket (AF_INET,SOCK_DGRAM,0);

  if (sck_inet == -1)
    bail("socket()");
	
  memset(&addr_inet,0,sizeof addr_inet);

  addr_inet.sin_family= AF_INET;
  addr_inet.sin_port=htons(authsrv_port);
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
    //	pckt_rx++;
    // decode packet
    auth_packet_to_decision(dgram);
  }
  close(sck_inet);

  return NULL;
}


int auth_packet_to_decision(char* dgram){
  unsigned long packet_id;
  int sandf;
  switch (*dgram) {
  case 0x1:
    if ( *(dgram+1) == AUTH_ANSWER) {
      packet_id=*(unsigned long *)(dgram+8);
      /* lock mutex */
      pthread_mutex_lock(&packets_list_mutex);
      sandf=psearch_and_destroy (packet_id);
      pthread_mutex_unlock(&packets_list_mutex);
      if (sandf){
	if ( *(dgram+4) == OK ) {
	  /* TODO : test on return */
	  /*if (debug){
	    printf ("Accepting %lu\n",packet_id);
	  }
	  */
	  nufw_debug(1,1,"Accepting\n");
	  IPQ_SET_VERDICT(packet_id, NF_ACCEPT);
	  pckt_tx++;
	  return 1;
	} else {
	   if (debug){
	    printf ("Rejecting %lu\n",packet_id);
	  }
	  IPQ_SET_VERDICT(packet_id, NF_DROP);
	  return 0;
	}
      } else {
	if (debug) {
	  fprintf(stdout,"Packet without a known ID :-(\n");
	}
      }
    } else {
      if (debug) {
	fprintf(stdout,"Type %d for packet %lu (not for me)\n",*(dgram+1),*(unsigned long * )(dgram+4));
      }
    }
    break;
  }
  return 1;
}

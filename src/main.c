/* $Id: main.c,v 1.3 2003/09/07 14:03:21 regit Exp $ */

/*
** Copyright (C) 2002 Eric Leblond <eric@regit.org>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
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



#include <linux/netfilter.h>
#include <libipq/libipq.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netdb.h>
#include <structure.h>


int main(int argc,char * argv[]){
  pthread_t pckt_server,auth_server;
  struct hostent *authreq_srv;
  /* option */
  char * options_list = "DhVvl:d:p:t:T:";
  int option,daemonize = 0;
  int value;
  unsigned int ident_srv;
  char* version=VERSION;

  /* initialize variables */

  authreq_port = AUTHREQ_PORT;
  authsrv_port = AUTHSRV_PORT;
  packet_timeout = PACKET_TIMEOUT;
  track_size = TRACK_SIZE;
  id_srv = ID_SERVER;
  strncpy(authreq_addr,AUTHREQ_ADDR,HOSTNAME_SIZE);
  debug=DEBUG;
  pid_t pidf;

  /*parse options */
  while((option = getopt ( argc, argv, options_list)) != -1 ){
    switch (option){
    case 'V' :
      fprintf (stdout, "PACKAGE (version %s)\n",version);
      return 1;
    case 'D' :
      daemonize = 1;
      break;
    case 'v' :
      fprintf (stdout, "Debug should be On\n");
      debug=1;
      break;
      /* port we listen for auth answer */
    case 'l' :
      sscanf(optarg,"%d",&value);
      printf("Listen on UDP port %d\n",value);
      authsrv_port=value;
      break;
      /* destination port */
    case 'p' :
      sscanf(optarg,"%d",&value);
      printf("Auth request send to port %d\n",value);
      authreq_port=value;
      break;
      /* destination IP */
    case 'd' :
      strncpy(authreq_addr,optarg,HOSTNAME_SIZE);
      printf("Sending Auth request to %s\n",authreq_addr);
      break;
      /* packet timeout */
    case 't' :
      sscanf(optarg,"%d",&packet_timeout);
      break;
      /* max size of packet list */
    case 'T' :
      sscanf(optarg,"%d",&track_size);
      break;
    case 'I' :
      sscanf(optarg,"%ud",&ident_srv);
      id_srv=ident_srv;
      break;
    case 'h' :
      fprintf (stdout ,"PACKAGE [-hVv] [-l local_port] [-d remote_addr] [-p remote_port]  [-t packet_timeout] [-T track_size] [-I id_server]\n");
      return 1;
    }
  }

/* Daemon code */
if (daemonize == 1) {
  if ((pidf = fork()) < 0){
  	printf("Unable to fork\n");
	exit (-1);
  } else {
  	/* parent */
 	 if (pidf > 0) {
		exit(0);
	}
  }
}
  
  /* create socket for sending auth request */
  sck_auth_request = socket (AF_INET,SOCK_DGRAM,0);
    
  if (sck_auth_request == -1)
    printf("socket()");
     
  memset(&adr_srv,0,sizeof adr_srv);

  adr_srv.sin_family= AF_INET;
  adr_srv.sin_port=htons(authreq_port);
  /* hostname conversion */
  authreq_srv=gethostbyname(authreq_addr);
  adr_srv.sin_addr=*(struct in_addr *)authreq_srv->h_addr;

  if (adr_srv.sin_addr.s_addr == INADDR_NONE )
    fprintf(stdout,"Bad Address.");
    
  packets_list_start=NULL;
  packets_list_end=NULL;
  packets_list_length=0;
  /* initialize mutex */
  pthread_mutex_init(&packets_list_mutex ,NULL);

  /* init netlink connection */
  hndl = ipq_create_handle(0,PF_INET);
  if (hndl)
    ipq_set_mode(hndl, IPQ_COPY_PACKET,BUFSIZ);  
  else {
    fprintf (stderr,"Can not create ipq handle\n");
  }

  /* create thread for packet server */
  if (pthread_create(&pckt_server,NULL,packetsrv,NULL) == EAGAIN){
    exit(1);
  }
  /* create thread for auth server */
  if (pthread_create(&auth_server,NULL,authsrv,NULL) == EAGAIN){
    exit(1);
  }
    
  /* control stuff */
  pckt_tx=pckt_rx=0;
  for(;;){
     pthread_mutex_lock(&packets_list_mutex);
     clean_old_packets ();
     pthread_mutex_unlock(&packets_list_mutex);
    if (debug) {
      fprintf(stdout,"rx : %d, tx : %d, track_size : %d, start_list : %p\n",pckt_rx,pckt_tx,packets_list_length,packets_list_start);
    }
    sleep(5);	
  }
}

/* $Id: structure.h,v 1.6 2003/10/28 07:23:56 regit Exp $ */

/*
** Copyright (C) 2002, Éric Leblond <eric@regit.org>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; version 2 of the License.
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

#include <semaphore.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <libipq/libipq.h>
#include <linux/netfilter.h>
#include "config.h"

#include "proto.h"

#define DEBUG 0
#define AUTHREQ_ADDR   "192.168.1.1"
#define AUTHSRV_PORT 4128
#define AUTHREQ_PORT 4129
#define TRACK_SIZE 1000
#define ID_SERVER 12345
#define PACKET_TIMEOUT 15
#define PRIO 1
#define HOSTNAME_SIZE 128


char authreq_addr[HOSTNAME_SIZE];
u_int16_t authreq_port;
u_int16_t authsrv_port;
int packet_timeout;
int track_size;
u_int16_t id_srv;
int debug;
int nufw_set_mark;



/* Keep id of packets received */
/* TODO use a kind of HASH */
typedef struct Packet_Ids {
  unsigned long id;
  long timestamp;
#ifdef HAVE_LIBIPQ_MARK
  unsigned long nfmark;
#endif
  struct Packet_Ids * next;
} packet_idl;

packet_idl * packets_list_start;
packet_idl * packets_list_end;
int packets_list_length;
/* mutex relative to packet_list */
pthread_mutex_t packets_list_mutex;

/* ipq handler */
struct ipq_handle *hndl;
/* mutex */
pthread_mutex_t hndl_mutex;

/* do some define to add mutex usage */
#define	IPQ_SET_VERDICT(PACKETID, DECISION) ipq_set_verdict(hndl, PACKETID, DECISION,0,NULL)
#define	IPQ_SET_VWMARK(PACKETID, DECISION,NFMARK) ipq_set_vwmark(hndl, PACKETID, DECISION,NFMARK,0,NULL)


//global variable :
int pckt_tx,pckt_rx ;

/* socket number to send auth request */
int sck_auth_request;
struct sockaddr_in adr_srv;


/* 
 * all functions 
 */

// IP packet catcher

void* packetsrv();

// IP auth server

void* authsrv();

/* send an auth request packet given a payload (raw packet) */
int auth_request_send(unsigned long packet_id, char* payload,int data_len,long timestamp);
/* take decision given a auth answer packet payload */
int auth_packet_to_decision(char* dgram);


/* common */

unsigned long padd ( packet_idl * packet);
int psearch_and_destroy (unsigned long packet_id,unsigned long * mark);
int clean_old_packets ();

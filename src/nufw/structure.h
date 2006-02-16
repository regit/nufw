/* $Id: structure.h,v 1.8 2003/11/28 13:10:23 gryzor Exp $ */

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
#include <linux/netfilter.h>
#include <time.h>
#include "config.h"

#include "proto.h"

#define DEBUG 0
#define AUTHREQ_ADDR  "127.0.0.1"
#define LISTEN_ADDR   "127.0.0.1"
#define AUTHSRV_PORT 4128
#define AUTHREQ_PORT 4129
#define TRACK_SIZE 1000
#define ID_SERVER 12345
#define PACKET_TIMEOUT 15   /*!< Default value of ::packet_timeout */
#define PRIO 1
#define HOSTNAME_SIZE 256
#define FILENAME_SIZE 256
#define CERT_FILE
#define KEY_FILE


char *cert_file;
char *key_file;
char *ca_file;
char *nuauth_cert_dn;

char authreq_addr[HOSTNAME_SIZE];
char listen_addr[HOSTNAME_SIZE];
u_int16_t authreq_port;
u_int16_t authsrv_port;
int packet_timeout;   /*!< Number of second before a packet is dropped, default value: #PACKET_TIMEOUT */
int track_size;       /*!< Maximum size of the packet list (::packets_list), default value: #TRACK_SIZE */
u_int16_t id_srv;
int debug;
int nufw_set_mark;



/**
 * Keep id of received packets
 */
/* TODO use a kind of HASH */
typedef struct Packet_Ids {
  unsigned long id;
  long timestamp;
#if (HAVE_LIBIPQ_MARK || USE_NFQUEUE)
  unsigned long nfmark;
#endif
  struct Packet_Ids * next;
} packet_idl;

/***** Pack list ****/

struct packets_list_t 
{
  packet_idl * start;    /*!< Begin of the list (NULL if the list is empty) */
  packet_idl * end;      /*!< End of the list (NULL if the list is empty) */
  int length;            /*!< Length of the list */
  pthread_mutex_t mutex;
} packets_list;

#if USE_NFQUEUE
struct nfq_q_handle *hndl;
#else
/* ipq handler */
struct ipq_handle *hndl;
#endif

/* mutex */
pthread_mutex_t hndl_mutex;

/* do some define to add mutex usage */
#if USE_NFQUEUE
#define IPQ_SET_VERDICT(PACKETID, DECISION) \
    nfq_set_verdict(hndl, PACKETID, DECISION, 0 , NULL)
#define IPQ_SET_VWMARK(PACKETID, DECISION, NFMARK) \
    nfq_set_verdict_mark(hndl, PACKETID, DECISION, NFMARK, 0, NULL) 
#else
#define	IPQ_SET_VERDICT(PACKETID, DECISION) \
    ipq_set_verdict(hndl, PACKETID, DECISION,0,NULL)
#define	IPQ_SET_VWMARK(PACKETID, DECISION, NFMARK) \
    ipq_set_vwmark(hndl, PACKETID, DECISION, NFMARK,0,NULL)
#endif

int pckt_tx;   /*!< Number of transmitted packets since NuFW is running */
int pckt_rx;   /*!< Number of received packets since NuFW is running */


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

/** \file structure.h
 *  \brief Global variables with their default value
 *   
 * Global variables with their default value. Most important one is
 * the ::packets_list.
 */

#ifndef STRUCTURE_HEADER
#define STRUCTURE_HEADER

#ifndef NUFW_HEADER_H
#   error "include nufw.h instead of structure.h"
#endif

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

#define AUTHREQ_ADDR  "127.0.0.1" /*!< Default value of ::authreq_addr */
#define AUTHREQ_PORT 4129   /*!< Default value of  ::authreq_port */
#define TRACK_SIZE 1000     /*!< Default value of ::track_size */
#define PACKET_TIMEOUT 15   /*!< Default value of ::packet_timeout */
#define HOSTNAME_SIZE 256   /*!< Maximum size of hostnames (::authreq_addr) */
#define FILENAME_SIZE 256   /*!< Maximum length of filenames */

extern char *cert_file;   /*!< Certificatename used in TLS connection, default value: NULL */
extern char *key_file;  /*!< Key filename used in TLS connection, default value: NULL */
char *ca_file;   /*!< Trust filename used in TLS connection, default value: NULL */
char *nuauth_cert_dn;   /*!< NuAuth certificate filename, default value: NULL */

/*! IP or hostname of NuAuth server address (::adr_srv), default value: #AUTHREQ_ADDR */
char authreq_addr[HOSTNAME_SIZE];

/*! Port of NuAuth server address (::adr_srv), default value: #AUTHREQ_PORT */
u_int16_t authreq_port;

/*! Number of second before a packet is dropped, default value: #PACKET_TIMEOUT */
int packet_timeout;

/*! Maximum size of the packet list (::packets_list), default value: #TRACK_SIZE */
int track_size;

/*! If equals to 1, set mark on packet using #IPQ_SET_VWMARK. Default value: 0 */
int nufw_set_mark;

/**
 * Informations about one packet: unique identifier in netfilter queue,
 * timestamp (initialized by NuFW) and mark (if NuFW compiled with
 * mark support).
 */
/* TODO use a kind of HASH */
typedef struct Packet_Ids {
  /*! Unique identifier in netfilter queue, comes 
   * from nfq_get_msg_packet_hdr() */
  unsigned long id;

  /*! Timestamp in Epoch format, value comes from netfilter or time(NULL) */
  long timestamp;      
#ifdef PERF_DISPLAY_ENABLE
  struct timeval arrival_time;
#endif

#if (HAVE_LIBIPQ_MARK || USE_NFQUEUE)
  /*! Packet mark, comes from nfq_get_nfmark() */
  unsigned long nfmark;
#endif

  /*! Pointer to next packet entry in ::packets_list, 
   * set by padd() and psuppress() */
  struct Packet_Ids *next;
} packet_idl;

/***** Pack list ****/

/**
 * Packet list used to store packet until NuAuth answer.
 * clean_old_packets() and psearch_and_destroy() remove old packets (after 
 * ::packet_timeout secondes).
 */
struct packets_list_t 
{
  packet_idl * start;    /*!< Begin of the list (NULL if the list is empty) */
  packet_idl * end;      /*!< End of the list (NULL if the list is empty) */
  int length;            /*!< Length of the list */
  pthread_mutex_t mutex;
} packets_list;

/**
 * Store old signal handlers
 */
struct Signals
{
    struct sigaction old_sigterm_hdl;
    struct sigaction old_sigint_hdl;
};

#if USE_NFQUEUE
struct nfq_q_handle *hndl;
#else
/* ipq handler */
struct ipq_handle *hndl;
#endif

/**
 * All data of a thread (use for packetsrv()) 
 */
struct ThreadType
{
    pthread_t thread;
    pthread_mutex_t mutex;
};

/**
 * Structure to send arguments to the thread.
 */
struct ThreadArgument
{
    struct Thread *thread;
    int parent_pid;
};    

/* mutex */
pthread_mutex_t hndl_mutex;

/** \def IPQ_SET_VERDICT(PACKETID, DECISION)
 * Set decision (NF_ACCEPT or NF_DROP) of a packet. Call nfq_set_verdict() 
 * or ipq_set_verdict().
 */

/** \def IPQ_SET_VWMARK(PACKETID, DECISION, NFMARK)
 * Set decision (NF_ACCEPT or NF_DROP) of a packet and add a marker. Call
 * nfq_set_verdict_mark() or ipq_set_vwmark().
 */

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

#endif   /* ifndef STRUCTURE_HEADER */


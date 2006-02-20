#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "structure.h"
#include <signal.h>
#include <assert.h>
#include <strings.h>
#include <gnutls/gnutls.h>
#include <gcrypt.h>
#include <errno.h>
#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif
#include "log.h"
#include "security.h"

/** \file nufw.h
 *  \brief Common functions and variables to NuFW 
 *   
 * Some structures, functions, global variables and #define common to NuFW.
 */

#if USE_NFQUEUE
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>

/** Default value of ::nfqueue_num */
#define DEFAULT_NFQUEUE 0

/** Default value of ::handle_conntrack_event */
#define CONNTRACK_HANDLE_DEFAULT 0

/** NetFilter queue number, default value: #DEFAULT_NFQUEUE */
uint16_t nfqueue_num;
/** Netfilter queue handle */
struct nfq_handle *h;

#else

/* redhat like hack */
#ifdef HAVE_LIBIPQ_LIBIPQ_H 
#  include <libipq/libipq.h>
#else
#  ifdef HAVE_LIBIPQ_H
#    include <libipq.h>
#  else
#    error "libipq needed for NuFW compilation"
#  endif      /* ifdef HAVE_LIBIPQ_H */
#endif      /* ifdef HAVE_LIBIPQ_LIBIPQ_H  */            
#endif   /* if USE_NFQUEUE */

/* conntrack things */
#ifdef HAVE_LIBCONNTRACK
#  include <libnetfilter_conntrack/libnetfilter_conntrack.h>
   struct nfct_handle *cth;
   unsigned char handle_conntrack_event; 
   void* conntrack_event_handler(void *data);
#endif

/** Gryzor hacks with aims to answer ICMP message when a packet is dropped. */
#define GRYZOR_HACKS
#undef GRYZOR_HACKS

#ifdef GRYZOR_HACKS
#include <sys/socket.h>
#endif

/** If equals to 1, compile with x509 certificate support */
#define USE_X509 1

/** Default value, prefixed with CONFIG_DIR, of ::key_file */
#define KEYFILE "/nufw-key.pem"  

/** Default value, prefixed with CONFIG_DIR, of ::cert_file */
#define CERTFILE "/nufw-cert.pem"  

struct nuauth_conn {
        gnutls_session * session;
        pthread_mutex_t* mutex;
        unsigned char auth_server_running;
        pthread_t auth_server;
        pthread_t conntrack_event_handler;
};

struct nuauth_conn tls;

gnutls_session * tls_connect();
pthread_cond_t *session_destroyed_cond;
pthread_cond_t *session_active_cond;
pthread_mutex_t *session_destroyed_mutex;
pthread_mutex_t *session_active_mutex;

/** IPv4 address of NuAuth server: hostname ::authreq_addr,
 * port ::authreq_port. Used in tls_connect().
 */
struct sockaddr_in adr_srv;

#ifdef GRYZOR_HACKS
//Raw socket we use for sending ICMP messages
int raw_sock;
#endif

/* 
 * all functions 
 */

// IP packet catcher
void* packetsrv(void *data);

// IP auth server
void* authsrv(void* data);

/* send an auth request packet given a payload (raw packet) */
int auth_request_send(uint8_t type,uint32_t packet_id, char* payload,int data_len);

/* take decision given a auth answer packet payload */
void auth_packet_to_decision(char* dgram);

unsigned long padd ( packet_idl * packet);
int psearch_and_destroy (uint32_t packet_id,uint32_t * mark);
void clean_old_packets ();

void process_usr1(int signum);
void process_usr2(int signum);
void process_poll(int signum);

#ifdef GRYZOR_HACKS
int send_icmp_unreach(char *dgram);
#endif


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "structure.h"
#include <nufw_debug.h>
#include <signal.h>

#include <strings.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#if USE_NFQUEUE
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>

uint16_t nfqueue_num;
struct nfq_handle *h;
#else
/* redhat like hack */
#ifdef HAVE_LIBIPQ_LIBIPQ_H 
#include <libipq/libipq.h>
#else
#ifdef HAVE_LIBIPQ_H
#include <libipq.h>
#else
#error "libipq needed for NuFW compilation"
#endif
#endif
#endif



#include <gnutls/gnutls.h>
#include <gcrypt.h>
#include <errno.h>

#define GRYZOR_HACKS
#undef GRYZOR_HACKS

#ifdef GRYZOR_HACKS
#include <sys/socket.h>
#endif






#define USE_X509 1
#define KEYFILE "/nufw-key.pem"
#define CERTFILE "/nufw-cert.pem"

struct nuauth_conn {
        gnutls_session * session;
        unsigned char active;
};

struct nuauth_conn tls;
gnutls_session * tls_connect( );
pthread_cond_t *session_destroyed_cond;
pthread_cond_t *session_active_cond;
pthread_mutex_t *session_destroyed_mutex;
pthread_mutex_t *session_active_mutex;

/* socket number to send auth request */
int sck_auth_request;
struct sockaddr_in adr_srv, list_srv;

#ifdef GRYZOR_HACKS
//Raw socket we use for sending ICMP messages
int raw_sock;
#endif
/* 
 * all functions 
 */

// IP packet catcher

void* packetsrv();

// IP auth server

void* authsrv();

/* send an auth request packet given a payload (raw packet) */
int auth_request_send(u_int8_t type,unsigned long packet_id, char* payload,int data_len);
/* take decision given a auth answer packet payload */
int auth_packet_to_decision(char* dgram);


/* common */

unsigned long padd ( packet_idl * packet);
int psearch_and_destroy (unsigned long packet_id,unsigned long * mark);
int clean_old_packets ();

void process_usr1(int signum);
void process_usr2(int signum);
void process_poll(int signum);

#ifdef GRYZOR_HACKS
int send_icmp_unreach(char *dgram);
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "structure.h"
#include <nufw_debug.h>
#include <signal.h>
#include <assert.h>

#include <strings.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#if USE_NFQUEUE
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>

#define DEFAULT_NFQUEUE 0
#define CONNTRACK_HANDLE_DEFAULT 0

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


#ifdef HAVE_LIBCONNTRACK
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

struct nfct_handle *cth;
unsigned char handle_conntrack_event; 

void* conntrack_event_handler(void *data);

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
        pthread_mutex_t* mutex;
        unsigned char auth_server_running;
        pthread_t auth_server;
        pthread_t conntrack_event_handler;
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

void* packetsrv(void *data);

// IP auth server

void* authsrv(void* data);

/* send an auth request packet given a payload (raw packet) */
int auth_request_send(u_int8_t type,uint32_t packet_id, char* payload,int data_len);
/* take decision given a auth answer packet payload */
int auth_packet_to_decision(char* dgram);


/* common */
void log_printf(int priority, char *format, ...);

unsigned long padd ( packet_idl * packet);
int psearch_and_destroy (uint32_t packet_id,uint32_t * mark);
int clean_old_packets ();

void process_usr1(int signum);
void process_usr2(int signum);
void process_poll(int signum);

#ifdef GRYZOR_HACKS
int send_icmp_unreach(char *dgram);
#endif

#define SECURE_STRNCPY(dst, src, size) \
    do { strncpy(dst, src, (size)-1); (dst)[(size)-1] = '\0'; } while (0)

#define DEBUG_OR_NOT(LOGLEVEL,LOGAREA) (LOGAREA&&(debug_areas))&&((debug_level)>=LOGLEVEL)

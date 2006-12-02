#ifndef NUFW_HEADER_H
#define NUFW_HEADER_H

/** \file nufw.h
 *  \brief Common functions and variables to NuFW 
 *   
 * Some structures, functions, global variables and \#define common to NuFW.
 */

/**
 * Use ISO C99 standard, needed by snprintf for example
 */
#define _ISOC99_SOURCE

/*
 * Use POSIX standard, version "IEEE 1003.1-2004"
 */
#define _POSIX_C_SOURCE 199506L

/**
 * Use 4.3BSD standard
 */
#define _BSD_SOURCE

/* Disable inline keyword when compiling in strict ANSI conformance */
#ifdef __STRICT_ANSI__
#  define inline
#endif

/*#define PERF_DISPLAY_ENABLE 1*/

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <strings.h>
#include <gnutls/gnutls.h>
#include <gcrypt.h>
#include <errno.h>

#include "log.h"
#include "security.h"
#include "structure.h"

#if USE_NFQUEUE
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>

/** Default value of ::nfqueue_num */
#define DEFAULT_NFQUEUE 0

/** Default value of ::handle_conntrack_event */
#define CONNTRACK_HANDLE_DEFAULT 0

#define QUEUE_MAXLEN 1024

/** NetFilter queue number, default value: #DEFAULT_NFQUEUE */
uint16_t nfqueue_num;
/** Netfilter queue handle */
struct nfq_handle *h;
/** Netfilter queue max length */
uint32_t queue_maxlen;

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
   unsigned char nufw_conntrack_uses_mark; 
   void* conntrack_event_handler(void *data);
#endif

#include <sys/socket.h>
#include <netdb.h>

/** If equals to 1, compile with x509 certificate support */
#define USE_X509 1

/** Default value, prefixed with CONFIG_DIR, of ::key_file */
#define KEYFILE "/nufw-key.pem"  

/** Default value, prefixed with CONFIG_DIR, of ::cert_file */
#define CERTFILE "/nufw-cert.pem"  

struct nuauth_conn {
        gnutls_session * session;
        pthread_mutex_t mutex;
        unsigned char auth_server_running;
        pthread_t auth_server;
        pthread_mutex_t auth_server_mutex;
#ifdef HAVE_LIBCONNTRACK
        pthread_t conntrack_event_handler;
#endif
        gnutls_certificate_credentials xcred;
};

struct nuauth_conn tls;

gnutls_session * tls_connect();
pthread_cond_t *session_destroyed_cond;
pthread_cond_t *session_active_cond;
pthread_mutex_t *session_destroyed_mutex;
pthread_mutex_t *session_active_mutex;

/** 
 * Address informations of NuAuth server: hostname ::authreq_addr,
 * port ::authreq_port. Used in tls_connect().
 */
struct addrinfo *adr_srv;

/* Raw IPv4 socket we use for sending ICMP messages */
int raw_sock4;

/* Raw IPv6 socket we use for sending ICMPv6 messages */
int raw_sock6;

/* 
 * all functions 
 */

/* IP packet catcher */
void* packetsrv(void *data);

/* IP auth server */
void* authsrv(void* data);

/* send an auth request packet given a payload (raw packet) */
int auth_request_send(uint8_t type,uint32_t packet_id, char* payload, unsigned int data_len);

void close_tls_session();

unsigned long padd ( packet_idl * packet);
int psearch_and_destroy (uint32_t packet_id,uint32_t * mark);
void clear_packet_list ();
void clean_old_packets ();

void process_usr1(int signum);
void process_usr2(int signum);
void process_poll(int signum);

int send_icmp_unreach(char *payload);

#endif   /* _NUFW_HEADER_H */


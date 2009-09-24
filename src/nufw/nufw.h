/*
 ** Copyright (C) 2007 INL
 ** Written by Eric Leblond <regit@inl.fr>
 **            Vincent Deffontaines <vincent@gryzor.com>
 ** INL http://www.inl.fr/
 **
 ** $Id$
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, version 3 of the License.
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

#ifndef NUFW_HEADER_H
#define NUFW_HEADER_H

/** \file nufw.h
 *  \brief Common functions and variables to NuFW
 *
 * Some structures, functions, global variables and \#define common to NuFW.
 */

/* Disable inline keyword when compiling in strict ANSI conformance */
#ifdef __STRICT_ANSI__
#  define inline
#endif

/*#define PERF_DISPLAY_ENABLE 1*/

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "nufw_source.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>
#include <strings.h>
#include <gcrypt.h>
#include <errno.h>

#include <nussl.h>
#include "security.h"
#include "structure.h"

#if USE_NFQUEUE
#include <linux/netfilter.h>	/* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>

/** Default value of config file */
#define DEFAULT_NUFW_CONF_FILE CONFIG_DIR "/nufw.conf"

/** Default value of ::nfqueue_num */
#define DEFAULT_NFQUEUE 0

/** Default value of ::handle_conntrack_event */
#define CONNTRACK_HANDLE_DEFAULT 0

#define QUEUE_MAXLEN 0

/** NetFilter queue number, default value: #DEFAULT_NFQUEUE */
uint16_t nfqueue_num;
/** Netfilter queue handle */
struct nfq_handle *h;
/** Netfilter queue max length */
uint32_t queue_maxlen;

#else

/* redhat like hack */
#   ifdef HAVE_LIBIPQ_LIBIPQ_H
#       include <libipq/libipq.h>
#   else
#       ifdef HAVE_LIBIPQ_H
#           include <libipq.h>
#       else
#           error "libipq needed for NuFW compilation"
#       endif			/* ifdef HAVE_LIBIPQ_H */
#   endif			/* ifdef HAVE_LIBIPQ_LIBIPQ_H  */
#endif				/* if USE_NFQUEUE */

/* conntrack things */
#ifdef HAVE_LIBCONNTRACK
#  include <libnetfilter_conntrack/libnetfilter_conntrack.h>
struct nfct_handle *cth;
unsigned char handle_conntrack_event;
unsigned char nufw_conntrack_uses_mark;
void *conntrack_event_handler(void *data);
#endif

#include <sys/socket.h>
#include <netdb.h>
#include <ev.h>

/** If equals to 1, compile with x509 certificate support */
#define USE_X509 1

/** Default value, prefixed with CONFIG_DIR, of ::key_file */
#define KEYFILE "/nufw-key.pem"
#define DEFAULT_NUFW_KEY  CONFIG_DIR KEYFILE

/** Default value, prefixed with CONFIG_DIR, of ::cert_file */
#define CERTFILE "/nufw-cert.pem"
#define DEFAULT_NUFW_CERT  CONFIG_DIR CERTFILE

struct nuauth_conn {
	nussl_session *session;
	unsigned char auth_server_running;
	ev_io ev_io;
#ifdef HAVE_LIBCONNTRACK
	pthread_t conntrack_event_handler;
#endif
};

struct queued_pckt {
	uint32_t packet_id;

	char indev[IFNAMSIZ];
	char physindev[IFNAMSIZ];
	char outdev[IFNAMSIZ];
	char physoutdev[IFNAMSIZ];
	u_int32_t mark;

	time_t timestamp;

	char *payload;
	int payload_len;
};

struct nuauth_conn tls;

int init_x509_filenames();
void tls_connect();

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
void *packetsrv(void *data);

/* IP auth server */
void *authsrv(void *data);

/* send an auth request packet given a payload (raw packet) */
int auth_request_send(uint8_t type, struct queued_pckt *pckt);

void close_tls_session();
void shutdown_tls();

int padd(packet_idl * packet);
int psearch_and_destroy(uint32_t packet_id, uint32_t * mark);
void clear_packet_list();
void clean_old_packets();

void process_usr1(int signum);
void process_usr2(int signum);
void process_poll(int signum);
void process_hup(int signum);

int send_icmp_unreach(char *payload, int payload_len);

#endif				/* _NUFW_HEADER_H */

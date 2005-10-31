/*
** Copyright(C) 2003-2005 Eric Leblond <regit@inl.fr>
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

#ifndef AUTH_SRV_H
#define AUTH_SRV_H

/* Use glib to treat data structures */
#include <glib.h>
#include <gmodule.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
/* config dependant */
#include <config.h>
#include <gnutls/gnutls.h>
#include <sasl/sasl.h>
#include <locale.h>

/* NUFW Protocol */
#include <proto.h>

/*debug functions*/
#include <nuauth_debug.h>

/* config file related */
#include <conffile.h>
#include "tls.h"
#include "connections.h"
#include "auth_common.h"
#include "check_acls.h"
#include "user_logs.h"
#include "pckt_authsrv.h"
#include "modules.h"
#include "cache.h"
#include "acls.h"
#include "users.h"
#include "user_authsrv.h"
#include "internal_messages.h"
#include "client_mngr.h"
#include "nu_gcrypt.h"
#include "ip_auth.h"
#include "x509_parsing.h"
#include "parsing.h"
#include "localid_auth.h"
#include "audit.h"

/*
 * declare some global variables and do some definitions
 */

#define NUAUTH_TLS_MAX_CLIENTS 1024
#define NUAUTH_TLS_MAX_SERVERS 16
#define TLS_CLIENT_MIN_DELAY 25000
#define AUTH_NEGO_TIMEOUT 30

#define UNKNOWN_STRING "UNKNOWN"

#define DUMMY 0
#define USE_LDAP 0
#define AUTHREQ_CLIENT_LISTEN_ADDR "0.0.0.0"
#define AUTHREQ_NUFW_LISTEN_ADDR "127.0.0.1"
#define AUTHREQ_PORT 4129
#define USERPCKT_PORT 4130
#define GWSRV_ADDR "127.0.0.1"
#define PRIO 1
#define PRIO_TO_NOK 1
#define HOSTNAME_SIZE 128
#define PACKET_TIMEOUT 15
#define DEFAULT_USERAUTH_MODULE "libsystem"
#define DEFAULT_ACLS_MODULE "libplaintext"
#define DEFAULT_LOGS_MODULE "libsyslog"
#define DEFAULT_IPAUTH_MODULE "libident"
#define MODULE_PATH MODULE_DIR "/nuauth/modules/"
/* define the number of threads that will do user check */
#define NB_USERCHECK 10
/* define the number of threads that will check acls  */
#define NB_ACLCHECK 10
/* define the number of threads that will log  */
#define NB_LOGGERS 3

#define BUFSIZE 1024

/* SSL stuffs */
#define NUAUTH_KEYFILE CONFIG_DIR "/nuauth-key.pem"
#define NUAUTH_CERTFILE CONFIG_DIR "/nuauth-cert.pem"
#define NUAUTH_CACERTFILE CONFIG_DIR "/NuFW-cacert.pem"
#define NUAUTH_SSL_MAX_CLIENTS 256

/* Start internal */
#define USERNAMESIZE 30

/* Sockets related */
char client_listen_address[HOSTNAME_SIZE];
char nufw_listen_address[HOSTNAME_SIZE];
int authreq_port;
int  gwsrv_port , userpckt_port;
int nuauth_aclcheck_state_ready;

/* global configuration variables */

int packet_timeout;
int authpckt_port;
int debug; /* This will disapear*/
int debug_level;
int debug_areas;
int nuauth_log_users;
int nuauth_log_users_sync;
int nuauth_log_users_strict;
int nuauth_log_users_without_realm;
int nuauth_prio_to_nok;
int nuauth_uses_utf8;
int nuauth_push;
int nuauth_do_ip_authentication;
int nuauth_hello_authentication;
int nuauth_datas_persistance;

struct sockaddr_in adr_srv, client_srv, nufw_srv;
/* cache variables for acl cache */
int nuauth_acl_cache;
struct cache_init_datas* acl_cache;

/* cache variables for user cache */
int nuauth_user_cache;
struct cache_init_datas* user_cache;

/* Multi user related variables */
/* authorized server list */
struct in_addr *authorized_servers;
/* multi users clients */
char** nuauth_multi_users_array;
struct in_addr * nuauth_multi_servers_array;

/**
 * pool of thread which treat user packet.
 */
GThreadPool* user_checkers;

/**
 * pool of thread which treat nufw packet.
 */
GThreadPool* acl_checkers;

/* private datas */
GPrivate *aclqueue;
GPrivate *userqueue;


GThreadPool* user_loggers;
GThreadPool* decisions_workers;

GThreadPool*  ip_authentication_workers;

GAsyncQueue* connexions_queue;
GAsyncQueue* tls_push;
GAsyncQueue* localid_auth_queue;

#endif

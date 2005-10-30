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


/* uncomment following line if you have
 * SUSE 9 and RHEL 3.0 which only have glib 2.3 */
//#define GLIB_23_HACK 1

#define NUAUTH_TLS_MAX_CLIENTS 1024
#define NUAUTH_TLS_MAX_SERVERS 16
#define TLS_CLIENT_MIN_DELAY 25000
#define AUTH_NEGO_TIMEOUT 30

#define UNKNOWN_STRING "UNKNOWN"


/* NUFW Protocol */
#include <proto.h>

/*debug functions*/
#include <nuauth_debug.h>

/* config file related */
#include <conffile.h>

#include "tls.h"

/*
 * declare some global variables and do some definitions
 */

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

/* SSL stuffs */
#define NUAUTH_KEYFILE CONFIG_DIR "/nuauth-key.pem"
#define NUAUTH_CERTFILE CONFIG_DIR "/nuauth-cert.pem"
#define NUAUTH_CACERTFILE CONFIG_DIR "/NuFW-cacert.pem"
#define NUAUTH_SSL_MAX_CLIENTS 256

/* Start internal */

/* internal auth srv */
#define STATE_NONE 0x0
#define STATE_AUTHREQ 0x1
#define STATE_USERPCKT 0x2
#define STATE_READY 0x3
#define STATE_COMPLETING 0x4
#define STATE_DONE 0x5
#define STATE_HELLOMODE 0x6

#define STATE_DROP 0x0
#define STATE_OPEN 0x1
#define STATE_ESTABLISHED 0x2
#define STATE_CLOSE 0x3

#define ALL_GROUPS 0

#define USERNAMESIZE 30

/* Sockets related */
char client_listen_address[HOSTNAME_SIZE];
char nufw_listen_address[HOSTNAME_SIZE];
int authreq_port;
int  gwsrv_port , userpckt_port;
int nuauth_aclcheck_state_ready;


/**
 * ipv4 headers related sructure used as key for connection identification.
 */
typedef struct uniq_headers {
  u_int32_t saddr;/*!< IPV4 source address. */
  u_int32_t daddr;/*!< IPV4 dest address. */
  u_int8_t protocol;/*!< IPV4 protocol. */
  /* TCP or UDP */
  u_int16_t source; /*!< TCP/UDP source port. */
  u_int16_t dest; /*!< TCP/UDP dest port. */
  /* ICMP Things */
  u_int8_t type; /*!< icmp message type. */
  u_int8_t code; /*!< icmp code type. */
} tracking;

/**
 * connection element
 * 
 * It contains all datas relative to a packet
 * 
 */
typedef struct Connection {
  // netfilter stuff 
  GSList * packet_id; /**< Netfilter number. */
  long timestamp; /**< Packet arrival time (seconds). */
  int socket;  /**< socket from which nufw request is coming. */
  nufw_session* tls; /**< infos on nufw which sent the request. */
  tracking tracking_hdrs; /**< IPV4  stuffs (headers). */
  u_int16_t user_id; /**< user numeric identity (protocol 1). Used by protocol 2 for marking. */
  char * username; /**< user identity (protocol 2). */
 /**
  * acl related groups.
  *
  * Contains the list of acl corresponding to the ipv4 header
  */
  GSList * acl_groups;
 /**
  * user groups.
  */
  GSList * user_groups;
  /* Pointer to cache */
  struct user_cached_datas * cacheduserdatas;
  /** operating system name. */
  gchar * sysname;
  /** operating system release. */
  gchar * release;
  /** operating system version. */
  gchar * version;
  /** application name.
   *
   * application full path
   */
  gchar * appname;
 /** application md5sum.
   *
   * md5sum of the binary which send the packet
   */
  gchar * appmd5;
  /** state of the packet. */
  char state;
  /** decision on packet. */
  char decision;
} connection;


/*
 * Keep connection in a hash
 */

/** hash table containing the connections. */
GHashTable * conn_list;
/** global lock for the conn list. */
GStaticMutex insert_mutex;
/** global lock for client hash. */
GStaticMutex client_mutex;

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
struct sockaddr_in adr_srv, client_srv, nufw_srv;
int nuauth_datas_persistance;

/** 
 * 
 * Used to store the acl that apply for a packet
 */ 

struct acl_group {
  GSList * groups;
  char answer;
};

GSList * ALLGROUP;

/**
 * user statistic. */

typedef struct User_Datas {
	u_int32_t ip;
	long first_pckt_timestamp;
	long last_packet_time;
	unsigned long last_packet_id;
	long last_packet_timestamp;
	GMutex * lock;
} user_datas;

GHashTable * users_hash;

/* internal for crypt */
GPrivate* crypt_priv;

#include "auth_common.h"

int external_acl_groups (connection * element);

#include "user_logs.h"
#include "pckt_authsrv.h"

/*
 * External auth  stuff
 */

GModule * auth_module;
GPrivate* ldap_priv; /* private pointer to ldap connection */
GPrivate* dbm_priv; /* private pointer for dbm file access */
GPrivate* pgsql_priv; /* private pointer for pgsql database access */
GPrivate* mysql_priv; /* private pointer for mysql database access */
GSList * (*module_acl_check) (connection* element);

int (*module_user_check) (const char *user, const char *pass,unsigned passlen,uint16_t *uid,GSList **groups);

int init_ldap_system(void);

/* ip auth */
gchar* (*module_ip_auth)(tracking * header);

#include "cache.h"

struct cache_init_datas* acl_cache;
int nuauth_acl_cache;
int nuauth_user_cache;

int nuauth_uses_utf8;

struct cache_init_datas* user_cache;


void free_cache_elt(gpointer data,gpointer userdata);

void cache_manager (gpointer datas);
/* 
 * message structure for async communication
 * between cache thread and others 
 */


#define WARN_MESSAGE 0x1
#define FREE_MESSAGE 0x0
#define INSERT_MESSAGE 0x2
#define GET_MESSAGE 0x3
#define REFRESH_MESSAGE 0x4

struct internal_message {
	guint type;
	gpointer datas;
};

#include "acls.h"

#include "users.h"

#include "client_mngr.h"

void free_buffer_read(struct buffer_read* datas);

#define BUFSIZE 1024

/*
 * For user authentication
 */

void* tls_user_authsrv();

void push_worker () ;

void user_check_and_decide (gpointer userdata ,gpointer data);

/* garbage ;-) */
 void bail (const char *on_what);


/* crypt */

int verify_user_password(const char* given,const char* ours);

GHashTable* client_conn_hash;
GHashTable* client_ip_hash;


/* authorized server list */
struct in_addr *authorized_servers;

int nuauth_push;

int nuauth_do_ip_authentication;

int nuauth_hello_authentication;

void external_ip_auth(gpointer userdata, gpointer data);

/* multi users clients */
char** nuauth_multi_users_array;
struct in_addr * nuauth_multi_servers_array;

#include "x509_parsing.h"

// Check validity of data before inserting them to SQL
// This allocates a new string.
// Returns NULL is the original string contains ' or ;
// Else returns escaped char (with glib function g_strescape()
gchar *string_escape(gchar *orig);

#include "parsing.h"

#include "localid_auth.h"

#include "audit.h"

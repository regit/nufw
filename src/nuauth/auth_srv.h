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

#define NUAUTH_TLS_MAX_CLIENTS 1024
#define NUAUTH_TLS_MAX_SERVERS 16
#define TLS_CLIENT_MIN_DELAY 25000

#define UNKNOWN_STRING "UNKNOWN"


/* NUFW Protocol */
#include <proto.h>

/*debug functions*/
#include <nuauth_debug.h>

/* config file related */
#include <conffile.h>

/*
 * declare some global variables and do some definitions
 */

#define DUMMY 0
#define USE_LDAP 0
#define AUTHREQ_CLIENT_LISTEN_ADDR "0.0.0.0"
#define AUTHREQ_NUFW_LISTEN_ADDR "127.0.0.1"
#define GWSRV_ADDR "127.0.0.1"
//#define CLIENT_LISTEN_ADDR "0.0.0.0"
//#define NUFW_LISTEN_ADDR "127.0.0.1"
#define GWSRV_PORT 4128
#define AUTHREQ_PORT 4129
#define USERPCKT_PORT 4130
#define PRIO 1
#define PRIO_TO_NOK 1
#define HOSTNAME_SIZE 128
#define PACKET_TIMEOUT 15
#define DEFAULT_AUTH_MODULE "libldap"
#define DEFAULT_LOGS_MODULE "libsyslog"
#define DEFAULT_IPAUTH_MODULE "libident";
#define MODULE_PATH MODULE_DIR "/nuauth/modules/"
/* define the number of threads that will do user check */
#define NB_USERCHECK 10
/* define the number of threads that will check acls  */
#define NB_ACLCHECK 10

/* SSL stuffs */
#define NUAUTH_KEYFILE CONFIG_DIR "/nuauth-key.pem"
#define NUAUTH_KEY_PASSWD "password"
#define NUAUTH_SSL_MAX_CLIENTS 256

/* Start internal */

/* internal auth srv */
#define STATE_NONE 0x0
#define STATE_AUTHREQ 0x1
#define STATE_USERPCKT 0x2
#define STATE_READY 0x3
#define STATE_COMPLETING 0x4
#define STATE_DONE 0x5

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



typedef struct Nufw_session {
        gnutls_session* tls;
	gint usage;
	gboolean alive;
} nufw_session;

void clean_nufw_session(nufw_session * c_session);


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
  u_int16_t user_id; /**< user numeric identity (protocol 1). */
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

int packet_timeout;
int authpckt_port;
int debug; /* This will disapear*/
int debug_level;
int debug_areas;
int nuauth_log_users;
int nuauth_log_users_sync;
int nuauth_log_users_strict;
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

/**
 * internal for send_auth_response. */

struct auth_answer {
  u_int8_t answer;
  u_int16_t user_id;
  int socket;
  nufw_session* tls;
};

/*
 * Functions
 */

/*
 * From auth_common.c
 */

void search_and_fill ();

gboolean compare_connection(gconstpointer conn1, gconstpointer conn2);
int sck_auth_reply;
void send_auth_response(gpointer data, gpointer userdata);
int conn_cl_delete(gconstpointer conn);
char change_state(connection *elt, char state);
inline char get_state(connection *elt);
gint take_decision(connection * element);
gint print_connection(gpointer data,gpointer userdata);
int free_connection(connection * conn);
int lock_and_free_connection(connection * conn);
void clean_connections_list ();
guint hash_connection(gconstpointer conn_p);
void decisions_queue_work (gpointer userdata, gpointer data);

char * get_rid_of_domain(const char* user);

/*
 * From check_acls.c
 */

int external_acl_groups (connection * element);

/*
 * From pckt_authsrv.c
 */

void* packet_authsrv();
connection*  authpckt_decode(char * , int);
void acl_check_and_decide (gpointer userdata , gpointer data);

/*
 * from userlogs.c
 */
 
int check_fill_user_counters(u_int16_t userid,long time,unsigned long packet_id,u_int32_t ip);
void print_users_list();
void log_new_user(char* username,char* remoteip);
GModule * logs_module;
void log_user_packet (connection element,int state);
void real_log_user_packet (gpointer userdata, gpointer data);
int (*module_user_logs) (connection element, int state);
/*
 * External auth  stuff
 */

GModule * auth_module;
GPrivate* ldap_priv; /* private pointer to ldap connection */
GPrivate* dbm_priv; /* private pointer for dbm file access */
GPrivate* pgsql_priv; /* private pointer for pgsql database access */
GPrivate* mysql_priv; /* private pointer for mysql database access */
GSList * (*module_acl_check) (connection* element);
#if USE_PROTO_V1
GSList * (*module_user_check) (connection* connexion,char *passwd);
#else
int (*module_user_check) (const char *user, const char *pass,unsigned passlen,uint16_t *uid,GSList **groups);
#endif
int init_ldap_system(void);

/* ip auth */
gchar* (*module_ip_auth)(tracking * header);

/*
 * cache system : cache.c
 */

/**
 * struct needed for initialisation of cache manager occurence
 */
struct cache_init_datas {
	GAsyncQueue * queue;
	GHashTable*  hash;
	void (*delete_elt)(gpointer,gpointer);
	void* (*duplicate_key)(gpointer);
	void (*free_key)(gpointer);
	gboolean (*equal_key)(gconstpointer,gconstpointer);
};


struct cache_init_datas* acl_cache;
int nuauth_acl_cache;
int nuauth_user_cache;

struct cache_init_datas* user_cache;


void free_cache_elt(gpointer data,gpointer userdata);

void cache_manager (gpointer datas);
/* 
 * message structure for async communication
 * between cache thread and others 
 */

/* define message types */
#define CACHE_GET 0x1
#define CACHE_PUT 0x2
#define CACHE_FREE 0x3
#define CACHE_UPDATE 0x4

/**
 * generic message send between thread working with the
 * cache system
 */

struct cache_message {
	guint type; /* message type */
	gpointer key; /* key that identify datas in hash */ 
	gpointer datas; /* datas to store */
	GAsyncQueue* reply_queue; /* reply has to be sent to */
};


gpointer null_message;
gpointer null_queue_datas;

#define WARN_CLIENTS 0x1
#define FREE_CLIENT 0x0
#define INSERT_CLIENT 0x2
#define REFRESH_CLIENTS 0x3

struct tls_message {
	guint type;
	gpointer datas;
};

/* from cache.c */
/* from acls.c (for cache)*/
void free_acl_cache(gpointer datas);
void free_acl_struct(gpointer datas,gpointer uda);
void free_acl_key(gpointer datas);
gboolean compare_acls(gconstpointer tracking_hdrs1, gconstpointer tracking_hdrs2);

gpointer acl_create_and_alloc_key(connection* kdatas);
inline  guint hash_acl(gconstpointer headers);
void free_acl_list(void * datas);
void get_acls_from_cache (connection* conn_elt);
gpointer acl_duplicate_key(gpointer datas);
/* from users.c (for cache) */
void free_user_cache(gpointer datas);
void free_user_struct(gpointer datas,gpointer uda);
void get_users_from_cache (connection* conn_elt);
gpointer user_duplicate_key(gpointer datas);

struct user_cached_datas {
       uint16_t uid;
       GSList * groups;
};

/* cache system related */

/**
 * stores all informatin relative to a TLS user session
 * so we don't have to get this information at each packet
 */
typedef struct User_session {
	uint32_t addr;
        gnutls_session* tls;
        char * userid;
	u_int16_t uid;
        GSList * groups;
	gchar * sysname;
	gchar * release;
	gchar * version;
        struct timeval last_req;
        gboolean req_needed;
	gboolean multiusers;
} user_session;

struct client_connection {
	int socket;
	struct sockaddr_in addr;
};

/**
 * structure used to sent data from
 * tls function to core functions
 */

struct buffer_read {
        int socket;
        gnutls_session* tls;
        char * userid;
	uint16_t uid;
        GSList * groups;
	char * sysname;
	char * release;
	char * version;
        char* buf;
};


#define BUFSIZE 1024

/*
 * For user authentication
 */

void* tls_user_authsrv();

void push_worker () ;

connection * userpckt_decode(struct buffer_read* dgram,int dgramsiz);
void user_check_and_decide (gpointer userdata ,gpointer data);

/* garbage ;-) */
 void bail (const char *on_what);


/* crypt */

int verify_user_password(const char* given,const char* ours);

/* AUDIT */

struct audit_struct{
  GThreadPool *users;
  GThreadPool *acls;
  GThreadPool *loggers;
  GHashTable *conn_list;
  GHashTable *aclcache;
  gint cache_req_nb;
  gint cache_hit_nb;
};

struct audit_struct *myaudit;

void process_usr1(int signum);
void process_usr2(int signum);
void process_poll(int signum);

/* END AUDIT */

GHashTable* client;

void create_x509_credentials();
void* tls_nufw_authsrv();
GHashTable* nufw_servers;

/* authorized server list */
struct in_addr *authorized_servers;

int nuauth_push;

int nuauth_do_ip_authentication;

void external_ip_auth(gpointer userdata, gpointer data);

/* multi users clients */
char** nuauth_multi_users_array;
struct in_addr * nuauth_multi_servers_array;

/* x509 parsing */
gchar * parse_x509_certificate_info(gnutls_session session);

// Check validity of data before inserting them to SQL
// This allocates a new string.
// Returns NULL is the original string contains ' or ;
// Else returns escaped char (with glib function g_strescape()
gchar *string_escape(gchar *orig);

/* parsing function */
struct in_addr* generate_inaddr_list(gchar* gwsrv_addr);
gboolean check_inaddr_in_array(struct in_addr check_ip,struct in_addr *iparray);
gboolean check_string_in_array(gchar* checkstring,gchar** stringarray);

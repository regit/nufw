/* $Id: auth_srv.h,v 1.28 2004/03/18 01:16:18 regit Exp $ */

/*
** Copyright(C) 2003 Eric Leblond <eric@regit.org>
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

/* config dependant */
#include <config.h>
/* NUFW Protocol */
#include <proto.h>
/* NUFW hash */
/* #include <nuhash.h>*/

/*debug functions*/
#include <debug.h>

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
//#define DEFAULT_LOGS_MODULE "libsyslog"
#define DEFAULT_LOGS_MODULE "libpgsql"
#define MODULE_PATH MODULE_DIR "/nuauth/modules/"
/* define the number of threads that will do user check */
#define NB_USERCHECK 10
/* define the number of threads that will check acls  */
#define NB_ACLCHECK 10

/* Start internal */

/* internal auth srv */
#define STATE_NONE 0x0
#define STATE_AUTHREQ 0x1
#define STATE_USERPCKT 0x2
#define STATE_READY 0x3
#define STATE_DONE 0x4

#define STATE_DROP 0x0
#define STATE_OPEN 0x1
#define STATE_ESTABLISHED 0x2
#define STATE_CLOSE 0x3

#define ALL_GROUPS 0

/* Sockets related */
char client_listen_address[HOSTNAME_SIZE];
char nufw_listen_address[HOSTNAME_SIZE];
int authreq_port;
int  gwsrv_port , userpckt_port;

typedef struct uniq_headers {
  /* IP */
  u_int32_t saddr;
  u_int32_t daddr;
  u_int8_t protocol;
  /* TCP or UDP */
  u_int16_t source;
  u_int16_t dest;
  /* ICMP Things */
  u_int8_t type;		/* message type */
  u_int8_t code;
} tracking;
//connection element


typedef struct Connection {
  // netfilter stuff
  GSList * packet_id; /* netfilter number */
  long timestamp;             /* Packet arrival time (seconds) */
  // IPV4  stuffs (headers)
  /* tracking test */
  tracking tracking_hdrs;
  u_int16_t id_srv;
  u_int16_t user_id;
  /* generic list to stock acl related groups */
  GSList * acl_groups;
  // auth stuff 
  GSList * user_groups;
  /* state */
  char state;
  /* decision on packet */
  char decision;
  /* exclusion mutex to protect during access */
  GMutex * lock;
} connection;

#define TRYLOCK_CONN(ARG1) if (((connection *)ARG1)->lock != NULL) { g_mutex_trylock(((connection *)ARG1)->lock); } else { g_message("trying lock NULL\n"); };
#define LOCK_CONN(ARG1) if (((connection *)ARG1)->lock != NULL) { g_mutex_lock(((connection *)ARG1)->lock); } else { g_message("trying lock NULL\n"); };
#define UNLOCK_CONN(ARG1) if (((connection *)ARG1)->lock != NULL) g_mutex_unlock(((connection *)ARG1)->lock);

GSList * busy_mutex_list;
GSList * free_mutex_list;

/*
 * Keep connection in a List
 */


GHashTable * conn_list;
/* global lock for the conn list */
GStaticMutex insert_mutex;


GThreadPool* user_checkers;
GThreadPool* acl_checkers;
GThreadPool* user_loggers;

int packet_timeout;
int authpckt_port;
int debug; /* This will disapear*/
int debug_level;
int debug_areas;
int nuauth_log_users;
int nuauth_prio_to_nok;
struct sockaddr_in adr_srv, client_srv, nufw_srv;


/*
 * TODO : switch to dyn size array
 */

struct acl_group {
  GSList * groups;
  char answer;
};



GSList * ALLGROUP;



struct acl_group DUMMYACL ;
GSList * DUMMYACLS;


/*
 * user datas
 */

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

/* internal for send_auth_response */

struct auth_answer {
  u_int8_t answer;
  u_int16_t user_id;
};

/*
 * Functions
 */

/*
 * From auth_common.c
 */

connection * search_and_fill (connection * );

gboolean compare_connection(gconstpointer conn1, gconstpointer conn2);
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
 * From user_authsrv.c
 */

void* user_authsrv();
void* ssl_user_authsrv();
connection * userpckt_decode(char* dgram,int dgramsiz);
void user_check_and_decide (gpointer userdata ,gpointer data);

/* garbage ;-) */
 void bail (const char *on_what);


/*
 * from userlogs.c
 */
 
int check_fill_user_counters(u_int16_t userid,long time,unsigned long packet_id,u_int32_t ip);
void print_users_list();
void log_new_user(int id,u_int32_t ip);
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
GSList * (*module_user_check) (u_int16_t userid,char *passwd);
int init_ldap_system(void);

/* PROV */
#define MAX_CLIENTD 256
FILE* client[MAX_CLIENTD];

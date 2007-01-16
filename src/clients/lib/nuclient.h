/* nuclient.h, header file for libnuclient
 *
 * Copyright 2004-2006 - INL
 *	written by Eric Leblond <regit@inl.fr>
 *	           Vincent Deffontaines <vincent@inl.fr>
 *
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

#ifndef NUCLIENT_H
#define NUCLIENT_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "nufw_source.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <features.h>
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <termios.h>
#include <time.h>
#define _XOPEN_SOURCE
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <errno.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

#include <gcrypt.h>
#include <pthread.h>

#include <gnutls/gnutls.h>
#include <sasl/sasl.h>

#define NUCLIENT_VERSION "2.1.1-3"
#define DEBUG 0

#ifndef CONNTABLE_BUCKETS
/** Maximum number of connections in connection table, see ::conntable_t */
#define CONNTABLE_BUCKETS 5003
#endif

/** Default nuauth IP address */
#define NUAUTH_IP "192.168.1.1"

/** Default filename of key */
#define KEYFILE "key.pem"

/** Timeout of UDP connections */
#define UDP_TIMEOUT 30

/*
 * This structure holds everything we need to know about a connection.
 *
 * We use unsigned int and long (instead of exact type) to make
 * hashing easier.
 */
typedef struct conn
{
    unsigned int protocol;     /*!< IPv4 protocol */
    struct in6_addr ip_src;    /*!< Local address IPv4 */
    unsigned short port_src;   /*!< Local address port */
    struct in6_addr ip_dst;    /*!< Remote address IPv4 */
    unsigned short port_dst;   /*!< Remote address port */
    unsigned long uid;         /*!< User identifier */
    unsigned long inode;       /*!< Inode */
    unsigned int retransmit;   /*!< Restransmit */
    time_t createtime;         /*!< Creation time (Epoch format) */

    /** Pointer to next connection (NULL if it's as the end) */
    struct conn *next;
} conn_t;

/**
 * A connection table: hash table of single-linked connection lists,
 * a list stops with NULL value.
 *
 * Methods:
 *   - tcptable_init(): create a structure (allocate memory) ;
 *   - tcptable_hash(): compute a connection hash (index in this table) ;
 *   - tcptable_add(): add a new entry ;
 *   - tcptable_find(): fin a connection in a table ;
 *   - tcptable_read(): feed the table using /proc/net/ files (under Linux) ;
 *   - tcptable_free(): destroy a table (free memory).
 */
typedef struct conntable {
	conn_t *buckets[CONNTABLE_BUCKETS];
} conntable_t;

/* only publicly seen structure but datas are private */

#ifndef USE_SHA1
#  define PACKET_ITEM_MAXSIZE \
     ( sizeof(struct nu_authreq) + sizeof(struct nu_authfield_ipv6) \
       + sizeof(struct nu_authfield_app) + PROGNAME_BASE64_WIDTH )
#else
#  error "TODO: Compute PACKET_ITEM_MAXSIZE with SHA1 checksum"
#endif

#define PACKET_SIZE \
    ( sizeof(struct nu_header) + CONN_MAX * PACKET_ITEM_MAXSIZE )

enum
{
    ERROR_OK = 0,
    ERROR_LOGIN = 1,
    ERROR_NETWORK = 2
};

/* NuAuth structure */

typedef struct {
	/*--------------- PUBLIC MEMBERS -------------------*/
	u_int32_t userid;        /*!< Local user identifier (getuid()) */
	char *username;          /*!< Username (encoded in UTF-8) */
	char *password;          /*!< Password (encoded in UTF-8) */

    gnutls_session tls;      /*!< TLS session over TCP socket */
	gnutls_certificate_credentials cred; /*!< TLS credentials */
	char* tls_password;      /*!< TLS password */

	int socket;              /*!< TCP socket used to exchange message with nuauth */
	conntable_t *ct;         /*!< Connection table */
	u_int32_t packet_seq;    /*!< Packet sequence number (start at zero) */
    int auth_by_default;     /*!< Auth. by default (=1) */
    unsigned char debug_mode; /*!< Debug mode, enabled if different than zero */
    unsigned char verbose;   /*!< Verbose mode (default: enabled) */
    unsigned char diffie_hellman;   /*!< Use Diffie Hellman for key exchange? */

    /** Server mode: #SRV_TYPE_POLL or #SRV_TYPE_PUSH */
	u_int8_t server_mode;

	/*------------- PRIVATE MEMBERS ----------------*/

    /** Mutex used in session destruction */
	pthread_mutex_t mutex;

    /**
     * Flag to signal if user is connected or not.
     * Connected means that TLS tunnel is opened
     * and that authentification is done.
     */
	unsigned char connected;

	/**
     * Condition and associated mutex used to know when a check is necessary
     */
	pthread_cond_t check_cond;
	pthread_mutex_t check_count_mutex;
	int count_msg_cond;

    /**
     * Thread which check connection with nuauth,
     * see function nu_client_thread_check().
     */
	pthread_t checkthread;

    /**
     * Thread which receive messages from nuauth, see function recv_message().
     */
	pthread_t recvthread;

    /**
     * Diffie Hellman parameters used to establish TLS tunnel.
     */
    gnutls_dh_params dh_params;

    /**
     * Does we need to set credentials to current gnutls session?
     */
    unsigned char need_set_cred;

    /** Timestamp (Epoch format) of last packet send to nuauth */
	time_t timestamp_last_sent;
} NuAuth;

/** Error family */
typedef enum
{
    INTERNAL_ERROR = 0,
    GNUTLS_ERROR = 1,
    SASL_ERROR = 2
} nuclient_error_family_t;

/* INTERNAL ERROR CODES */
enum
{
    NO_ERR  = 0,                     /** No error */
    SESSION_NOT_CONNECTED_ERR  = 1,  /** Session not connected */
    UNKNOWN_ERR = 2,                 /** Unkown error */
    TIMEOUT_ERR = 3,                 /** Connection timeout */
    DNS_RESOLUTION_ERR = 4,          /** DNS resolution error */
    NO_ADDR_ERR = 5,                 /** Address not recognized */
    FILE_ACCESS_ERR = 6,             /** File access error */
    CANT_CONNECT_ERR  = 7,           /** Connection failed */
    MEMORY_ERR  = 8,                 /** No more memory */
    TCPTABLE_ERR  = 9,               /** Fail to read connection table */
    SEND_ERR = 10,                   /** Fail to send packet to nuauth */
    BAD_CREDENTIALS_ERR = 11
};

/* libnuclient return code structure */
typedef struct
{
    nuclient_error_family_t family;
    int error;
} nuclient_error;

/* Exported functions */
int 	nu_client_check(NuAuth * session, nuclient_error *err);

int     nu_client_error_init(nuclient_error **err);
void    nu_client_error_destroy(nuclient_error *err);

int  nu_client_global_init(nuclient_error *err);
void nu_client_global_deinit();

NuAuth* nu_client_new(
        const char* username,
        const char* password,
        unsigned char diffie_hellman,
        nuclient_error *err);

void nu_client_set_realm(NuAuth* session, char *realm);
void nu_client_set_debug(NuAuth* session, unsigned char enabled);
void nu_client_set_verbose(NuAuth* session, unsigned char enabled);

int nu_client_setup_tls(NuAuth* session,
        char* tls_passwd,
        char* keyfile,
        char* certfile,
        char* cafile,
        nuclient_error *err);

int nu_client_connect(NuAuth* session,
        const char *hostname,
        const char *service,
        nuclient_error *err);

void nu_client_reset(NuAuth *session);

void nu_client_delete(NuAuth *session);

const char* nu_client_strerror (nuclient_error *err);

char* nu_client_to_utf8(const char* inbuf, char *from_charset);

const char *nu_get_version();
int nu_check_version(const char *version);

char* nu_get_home_dir();

#ifdef __cplusplus
}
#endif

#endif

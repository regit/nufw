/* nuclient.h, header file for libnuclient
 *
 * Copyright 2004-2006 - INL
 *	written by Eric Leblond <regit@inl.fr>
 *	           Vincent Deffontaines <vincent@inl.fr>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef NUCLIENT_H
#define NUCLIENT_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif 

/*
 * Use POSIX standard, version "IEEE 1003.1-2004",
 * needed to get sigaction for example
 */
#ifdef LINUX
#define _POSIX_C_SOURCE 200112L
#endif

/**
 * Use 4.3BSD standard, needed to get snprintf for example
 */
#define _BSD_SOURCE

/* Disable inline keyword when compiling in strict ANSI conformance */
#if defined(__STRICT_ANSI__) && !defined(__cplusplus)
#  define inline
#endif

#ifdef __cplusplus
extern "C" {
#endif

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
     ( sizeof(struct nuv2_authreq) + sizeof(struct nuv2_authfield_ipv6) \
       + sizeof(struct nuv2_authfield_app) + PROGNAME_BASE64_WIDTH )
#else
#  error "TODO: Compute PACKET_ITEM_MAXSIZE with SHA1 checksum"
#endif

#define PACKET_SIZE \
    ( sizeof(struct nuv2_header) + CONN_MAX * PACKET_ITEM_MAXSIZE )

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
	char *password;          /*!< Password,(encoded in UTF-8) */
	
    gnutls_session tls;      /*!< TLS session over TCP socket */
	gnutls_certificate_credentials cred; /*!< TLS credentials */
	char* tls_password;      /*!< TLS password */
	
	int socket;              /*!< TCP socket used to exchange message with nuauth */
	conntable_t *ct;         /*!< Connection table */
	u_int32_t packet_seq;    /*!< Packet sequence number (start at zero) */
    int auth_by_default;     /*!< Auth. by default (=1) */
    unsigned char debug_mode; /*!< Debug mode, enabled if different than zero */
    unsigned char verbose;   /*!< Verbose mode (default: enabled) */

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
        nuclient_error *err);

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

#ifdef __cplusplus
}
#endif

#endif

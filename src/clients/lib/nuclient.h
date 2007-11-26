/*
 ** Copyright 2004-2007 - INL
 ** Written by Eric Leblond <regit@inl.fr>
 **            Vincent Deffontaines <vincent@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** $Id$
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

#ifndef NUCLIENT_H
#define NUCLIENT_H

#ifdef __cplusplus
extern "C" {
#if 0
	/* dummy code to make vim indentation works */
}
#endif
#endif

#ifdef _FEATURES_H
#   error "nuclient.h have to be included before <features.h>"
#endif

/**
 * Use ISO C99 standard, needed by snprintf for example
 */
#define _ISOC99_SOURCE

/**
 * Use GNU extensions like getline() in stdio.h
 */
#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef FREEBSD
#include <features.h>
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

#include <gnutls/gnutls.h>

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

/**
 * This structure holds everything we need to know about a connection.
 *
 * We use unsigned int and long (instead of exact type) to make
 * hashing easier.
 *
 * \see ::conn_t
 */
typedef struct conn_type {
	unsigned int protocol;	/*!< IPv4 protocol */
	struct in6_addr ip_src;	/*!< Local address IPv4 */
	unsigned short port_src;	/*!< Local address port */
	struct in6_addr ip_dst;	/*!< Remote address IPv4 */
	unsigned short port_dst;	/*!< Remote address port */
	unsigned long uid;	/*!< User identifier */
	unsigned long inode;	/*!< Inode */
	unsigned int retransmit;	/*!< Retransmit */
	time_t createtime;	/*!< Creation time (Epoch format) */

	/** Pointer to next connection (NULL if it's as the end) */
	struct conn_type *next;
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
typedef struct {
	conn_t *buckets[CONNTABLE_BUCKETS];
} conntable_t;

/* only publicly seen structure but data are private */

#ifndef USE_SHA1
#  define PACKET_ITEM_MAXSIZE \
	( sizeof(struct nu_authreq) + sizeof(struct nu_authfield_ipv6) \
	  + sizeof(struct nu_authfield_app) + PROGNAME_BASE64_WIDTH )
#else
#  error "TODO: Compute PACKET_ITEM_MAXSIZE with SHA1 checksum"
#endif

#define PACKET_SIZE \
	( sizeof(struct nu_header) + CONN_MAX * PACKET_ITEM_MAXSIZE )

enum {
	ERROR_OK = 0,
	ERROR_LOGIN = 1,
	ERROR_NETWORK = 2
};

/* nuauth_session_t structure */

typedef struct {
	/*--------------- PUBLIC MEMBERS -------------------*/
	u_int32_t userid;	/*!< Local user identifier (getuid()) */
	char *username;	/*!< Username (encoded in UTF-8) */
	char *password;	/*!< Password (encoded in UTF-8) */
	/** Callback used to get username */
	char* (*username_callback)();
	/** Callback used to get password */
	char* (*passwd_callback)();

	gnutls_session tls;	/*!< TLS session over TCP socket */
	gnutls_certificate_credentials cred;	/*!< TLS credentials */
	char *tls_password;	/*!< TLS password */
	char *nuauth_cert_dn;

	int socket;	/*!< TCP socket used to exchange message with nuauth */
	conntable_t *ct;	/*!< Connection table */
	u_int32_t packet_seq;	/*!< Packet sequence number (start at zero) */
	int auth_by_default;	/*!< Auth. by default (=1) */
	unsigned char debug_mode;	/*!< Debug mode, enabled if different than zero */
	unsigned char verbose;	/*!< Verbose mode (default: enabled) */
	/* TODO: To remove */ unsigned char diffie_hellman;	/*!< Use Diffie Hellman for key exchange? */
	int has_src_addr;		/*!< Has source address? */
	struct sockaddr_storage src_addr;	/*!< Source address */

	/** Server mode: #SRV_TYPE_POLL or #SRV_TYPE_PUSH */
	u_int8_t server_mode;

	/*------------- PRIVATE MEMBERS ----------------*/

	/** Mutex used in session destruction */
	pthread_mutex_t mutex;

	/**
	 * Flag to signal if user is connected or not.
	 * Connected means that TLS tunnel is opened
	 * and that authentication is done.
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

	/* TODO: To remove */
	/**
	 * Diffie Hellman parameters used to establish TLS tunnel.
	 */
	gnutls_dh_params dh_params;

	/**
	 * Do we need to set credentials to current gnutls session?
	 */
	unsigned char need_set_cred;

	/** Timestamp (Epoch format) of last packet send to nuauth */
	time_t timestamp_last_sent;

	/** Do we need to check the CA certificate */
	unsigned char need_ca_verif;
} nuauth_session_t;

#define NuAuth nuauth_session_t

/** Error family */
typedef enum {
	INTERNAL_ERROR = 0,
	GNUTLS_ERROR = 1,
	SASL_ERROR = 2
} nuclient_error_family_t;

/* INTERNAL ERROR CODES */
enum {
	NO_ERR = 0,	     /** No error */
	SESSION_NOT_CONNECTED_ERR = 1,
	/** Session not connected */
	UNKNOWN_ERR = 2,     /** Unknown error */
	TIMEOUT_ERR = 3,     /** Connection timeout */
	DNS_RESOLUTION_ERR = 4,
	/** DNS resolution error */
	NO_ADDR_ERR = 5,     /** Address not recognized */
	FILE_ACCESS_ERR = 6, /** File access error */
	CANT_CONNECT_ERR = 7,/** Connection failed */
	MEMORY_ERR = 8,	     /** No more memory */
	TCPTABLE_ERR = 9,    /** Fail to read connection table */
	SEND_ERR = 10,	     /** Fail to send packet to nuauth */
	BAD_CREDENTIALS_ERR, /** Username/password error */
	BINDING_ERR,	     /** bind() call failed */
};

/* Define for backward compatibility */
#define nuclient_error nuclient_error_t

/* libnuclient return code structure */
typedef struct {
	nuclient_error_family_t family;
	int error;
} nuclient_error_t;

/* Exported functions */
int nu_client_check(nuauth_session_t *session, nuclient_error_t *err);

int nu_client_error_init(nuclient_error_t **err);
void nu_client_error_destroy(nuclient_error_t *err);

int nu_client_global_init(nuclient_error_t *err);
void nu_client_global_deinit();

nuauth_session_t *nu_client_new(const char *username,
		const char *password,
		unsigned char diffie_hellman,
		nuclient_error_t *err);

nuauth_session_t *nu_client_new_callback(void *username_callback,
		void *passwd_callback,
		unsigned char diffie_hellman,
		nuclient_error_t * err);

void nu_client_set_username(nuauth_session_t *session,
		const char *username);

void nu_client_set_password(nuauth_session_t *session,
		const char *password);

void nu_client_set_debug(nuauth_session_t * session, unsigned char enabled);
void nu_client_set_verbose(nuauth_session_t * session,
		unsigned char enabled);
void nu_client_set_source(nuauth_session_t *session, struct sockaddr_storage *addr);

int nu_client_setup_tls(nuauth_session_t * session,
		char *tls_passwd,
		char *keyfile,
		char *certfile,
		char *cafile, nuclient_error_t *err);

int nu_client_set_nuauth_cert_dn(nuauth_session_t * session,
		char *nuauth_cert_dn,
		nuclient_error_t *err);

int nu_client_connect(nuauth_session_t * session,
		const char *hostname,
		const char *service,
		nuclient_error_t *err);

void nu_client_reset(nuauth_session_t * session);

void nu_client_delete(nuauth_session_t * session);

const char *nu_client_strerror(nuclient_error_t *err);

char *nu_client_to_utf8(const char *inbuf, char *from_charset);

const char *nu_get_version();
int nu_check_version(const char *version);

char *nu_get_home_dir();

int secure_snprintf(char *buffer, unsigned int buffer_size,
		char *format, ...);

#ifdef __cplusplus
}
#endif
#endif   /* #ifndef NUCLIENT_H */


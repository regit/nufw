/*
 ** Copyright 2004-2008 - INL
 ** Written by Eric Leblond <regit@inl.fr>
 **            Vincent Deffontaines <vincent@inl.fr>
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

#ifndef LIBNUCLIENT_H
#define LIBNUCLIENT_H

#ifdef _FEATURES_H
#   error "libnuclient.h have to be included before <features.h>"
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
#include <nussl.h>

#include "nufw_source.h"

#include "nubase.h"
#include "nuclient.h"

/* Constants */
#define SENT_TEST_INTERVAL 30

#ifndef CONNTABLE_BUCKETS
/** Maximum number of connections in connection table, see ::conntable_t */
#define CONNTABLE_BUCKETS 5003
#endif

/*> max number of packets to authenticate in a single tls packet */
#define CONN_MAX 10

#define MIN_DELAY_SEC 0
#define MIN_DELAY_USEC 50*1000
#define MAX_DELAY_SEC 1
#define MAX_DELAY_USEC 600*1000

/* Macros declarations */
#define SET_ERROR(ERR, FAMILY, CODE) \
	if (ERR != NULL) \
	{ \
		ERR->family = FAMILY; \
		ERR->error = CODE; \
	}

#define PACKET_ITEM_MAXSIZE \
	( sizeof(struct nu_authreq) + sizeof(struct nu_authfield_ipv6) \
	  + sizeof(struct nu_authfield_app) + PROGNAME_BASE64_WIDTH )

#define PACKET_SIZE \
	( sizeof(struct nu_header) + CONN_MAX * PACKET_ITEM_MAXSIZE )

/**
 * \def panic(format, ...)
 *
 * Call do_panic(__FILE__, __LINE__, format, ...)
 */
#define panic(format, args...) \
	do_panic(__FILE__, __LINE__, format, ##args )

/**
 * \def nu_assert(test, format, ...)
 *
 * If test fails, call do_panic(__FILE__, __LINE__, format, ...)
 */
#define nu_assert(test, format, args...) \
	do { if (!(test)) do_panic(__FILE__, __LINE__, format, ##args ); } while (0)


/* Type declarations */

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

/* nuauth_session_t structure */

/* -- PRIVATE STRUCTURE -- */
struct nuauth_session {
	nussl_session* nussl;

	u_int32_t userid;	/*!< Local user identifier (getuid()) */
	char *username;	/*!< Username (encoded in UTF-8) */
	char *password;	/*!< Password (encoded in UTF-8) */
	char *pem_key; /* Path to file */
	char *pem_cert; /* Path to file */
	char *pem_ca; /* Path to file */
	char *pem_crl; /* Path to file */
	char *pkcs12_file; /* Path to file */
	char *pkcs12_password; /* Path to file */
	/** Callback used to get username */
	char* (*username_callback)();
	/** Callback used to get password */
	char* (*passwd_callback)();

	char *nuauth_cert_dn;

	char *krb5_service;

	conntable_t *ct;	/*!< Connection table */
	u_int32_t packet_seq;	/*!< Packet sequence number (start at zero) */
	int auth_by_default;	/*!< Auth. by default (=1) */
	unsigned char debug_mode;	/*!< Debug mode, enabled if different than zero */
	unsigned char verbose;	/*!< Verbose mode (default: enabled) */
	unsigned char diffie_hellman;	/*!< Use Diffie Hellman for key exchange? */
	int has_src_addr;		/*!< Has source address? */
	struct sockaddr_storage src_addr;	/*!< Source address */

	/** Server mode: #SRV_TYPE_POLL or #SRV_TYPE_PUSH */
	u_int8_t server_mode;

	/**
	 * Flag to signal if user is connected or not.
	 * Connected means that TLS tunnel is opened
	 * and that authentication is done.
	 */
	unsigned char connected;

	/** Timestamp (Epoch format) of last packet send to nuauth */
	time_t timestamp_last_sent;

	/** sleep delay between check in microseconds */
	struct timeval sleep_delay;

	/** min sleep delay between check in microseconds */
	struct timeval min_sleep_delay;

	/** max sleep delay between check in microseconds */
	struct timeval max_sleep_delay;

	/** Suppress warning when no CA is configured */
	int suppress_ca_warning;

	/** Suppress certificate FQDN verification */
	int suppress_fqdn_verif;

	/** Suppress certificate verification */
	int suppress_cert_verif;
};


/* Funstions declarations */

char *locale_to_utf8(char *inbuf);

void nu_exit_clean(nuauth_session_t * session);

int compare(nuauth_session_t * session, conntable_t * old, conntable_t * new,
	    nuclient_error * err);

void do_panic(const char *filename, unsigned long line, const char *fmt,
	      ...);

void ask_session_end(nuauth_session_t * session);

#endif

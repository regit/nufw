/* nuclient.h, header file for libnuclient
 *
 * Copyright 2004,2005 - INL
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

/*
 * Use POSIX standard, version "IEEE 1003.1-2004",
 * needed to get sigaction for example
 */
#define _POSIX_C_SOURCE 200112L

/**
 * Use 4.3BSD standard, needed to get snprintf for example
 */
#define _BSD_SOURCE

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
/* #warning "this may be a source of problems" */
#include <pthread.h>

#include <gnutls/gnutls.h>
#include <sasl/sasl.h>

/* Disable inline keyword when compiling in strict ANSI conformance */
#ifdef __STRICT_ANSI__
#  define inline
#endif

#define DEBUG 0

#ifndef CONNTABLE_BUCKETS
#define CONNTABLE_BUCKETS 5003
#endif
#define NUAUTH_IP "192.168.1.1"

#define KEYFILE "key.pem"

#define UDP_TIMEOUT 30

/*
 * This structure holds everything we need to know about a connection. We
 * use unsigned long instead of (for example) uid_t, ino_t to make hashing
 * easier.
 */
typedef struct conn {
        unsigned int proto;
	unsigned long lcl;
	unsigned int lclp;
	unsigned long rmt;
	unsigned int rmtp;
	unsigned long uid;
	unsigned long ino;
	unsigned int retransmit;
        time_t  createtime;

	struct conn *next;
} conn_t;

typedef struct conntable {
	conn_t *buckets[CONNTABLE_BUCKETS];
} conntable_t;

/* only publicly seen structure but datas are private */

#define PACKET_SIZE 1482

#define ERROR_OK 0x0
#define ERROR_UNKNOWN 0x1
#define ERROR_LOGIN 0x2
#define ERROR_NETWORK 0x3

/* NuAuth structure */

typedef struct _NuAuth {
	u_int8_t protocol;
	unsigned long userid;
	unsigned long localuserid;
	char * username;
	char * password;
        gnutls_session tls;
	gnutls_certificate_credentials cred;

	char* (*username_callback)();
	char* (*passwd_callback)();
	char* (*tls_passwd_callback)();
	int socket;
        int error;
	struct sockaddr_in adr_srv;
	conntable_t *ct;
	unsigned long packet_id;
        int auth_by_default;
	unsigned char mode;
	/* private ;-) */
	pthread_mutex_t mutex;
	unsigned char connected;
	/* condition and associated mutex used to know when a check
	 * is necessary */
	pthread_cond_t check_cond;
	pthread_mutex_t check_count_mutex;
	int count_msg_cond;
	pthread_t checkthread;
	pthread_t recvthread;
	time_t timestamp_last_sent;
} NuAuth;

/* libnuclient return code structure */

typedef struct _nuclient_error {
        int family;
        int error;
} nuclient_error;

#define INTERNAL_ERROR 0
#define GNUTLS_ERROR 1
#define SASL_ERROR 2

/* INTERNAL ERROR CODES */
#define NOERR 0
#define NO_ERR 0
#define SESSION_NOT_CONNECTED_ERR 1
#define UNKNOWN_ERR 2
#define TIMEOUT_ERR 3
#define DNS_RESOLUTION_ERR 4
#define NO_ADDR_ERR 5
#define FILE_ACCESS_ERR 6
#define CANT_CONNECT_ERR 7

/*typedef enum {
        NOERR,
        SESSION_NOT_CONNECTED,
        UNKNOWN
} internal_errors_t;*/

/* Exported functions */

/* OLD : die now
NuAuth* nu_client_init(char *username, 
                       unsigned long userid, 
                       char * password,
                       const char * hostname, 
                       unsigned int port, 
                       char protocol, 
                       char ssl_on);*/


int	nu_client_check(NuAuth * session, nuclient_error *err);
int     nu_client_error(NuAuth * session, nuclient_error *err);
void 	nu_client_free(NuAuth *session, nuclient_error *err);

int     nuclient_error_init(nuclient_error **err);
void    nuclient_error_destroy(nuclient_error *err);

void nu_client_global_init(nuclient_error *err);
void nu_client_global_deinit(nuclient_error *err);

NuAuth* nu_client_init2(
		const char *hostname, 
                unsigned int port,
		char* keyfile, 
                char* certfile,
		void* username_callback,
                void * passwd_callback, 
                void* tlscred_callback,
                nuclient_error *err
		);

const char* nuclient_strerror (nuclient_error *err);

int secure_snprintf(char *buffer, unsigned int buffer_size, char *format, ...);

#ifdef __cplusplus
}
#endif

#endif

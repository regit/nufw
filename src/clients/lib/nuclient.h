#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
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
#include <crypt.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

#include <gcrypt.h>
//#warning "this may be a source of problems"
#include <pthread.h>
#ifndef GCRY_THREAD
#define GCRY_THREAD 1
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif


#include <gnutls/gnutls.h>
#include <sasl/sasl.h>

#ifndef CONNTABLE_BUCKETS
#define CONNTABLE_BUCKETS 5003
#endif
#define NUAUTH_IP "192.168.1.1"

#define KEYFILE "key.pem"

/*
 * This structure holds everything we need to know about a connection. We
 * use unsigned long instead of (for example) uid_t, ino_t to make hashing
 * easier.
 */
typedef struct conn {
	unsigned long lcl;
	unsigned int lclp;
	unsigned long rmt;
	unsigned int rmtp;
	unsigned long uid;
	unsigned long ino;
	unsigned int retransmit;

	struct conn *next;
} conn_t;

typedef struct conntable {
	conn_t *buckets[CONNTABLE_BUCKETS];
} conntable_t;

/* only publicly seen structure but datas are private */

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
        gnutls_session* tls;
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
} NuAuth;


/* Exported functions */

NuAuth* nu_client_init(char *username, unsigned long userid, char * password,
        const char * hostname, unsigned int port, char protocol, char ssl_on);
int	nu_client_check(NuAuth * session);
int     nu_client_error(NuAuth * session);
void 	nu_client_free(NuAuth *session);

NuAuth* nu_client_init2(
		const char *hostname, unsigned int port,
		char* keyfile, char* certfile,
		void* username_callback,void * passwd_callback, void* tlscred_callback
		);

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

#include <openssl/ssl.h>

extern BIO *bio_err;
int berr_exit (char *string);
int err_exit(char *string);

SSL_CTX *initialize_ctx(char *keyfile, char *password);
void destroy_ctx(SSL_CTX *ctx);

#ifndef ALLOW_OLD_VERSIONS
#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
#error "Must use OpenSSL 0.9.6 or later"
#endif
#endif


#ifndef CONNTABLE_BUCKETS
#define CONNTABLE_BUCKETS 5003
#endif
#define NUAUTH_IP "192.168.1.1"

#define KEYFILE "key.pem"
#define PASSWORD "password"

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

	struct conn *next;
} conn_t;

typedef struct conntable {
	conn_t *buckets[CONNTABLE_BUCKETS];
} conntable_t;

/* only publicly seen structure but datas are private */

typedef struct _NuAuth {
	u_int8_t protocol;
	unsigned long userid;
	unsigned long localuserid;
	char * username;
	char * password;
	SSL* ssl;
	int socket;
	struct sockaddr_in adr_srv;
	conntable_t *ct;
	unsigned long packet_id;
} NuAuth;

/* Exported function */

NuAuth* nu_client_init(char *username,unsigned long userid,char * password, char * hostname, unsigned int port,char protocol,char ssl_on);
int	nu_client_check(NuAuth * session);
void nu_exit_clean(NuAuth * session);

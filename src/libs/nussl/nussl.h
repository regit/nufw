/*
 ** Copyright (C) 2007 INL
 ** Written by S.Tricaud <stricaud@inl.fr>
 **            L.Defert <ldefert@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** $Id: nussl_socket.c 4305 2008-01-11 15:56:09Z lds $
 **
 ** NuSSL: OpenSSL / GnuTLS layer based on libneon
 */

#ifndef NUSSL_H
#define NUSSL_H
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "nussl_constants.h"
#include "nussl_misc.h"

#ifdef __cplusplus
extern "C" {
#endif

struct nussl_nession_t;
typedef struct nussl_session_t nussl_session;
typedef struct nussl_session_server_t nussl_session_server;

typedef void *nussl_ptr;

/* Global library initialisation */
int nussl_init();

/* Create a session to the given server, using the given scheme.  If
 * "https" is passed as the scheme, SSL will be used to connect to the
 * server. */
nussl_session *nussl_session_create();

/* We se the crl refresh capability */
void nussl_set_crl_refresh(nussl_session *sess, int refresh);

/* Finish an HTTP session */
void nussl_session_destroy(nussl_session *sess);

/* Set destination hostname / port */
void nussl_set_hostinfo(nussl_session *sess, const char *hostname, unsigned int port);

/* Open the connection */
int nussl_open_connection(nussl_session* sess);

/* Prematurely force the connection to be closed for the given
 * session. */
void nussl_close_connection(nussl_session* sess);

/* Set the timeout (in seconds) used when reading from a socket.  The
 * timeout value must be greater than zero. */
void nussl_set_read_timeout(nussl_session* sess, int timeout);

/* Set the timeout (in seconds) used when making a connection.  The
 * timeout value must be greater than zero. */
void nussl_set_connect_timeout(nussl_session* sess, int timeout);

/* Retrieve the error string for the session */
const char *nussl_get_error(nussl_session* sess);

/* Write to session */
int nussl_write(nussl_session *sess, char *buffer, size_t count);

/* Read from session */
/* returns the number of octets read on success */
/* returns a NUSSL_SOCK_* error on failure */
ssize_t nussl_read(nussl_session *sess, char *buffer, size_t count);

/* Set private key and certificate */
int nussl_ssl_set_keypair(nussl_session *sess, const char* cert_file, const char* key_file);

/* Set private key and certificate */
int nussl_ssl_set_pkcs12_keypair(nussl_session *sess, const char* cert_file, const char* key_file);

/* Indicate that the certificate 'cert' is trusted */
int nussl_ssl_trust_cert_file(nussl_session* sess, const char *cert_file);

/* Returns a string containing informations about the certificate */
char* nussl_get_cert_infos(nussl_session* sess);

/* Returns a string containing informations about the peer certificate */
char* nussl_get_server_cert_infos(nussl_session* sess);

/* Begin: INL additions */

int nussl_ssl_cert_generate_dh_params(nussl_session *session);
void nussl_ssl_cert_dh_params(nussl_session *session);
int nussl_ssl_cert_set_x509_crl_file(nussl_session *session, const char *crl_file);
int nussl_ssl_context_set_verify(nussl_session *session, int required, const char *verify_cas);

/* Create session server from sock fd */
nussl_session_server *nussl_session_server_create_with_fd(int fd, int verify);

void nussl_session_server_destroy(nussl_session_server *srv_sess);

void nussl_session_server_close_connection(nussl_session_server *srv_sess);

nussl_session* nussl_session_server_new_client(nussl_session_server *srv_sess);

int nussl_session_server_set_keypair(nussl_session *srv_sess, const char* cert_file, const char* key_file);

int nussl_session_getpeer(nussl_session *sess, struct sockaddr *addr, socklen_t *addrlen);

int nussl_session_get_fd(nussl_session *sess);

/* End: INL additions */


#define NUSSL_OK (0) /* Success */
#define NUSSL_ERROR (1) /* Generic error; use nussl_get_error(session) for message */
#define NUSSL_LOOKUP (2) /* Server or proxy hostname lookup failed */
#define NUSSL_AUTH (3) /* User authentication failed on server */
#define NUSSL_PROXYAUTH (4) /* User authentication failed on proxy */
#define NUSSL_CONNECT (5) /* Could not connect to server */
#define NUSSL_TIMEOUT (6) /* Connection timed out */
#define NUSSL_FAILED (7) /* The precondition failed */
#define NUSSL_RETRY (8) /* Retry request (nussl_end_request ONLY) */
#define NUSSL_REDIRECT (9) /* See nussl_redirect.h */

#define NUSSL_SOCK_ERROR (-1)
/* Read/Write timed out */
#define NUSSL_SOCK_TIMEOUT (-2)
/* Socket was closed */
#define NUSSL_SOCK_CLOSED (-3)
/* Connection was reset (e.g. server crashed) */
#define NUSSL_SOCK_RESET (-4)
/* Secure connection was closed without proper SSL shutdown. */
#define NUSSL_SOCK_TRUNC (-5)

#define NUSSL_VALID_REQ_TYPE(n) (n >= NUSSL_CERT_IGNORE && n <= NUSSL_CERT_REQUIRE)

#ifdef __cplusplus
}
#endif

#endif /* NUSSL_H */


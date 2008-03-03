#include "nussl_session.h"
#include "nussl_private.h" /* XXX: Should we add this?*/

#ifndef NUSSL_SESSION_SERVER_H
#define NUSSL_SESSION_SERVER_H 1

NUSSL_BEGIN_DECLS

typedef struct nussl_session_server_s nussl_session_server;

/* Create session server from sock fd */
nussl_session_server *nussl_session_server_create_with_fd(int fd, int verify);

void nussl_session_server_destroy(nussl_session_server *srv_sess);

void nussl_session_server_close_connection(nussl_session_server *srv_sess);

nussl_session* nussl_session_server_new_client(nussl_session_server *srv_sess);

int nussl_session_server_set_keypair(nussl_session_server *srv_sess, const char* cert_file, const char* key_file);

NUSSL_END_DECLS

#endif /* NUSSL_SESSION_SERVER_H  */


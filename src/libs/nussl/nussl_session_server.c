#include <stdlib.h>
#include <stdio.h>

#include "nussl_session_server.h"
#include "nussl_socket.h"
#include "nussl_utils.h"

nussl_session_server *nussl_session_server_create_with_fd(int server_fd)
{
	nussl_session_server *srv_sess;
	srv_sess = malloc(sizeof(*srv_sess));
	if ( ! srv_sess ) {
		printf("Out of memory\n");
		return NULL;
	}

	srv_sess->socket = nussl_sock_create_with_fd(server_fd);
	srv_sess->ssl_context = nussl_ssl_context_create(0);

	return srv_sess;
}

void nussl_session_server_destroy(nussl_session_server *srv_sess)
{
	nussl_session_server_close_connection(srv_sess);
	free(srv_sess);
}

void nussl_session_server_close_connection(nussl_session_server *srv_sess)
{
	nussl_sock_close(srv_sess->socket);
	srv_sess->socket = NULL;
}

/* Verify: one of NUSSL_CERT_IGNORE, NUSSL_CERT_REQUEST or NUSSL_CERT_REQUIRE */
nussl_session* nussl_session_server_new_client(nussl_session_server *srv_sess, int verify)
{
	nussl_session* client_sess = nussl_session_create();

	if (!client_sess) {
		return NULL;
	}

	client_sess->socket = nussl_sock_create();

	if (nussl_sock_accept(client_sess->socket, nussl_sock_fd(srv_sess->socket)) != 0) {
		printf("Error during accept()\n");
		nussl_session_destroy(client_sess);
		return NULL;
	}

	client_sess->ssl_context->verify = verify;

	nussl_sock_accept_ssl(client_sess->socket, srv_sess->ssl_context);

	return client_sess;
}

int nussl_session_server_set_keypair(nussl_session *srv_sess, const char* cert_file, const char* key_file)
{
	nussl_ssl_client_cert* cert;
	int ret;

	if (check_key_perms(key_file)!= NUSSL_OK)
	{
		/* TODO: use nussl_set_error instead */
		fprintf(stdout, "Permissions on private key %s are not restrictive enough, it should be readable only by its owner.", key_file);

		return NUSSL_ERROR;
	}

	cert = nussl_ssl_import_keypair(cert_file, key_file);
	if (cert == NULL)
	{
		fprintf(stdout, "Unable to load private key or certificate file");

		return NUSSL_ERROR;
	}

	ret = nussl_session_server_set_clicert(srv_sess, cert);

	return ret;
}

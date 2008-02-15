/*
 * Various functions that must be done a better way
 * but are here to wrap things we need easily
 */

#include <gnutls/gnutls.h>

#include "nussl.h"
#include "nussl_misc.h"
#include "nussl_privssl.h"

void nussl_misc_set_fd_and_push(gnutls_session *session, nussl_ptr fd, gnutls_push_func push_func)
{
//	nussl_ssl_socket sock;

//	sock = session->socket->ssl;

	gnutls_transport_set_ptr(session, fd);
	gnutls_transport_set_push_function(session, push_func);

}


/*
 * Various functions that must be done a better way
 * but are here to wrap things we need easily
 */

#include <gnutls/gnutls.h>

#include "nussl.h"
#include "nussl_misc.h"

void nussl_misc_set_fd_and_push(nussl_session *session, nussl_ptr fd, gnutls_push_func push_func)
{
#if 0
	nussl_ssl_socket ssl_session;

	gnutls_transport_set_ptr(ssl_session, fd);
	gnutls_transport_set_push_function(ssl_session, tls_push_func);
#endif

}


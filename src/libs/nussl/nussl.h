/*
 ** Copyright (C) 2007-2009 INL
 ** Written by S.Tricaud <stricaud@inl.fr>
 **            L.Defert <ldefert@inl.fr>
 **            Pierre Chifflier <chifflier@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** NuSSL: OpenSSL / GnuTLS layer based on libneon

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
   MA 02111-1307, USA

   In addition, as a special exception, INL
   gives permission to link the code of its release of NuSSL with the
   OpenSSL project's "OpenSSL" library (or with modified versions of it
   that use the same license as the "OpenSSL" library), and distribute
   the linked executables.  You must obey the GNU General Public License
   in all respects for all of the code used other than "OpenSSL".  If you
   modify this file, you may extend this exception to your version of the
   file, but you are not obligated to do so.  If you do not wish to do
   so, delete this exception statement from your version.
 */

#ifndef NUSSL_H
#define NUSSL_H
#include <stdio.h>
#include <sys/types.h>

#include "nussl_constants.h"

#ifdef __cplusplus
extern "C" {
#endif

	struct nussl_nession_t;
	typedef struct nussl_session_t nussl_session;

	typedef void *nussl_ptr;

/* Global library initialisation */
	int nussl_init();

/* Create a session to the given server, using the given mode.
 * mode can be one of NUSSL_SSL_CTX_CLIENT, NUSSL_SSL_CTX_SERVER,
 * or NUSSL_SSL_CTX_SERVERv2 */
	nussl_session *nussl_session_create(int mode);

/* Finish an HTTP session */
	void nussl_session_destroy(nussl_session * sess);

/* Set destination hostname / port */
	void nussl_set_hostinfo(nussl_session * sess, const char *hostname,
				unsigned int port);

/* Open the connection */
	int nussl_open_connection(nussl_session * sess);

/* Prematurely force the connection to be closed for the given
 * session. */
	void nussl_close_connection(nussl_session * sess);

/* Set the timeout (in seconds) used when reading from a socket.  The
 * timeout value must be greater than zero. */
	void nussl_set_read_timeout(nussl_session * sess, int timeout);

/* Set the timeout (in seconds) used when making a connection.  The
 * timeout value must be greater than zero. */
	void nussl_set_connect_timeout(nussl_session * sess, int timeout);

/* Retrieve the error string for the session */
	const char *nussl_get_error(nussl_session * sess);

/* Write to session */
	int nussl_write(nussl_session * sess, const char *buffer, size_t count);

/* Read from session */
/* returns the number of octets read on success */
/* returns a NUSSL_SOCK_* error on failure */
	ssize_t nussl_read(nussl_session * sess, char *buffer,
			   size_t count);

/* Set private key and certificate */
	int nussl_ssl_set_keypair(nussl_session * sess,
				  const char *cert_file,
				  const char *key_file);

/* Set private key and certificate */
	int nussl_ssl_set_pkcs12_keypair(nussl_session * sess,
					 const char *cert_file,
					 const char *key_file);

/* Indicate that the certificate 'cert' is trusted */
	int nussl_ssl_trust_cert_file(nussl_session * sess,
				      const char *cert_file);

/* Add directory of trusted certificates */
	int nussl_ssl_trust_dir(nussl_session * sess,
				      const char *dir);

/* TODO: factorize those functions */
/* Returns a string containing informations about the certificate */
	char *nussl_get_cert_info(nussl_session * sess);

/* Returns a string containing informations about the peer certificate */
	char *nussl_get_server_cert_info(nussl_session * sess);

/* Returns a string containing informations about the peer certificate */
	char *nussl_get_server_cert_dn(nussl_session * sess);

/* Returns a string containing informations about the peer certificate */
	char *nussl_get_peer_dn(nussl_session * sess, char *buf,
				size_t * buf_size);

/* Server related functions */
/* Create session server from sock fd */
	nussl_session *nussl_session_create_with_fd(int fd, int verify);

	nussl_session *nussl_session_accept(nussl_session * srv_sess);

	int nussl_session_handshake(nussl_session * client_sess,
				    nussl_session * srv_sess);

	int nussl_session_get_fd(nussl_session * sess);

/* Set list of allowed ciphers for TLS negotiation */
	void nussl_session_set_ciphers(nussl_session * sess, const char *cipher_list);

	int nussl_session_get_cipher(nussl_session * sess, char *buf, size_t bufsz);

	int nussl_session_getpeer(nussl_session * sess,
				  struct sockaddr *addr,
				  socklen_t * addrlen);

	int nussl_session_set_dh_bits(nussl_session * sess,
				      unsigned int dh_bits);

	int nussl_session_set_dh_file(nussl_session * sess,
				      const char *filename);

	int nussl_ssl_set_crl_file(nussl_session * sess, const char *crl_file, const char *ca_file);

	void nussl_ssl_disable_certificate_check(nussl_session * sess, int is_disabled);

	/* Set a new value for a particular session flag. */
	void nussl_set_session_flag(nussl_session * sess,
		nussl_session_flag flag,
		int value);

	int nussl_get_session_flag(nussl_session * sess,
		nussl_session_flag flag);

	void *nussl_get_ctx(nussl_session * sess);

	void *nussl_get_socket(nussl_session * sess);

#define NUSSL_VALID_REQ_TYPE(n) (n >= NUSSL_CERT_IGNORE && n <= NUSSL_CERT_REQUIRE)

	/* local check of certificate against CA and CRL (optional) */
	int nussl_local_check_certificate(const char *cert,
		const char *ca_cert,
		const char *ca_path,
		const char *crl,
		char *ret_message,
		size_t message_sz);

#ifdef __cplusplus
}
#endif
#endif				/* NUSSL_H */

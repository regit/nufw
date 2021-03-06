/*
 ** Copyright (C) 2007-2009 INL
 ** Written by S.Tricaud <stricaud@inl.fr>
 **            L.Defert <ldefert@inl.fr>
 **            Pierre Chifflier <chifflier@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** NuSSL: OpenSSL / GnuTLS layer based on libneon
 *
 * ChangeLog:
 * 2008-22-01: Sebastien Tricaud
 *              * Added dh parameter to nussl_ssl_context_t
 */


/*
   SSL interface definitions internal to neon.
   Copyright (C) 2003-2005, Joe Orton <joe@manyfish.co.uk>
   Copyright (C) 2004, Aleix Conchillo Flaque <aleix@member.fsf.org>

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

/* THIS IS NOT A PUBLIC INTERFACE. You CANNOT include this header file
 * from an application.  */

#ifndef NUSSL_PRIVSSL_H
#define NUSSL_PRIVSSL_H

/* This is the private interface between nussl_socket, nussl_gnutls and
 * nussl_openssl. */

#include <config.h>
#include "nussl_config.h"

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

#include "nussl_ssl.h"
#include "nussl_socket.h"

#define DH_BITS 1024
#define NUSSL_OP_RETRY 3

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>

struct nussl_ssl_context_s {
	SSL_CTX *ctx;
	SSL_SESSION *sess;
	const char *hostname;	/* for SNI */
	int verify;		/* non-zero if client cert verification required */

	char *ciphers; /* allowed cipher list */

	DH *dh;
};

typedef SSL *nussl_ssl_socket;

#endif				/* HAVE_OPENSSL */

#ifdef HAVE_GNUTLS

#include <gnutls/gnutls.h>

struct nussl_ssl_context_s {
	gnutls_certificate_credentials cred;
	gnutls_dh_params dh;
	unsigned int dh_bits;
	int verify;		/* non-zero if client cert verification required */

	char *ciphers; /* allowed cipher list */

	int use_cert;

	const char *hostname;	/* for SNI */

	/* Session cache. */
	union nussl_ssl_scache {
		struct {
			gnutls_datum key, data;
		} server;
#if defined(HAVE_GNUTLS_SESSION_GET_DATA2)
		gnutls_datum client;
#else
		struct {
			char *data;
			size_t len;
		} client;
#endif
	} cache;
};

typedef gnutls_session nussl_ssl_socket;

#endif				/* HAVE_GNUTLS */

nussl_ssl_socket nussl__sock_sslsock(nussl_socket * sock);

/* Process-global initialization of the SSL library; returns non-zero
 * on error. */
int nussl__ssl_init(void);

/* Process-global de-initialization of the SSL library. */
void nussl__ssl_exit(void);

/* Set certificate verification options */
int nussl_ssl_context_set_verify(nussl_ssl_context * ctx,
				 int required,
				 const char *ca_names,
				 const char *verify_cas);


/* SSL accept function (with handshake), with timeout.
 * If timeout is 0, use blocking mode
 */
int nussl_ssl_accept(nussl_ssl_socket * ssl_sock, unsigned int timeout, char *errbuf, size_t errbufsz);

#endif				/* NUSSL_PRIVSSL_H */

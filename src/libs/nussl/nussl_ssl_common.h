/*
 ** Copyright (C) 2007-2009 INL
 ** Written by S.Tricaud <stricaud@inl.fr>
 **            L.Defert <ldefert@inl.fr>
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

#ifndef NUSSL_SSL_COMMON_H
#define NUSSL_SSL_COMMON_H

#include <config.h>
#include "nussl_config.h"
#include "nussl_privssl.h"
#include "nussl_session.h"

#ifdef HAVE_GNUTLS
#include <gnutls/gnutls.h>
#include <gnutls/pkcs12.h>

struct nussl_ssl_dname_s {
	int subject;		/* non-zero if this is the subject DN object */
	gnutls_x509_crt cert;
};

struct nussl_ssl_certificate_s {
	nussl_ssl_dname subj_dn, issuer_dn;
	gnutls_x509_crt subject;
	nussl_ssl_certificate *issuer;
	char *identity;
};

struct nussl_ssl_client_cert_s {
	gnutls_pkcs12 p12;
	int decrypted;		/* non-zero if successfully decrypted. */
	nussl_ssl_certificate cert;
	gnutls_x509_privkey pkey;
	char *friendly_name;
};
#endif				/* HAVE_GNUTLS */

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>

struct nussl_ssl_dname_s {
	X509_NAME *dn;
};

struct nussl_ssl_certificate_s {
	nussl_ssl_dname subj_dn, issuer_dn;
	X509 *subject;
	nussl_ssl_certificate *issuer;
	char *identity;
};

struct nussl_ssl_client_cert_s {
	PKCS12 *p12;
	int decrypted;		/* non-zero if successfully decrypted. */
	nussl_ssl_certificate cert;
	EVP_PKEY *pkey;
	char *friendly_name;
};
#endif

#endif				/* NUSSL_SSL_COMMON_H */

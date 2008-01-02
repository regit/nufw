/*
 ** Copyright (C) 2007 INL
 ** Written by S.Tricaud <stricaud@inl.fr>
 **            L.Defert <ldefert@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** $Id$
 **
 ** NuSSL: OpenSSL / GnuTLS layer based on libneon
 */


/*
   SSL/TLS abstraction layer for neon
   Copyright (C) 2003-2006, Joe Orton <joe@manyfish.co.uk>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
   MA 02111-1307, USA

*/

/* nussl_ssl.h defines an interface for loading and accessing the
 * properties of SSL certificates. */

#ifndef NUSSL_SSL_H
#define NUSSL_SSL_H 1

#include <sys/types.h>

#include "nussl_defs.h"

NUSSL_BEGIN_DECLS

/* A "distinguished name"; a unique name for some entity. */
typedef struct nussl_ssl_dname_s nussl_ssl_dname;

/* Returns a single-line string representation of a distinguished
 * name, intended to be human-readable (e.g. "Acme Ltd., Norfolk,
 * GB").  Return value is a UTF-8-encoded malloc-allocated string and
 * must be free'd by the caller. */
char *nussl_ssl_readable_dname(const nussl_ssl_dname *dn);

/* Returns zero if 'dn1' and 'dn2' refer to same name, or non-zero if
 * they are different. */
int nussl_ssl_dname_cmp(const nussl_ssl_dname *dn1, const nussl_ssl_dname *dn2);

/* An SSL certificate. */
typedef struct nussl_ssl_certificate_s nussl_ssl_certificate;

/* Read a certificate from a file in PEM format; returns NULL if the
 * certificate could not be parsed. */
nussl_ssl_certificate *nussl_ssl_cert_read(const char *filename);

/* Write a certificate to a file in PEM format; returns non-zero if
 * the certificate could not be written. */
int nussl_ssl_cert_write(const nussl_ssl_certificate *cert, const char *filename);

/* Export a certificate to a base64-encoded, NUL-terminated string.
 * The returned string is malloc-allocated and must be free()d by the
 * caller. */
char *nussl_ssl_cert_export(const nussl_ssl_certificate *cert);

/* Import a certificate from a base64-encoded string as returned by
 * nussl_ssl_cert_export(). Returns a certificate object or NULL if
 * 'data' was not valid. */
nussl_ssl_certificate *nussl_ssl_cert_import(const char *data);

/* Returns the identity of the certificate, or NULL if none is given.
 * For a server certificate this will be the hostname of the server to
 * which the cert was issued.  String returned is UTF-8-encoded. */
const char *nussl_ssl_cert_identity(const nussl_ssl_certificate *cert);

/* Return the certificate of the entity which signed certificate
 * 'cert'.  Returns NULL if 'cert' is self-signed or the issuer
 * certificate is not available. */
const nussl_ssl_certificate *nussl_ssl_cert_signedby(const nussl_ssl_certificate *cert);

/* Returns the distinguished name of the certificate issuer. */
const nussl_ssl_dname *nussl_ssl_cert_issuer(const nussl_ssl_certificate *cert);

/* Returns the distinguished name of the certificate subject. */
const nussl_ssl_dname *nussl_ssl_cert_subject(const nussl_ssl_certificate *cert);

#define NUSSL_SSL_DIGESTLEN (60)

/* Calculate the certificate digest ("fingerprint") and format it as a
 * NUL-terminated hex string in 'digest', of the form "aa:bb:...:ff".
 * Returns zero on success or non-zero if there was an internal error
 * whilst calculating the digest.  'digest' must be at least
 * NUSSL_SSL_DIGESTLEN bytes in length. */
int nussl_ssl_cert_digest(const nussl_ssl_certificate *cert, char *digest);

/* Copy the validity times for the certificate 'cert' into 'from' and
 * 'until' (either may be NULL).  If the time cannot be represented by
 * a time_t value, then (time_t)-1 will be written. */
void nussl_ssl_cert_validity_time(const nussl_ssl_certificate *cert,
                               time_t *from, time_t *until);

#define NUSSL_SSL_VDATELEN (30)
/* Copy the validity times into buffers 'from' and 'until' as
 * NUL-terminated human-readable strings, using RFC 1123-style date
 * formatting (and not localized, so always using English month/week
 * names).  The buffers must be at least NUSSL_SSL_VDATELEN bytes in
 * length, and either may be NULL. */
void nussl_ssl_cert_validity(const nussl_ssl_certificate *cert,
                          char *from, char *until);

/* Returns zero if 'c1' and 'c2' refer to the same certificate, or
 * non-zero otherwise. */
int nussl_ssl_cert_cmp(const nussl_ssl_certificate *c1,
                    const nussl_ssl_certificate *c2);

/* Deallocate memory associated with certificate. */
void nussl_ssl_cert_free(nussl_ssl_certificate *cert);

/* A client certificate (and private key). */
typedef struct nussl_ssl_client_cert_s nussl_ssl_client_cert;

/* Read a client certificate and private key from a PKCS12 file;
 * returns NULL if the file could not be parsed, or otherwise
 * returning a client certificate object. */
nussl_ssl_client_cert *nussl_ssl_clicert_read(const char *filename);

/* Returns the "friendly name" given for the client cert, or NULL if
 * none given.  This can be called before or after the client cert has
 * been decrypted.  Returns a NUL-terminated, UTF-8-encoded string. */
const char *nussl_ssl_clicert_name(const nussl_ssl_client_cert *ccert);

/* Returns non-zero if client cert is encrypted. */
int nussl_ssl_clicert_encrypted(const nussl_ssl_client_cert *ccert);

/* Decrypt the encrypted client cert using given password.  Returns
 * non-zero on failure, in which case, the function can be called
 * again with a different password.  For a ccert on which _encrypted()
 * returns 0, calling _decrypt results in undefined behaviour. */
int nussl_ssl_clicert_decrypt(nussl_ssl_client_cert *ccert, const char *password);

/* Return the actual certificate part of the client certificate (never
 * returns NULL). */
const nussl_ssl_certificate *nussl_ssl_clicert_owner(const nussl_ssl_client_cert *ccert);

/* Destroy a client certificate object. */
void nussl_ssl_clicert_free(nussl_ssl_client_cert *ccert);



/* SSL context object.  The interfaces to manipulate an SSL context
 * are only needed when interfacing directly with nussl_socket.h. */
typedef struct nussl_ssl_context_s nussl_ssl_context;

/* Context creation modes: */
#define NUSSL_SSL_CTX_CLIENT (0) /* client context */
#define NUSSL_SSL_CTX_SERVER (1) /* default server context */
#define NUSSL_SSL_CTX_SERVERv2 (2) /* SSLv2-specific server context */

/* Create an SSL context. */
nussl_ssl_context *nussl_ssl_context_create(int mode);

/* Client mode: trust the given certificate 'cert' in context 'ctx'. */
int nussl_ssl_context_trustcert(nussl_ssl_context *ctx, const nussl_ssl_certificate *cert);

/* Set the client certificate */
int nussl_ssl_context_keypair_from_data(nussl_ssl_context *ctx, nussl_ssl_client_cert* cert);

/* Server mode: use given cert and key (filenames to PEM certificates). */
int nussl_ssl_context_keypair(nussl_ssl_context *ctx,
                           const char *cert, const char *key);

/* Server mode: set client cert verification options: required is non-zero if
 * a client cert is required, if ca_names is non-NULL it is a filename containing
 * a set of PEM certs from which CA names are sent in the ccert request. */
int nussl_ssl_context_set_verify(nussl_ssl_context *ctx, int required,
                              const char *ca_names, const char *verify_cas);

#define NUSSL_SSL_CTX_SSLv2 (0)
/* Set a flag for the SSL context. */
void nussl_ssl_context_set_flag(nussl_ssl_context *ctx, int flag, int value);

/* Destroy an SSL context. */
void nussl_ssl_context_destroy(nussl_ssl_context *ctx);

NUSSL_END_DECLS

#endif

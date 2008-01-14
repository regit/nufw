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
   HTTP session handling
   Copyright (C) 1999-2007, Joe Orton <joe@manyfish.co.uk>

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

#ifndef NUSSL_SESSION_H
#define NUSSL_SESSION_H 1

#include <sys/types.h>

#include "nussl_ssl.h"
/* #include "nussl_uri.h" /\* for nussl_uri *\/ */
#include "nussl_defs.h"
#include "nussl_socket.h"
#include "nussl_privssl.h"

NUSSL_BEGIN_DECLS

typedef struct nussl_session_s nussl_session;

/* Create a session to the given server, using the given scheme.  If
 * "https" is passed as the scheme, SSL will be used to connect to the
 * server. */
nussl_session *nussl_session_create();

/* Finish an HTTP session */
void nussl_session_destroy(nussl_session *sess);

/* Prematurely force the connection to be closed for the given
 * session. */
void nussl_close_connection(nussl_session *sess);

/* Set the proxy server to be used for the session. */
/*void nussl_session_proxy(nussl_session *sess,
		      const char *hostname, unsigned int port);
*/
/* Defined session flags: */
typedef enum nussl_session_flag_e {
    NUSSL_SESSFLAG_PERSIST = 0, /* disable this flag to prevent use of
                              * persistent connections. */

    NUSSL_SESSFLAG_ICYPROTO, /* enable this flag to enable support for
                           * non-HTTP ShoutCast-style "ICY" responses. */

    NUSSL_SESSFLAG_SSLv2, /* disable this flag to disable support for
                        * SSLv2, if supported by the SSL library. */

    NUSSL_SESSFLAG_RFC4918, /* enable this flag to enable support for
                          * RFC4918-only WebDAV features; losing
                          * backwards-compatibility with RFC2518
                          * servers. */

    NUSSL_SESSFLAG_CONNAUTH, /* enable this flag if an awful, broken,
                           * RFC-violating, connection-based HTTP
                           * authentication scheme is in use. */

    NUSSL_SESSFLAG_TLS_SNI, /* disable this flag to disable use of the
                          * TLS Server Name Indication extension. */

    NUSSL_SESSFLAG_LAST /* enum sentinel value */
} nussl_session_flag;

/* Set a new value for a particular session flag. */
void nussl_set_session_flag(nussl_session *sess, nussl_session_flag flag, int value);

/* Return 0 if the given flag is not set, >0 it is set, or -1 if the
 * flag is not supported. */
int nussl_get_session_flag(nussl_session *sess, nussl_session_flag flag);

/* Bypass the normal name resolution; force the use of specific set of
 * addresses for this session, addrs[0]...addrs[n-1].  The addrs array
 * must remain valid until the session is destroyed. */
void nussl_set_addrlist(nussl_session *sess, const nussl_inet_addr **addrs, size_t n);

/* DEPRECATED: Progress callback. */
typedef void (*nussl_progress)(void *userdata, nussl_off_t progress, nussl_off_t total);

/* DEPRECATED API: Set a progress callback for the session; this is
 * deprecated in favour of nussl_set_notifier().  The progress callback
 * is invoked for after each block of the request and response body to
 * indicate request and response progress (there is no way to
 * distinguish between the two using this interface alone).
 *
 * NOTE: Use of this interface is mutually exclusive with the use of
 * nussl_set_notifier().  A call to nussl_set_progress() removes the
 * notifier callback, and vice versa. */
void nussl_set_progress(nussl_session *sess, nussl_progress progress, void *userdata);

/* Store an opaque context for the session, 'priv' is returned by a
 * call to nussl_session_get_private with the same ID. */
void nussl_set_session_private(nussl_session *sess, const char *id, void *priv);
void *nussl_get_session_private(nussl_session *sess, const char *id);

/* Status event type.  NOTE: More event types may be added in
 * subsequent releases, so callers must ignore unknown status types
 * for forwards-compatibility.  */
typedef enum {
    nussl_status_lookup = 0, /* looking up hostname */
    nussl_status_connecting, /* connecting to host */
    nussl_status_connected, /* connected to host */
    nussl_status_sending, /* sending a request body */
    nussl_status_recving, /* receiving a response body */
    nussl_status_disconnected /* disconnected from host */
} nussl_session_status;

/* Status event information union; the relevant structure within
 * corresponds to the event type.  WARNING: the size of this union is
 * not limited by ABI constraint; it may be extended with additional
 * members of different size, or existing members may be extended. */
typedef union nussl_session_status_info_u {
    struct /* nussl_status_lookup */ {
        /* The hostname which is being resolved: */
        const char *hostname;
    } lu;
    struct /* nussl_status_connecting */ {
        /* The hostname and network address to which a connection
         * attempt is being made: */
        const char *hostname;
        const nussl_inet_addr *address;
    } ci;
    struct /* nussl_status_connected, nussl_status_disconnected */ {
        /* The hostname to which a connection has just been
         * established or closed: */
        const char *hostname;
    } cd;
    struct /* nussl_status_sending and nussl_status_recving */ {
        /* Request/response body transfer progress; if total == -1, the
         * total size is unknown; else 0 <= progress <= total:  */
        nussl_off_t progress, total;
    } sr;
} nussl_session_status_info;

/* Callback invoked to notify a new session status event, given by the
 * 'status' argument.  On invocation, the contents of exactly one of
 * the structures in the info union will be valid, as indicated
 * above. */
typedef void (*nussl_notify_status)(void *userdata, nussl_session_status status,
                                 const nussl_session_status_info *info);

/* Set a status notification callback for the session, to report
 * session status events.  Only one notification callback per session
 * can be registered; the most recent of successive calls to this
 * function takes effect. Note that
 *
 * NOTE: Use of this interface is mutually exclusive with the use of
 * nussl_set_progress().  A call to nussl_set_notifier() removes the
 * progress callback, and vice versa. */
void nussl_set_notifier(nussl_session *sess, nussl_notify_status status, void *userdata);

/* Certificate verification failures.
 * The certificate is not yet valid: */
#define NUSSL_SSL_NOTYETVALID (0x01)
/* The certificate has expired: */
#define NUSSL_SSL_EXPIRED (0x02)
/* The hostname for which the certificate was issued does not
 * match the hostname of the server; this could mean that the
 * connection is being intercepted: */
#define NUSSL_SSL_IDMISMATCH (0x04)
/* The certificate authority which signed the server certificate is
 * not trusted: there is no indicatation the server is who they claim
 * to be: */
#define NUSSL_SSL_UNTRUSTED (0x08)

/* The bitmask of known failure bits: if (failures & ~NUSSL_SSL_FAILMASK)
 * is non-zero, an unrecognized failure is given, and the verification
 * should be failed. */
#define NUSSL_SSL_FAILMASK (0x0f)

#if 0
/* A callback which is used when server certificate verification is
 * needed.  The reasons for verification failure are given in the
 * 'failures' parameter, which is a binary OR of one or more of the
 * above NUSSL_SSL_* values. failures is guaranteed to be non-zero.  The
 * callback must return zero to accept the certificate: a non-zero
 * return value will fail the SSL negotiation. */
typedef int (*nussl_ssl_verify_fn)(void *userdata, int failures,
				const nussl_ssl_certificate *cert);

/* Install a callback to handle server certificate verification.  This
 * is required when the CA certificate is not known for the server
 * certificate, or the server cert has other verification problems. */
void nussl_ssl_set_verify(nussl_session *sess, nussl_ssl_verify_fn fn, void *userdata);
#endif

/* Use the given client certificate for the session.  The client cert
 * MUST be in the decrypted state, otherwise behaviour is undefined.
 * The 'clicert' object is duplicated internally so can be destroyed
 * by the caller.  */
int nussl_ssl_set_clicert(nussl_session *sess, const nussl_ssl_client_cert *clicert);

#if 0
/* Indicate that the certificate 'cert' is trusted; the 'cert' object
 * is duplicated internally so can be destroyed by the caller.  This
 * function has no effect for non-SSL sessions. */
void nussl_ssl_trust_cert(nussl_session *sess, const nussl_ssl_certificate *cert);

/* If the SSL library provided a default set of CA certificates, trust
 * this set of CAs. */
void nussl_ssl_trust_default_ca(nussl_session *sess);

/* Callback used to load a client certificate on demand.  If dncount
 * is > 0, the 'dnames' array dnames[0] through dnames[dncount-1]
 * gives the list of CA names which the server indicated were
 * acceptable.  The callback should load an appropriate client
 * certificate and then pass it to 'nussl_ssl_set_clicert'. */
typedef void (*nussl_ssl_provide_fn)(void *userdata, nussl_session *sess,
				  const nussl_ssl_dname *const *dnames,
                                  int dncount);

/* Register a function to be called when the server requests a client
 * certificate. */
void nussl_ssl_provide_clicert(nussl_session *sess,
                            nussl_ssl_provide_fn fn, void *userdata);
#endif

/* Set the timeout (in seconds) used when reading from a socket.  The
 * timeout value must be greater than zero. */
void nussl_set_read_timeout(nussl_session *sess, int timeout);

/* Set the timeout (in seconds) used when making a connection.  The
 * timeout value must be greater than zero. */
void nussl_set_connect_timeout(nussl_session *sess, int timeout);

/* Set the error string for the session; takes printf-like format
 * string. */
void nussl_set_error(nussl_session *sess, const char *format, ...)
    nussl_attribute((format (printf, 2, 3)));

/* Retrieve the error string for the session */
const char *nussl_get_error(nussl_session *sess);

/* Set destination hostname / port */
void nussl_set_hostinfo(nussl_session* sess, const char *hostname, unsigned int port);

/* Write to session */
int nussl_write(nussl_session *session, char *buffer, size_t count);

/* Read from session */
ssize_t nussl_read(nussl_session *session, char *buffer, size_t count);

/* Set private key and certificate */
int nussl_ssl_set_keypair(nussl_session *session, const char* cert_file, const char* key_file);

/* Set private key and certificate */
int nussl_ssl_set_pkcs12_keypair(nussl_session *session, const char* cert_file, const char* key_file);

/* Indicate that the certificate 'cert' is trusted */
int nussl_ssl_trust_cert_file(nussl_session *sess, const char *cert_file);

nussl_ssl_client_cert* nussl_ssl_import_keypair(nussl_session* session, const char* cert_file, const char* key_file);

char* nussl_get_cert_infos(nussl_session* sess);
char* nussl_get_server_cert_infos(nussl_session* sess);
int nussl_init();

NUSSL_END_DECLS

#endif /* NUSSL_SESSION_H */

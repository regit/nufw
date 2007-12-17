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
   HTTP Request Handling
   Copyright (C) 1999-2006, Joe Orton <joe@manyfish.co.uk>

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

/* THIS IS NOT A PUBLIC INTERFACE. You CANNOT include this header file
 * from an application.  */
 
#ifndef NE_PRIVATE_H
#define NE_PRIVATE_H

/* #include "nussl_request.h" */
#include "nussl_socket.h"
#include "nussl_ssl.h"

struct host_info {
    char *hostname;
    unsigned int port;
    ne_sock_addr *address; /* if non-NULL, result of resolving 'hostname'. */
    /* current network address obtained from 'address' being used. */
    const ne_inet_addr *current;
};

/* Store every registered callback in a generic container, and cast
 * the function pointer when calling it.  */
struct hook {
    void (*fn)(void);
    void *userdata;
    const char *id; /* non-NULL for accessors. */
    struct hook *next;
};

#define HAVE_HOOK(st,func) (st->hook->hooks->func != NULL)
#define HOOK_FUNC(st, func) (*st->hook->hooks->func)

/* Session support. */
struct ne_session_s {
    /* Connection information */
    ne_socket *socket;

    /* non-zero if connection has been established. */
    int connected;
    
    /* non-zero if connection has persisted beyond one request. */
    int persisted;

    struct host_info server;

    /* application-provided address list */
    const ne_inet_addr **addrlist;
    size_t numaddrs, curaddr;

    int flags[NE_SESSFLAG_LAST];

    int rdtimeout, cotimeout; /* read, connect timeouts. */

#ifdef NE_HAVE_SSL
    ne_ssl_client_cert *client_cert;
    ne_ssl_certificate *server_cert;
    ne_ssl_context *ssl_context;
#endif

    /* Server cert verification callback: */
    ne_ssl_verify_fn ssl_verify_fn;
    void *ssl_verify_ud;
    /* Client cert provider callback: */
    ne_ssl_provide_fn ssl_provide_fn;
    void *ssl_provide_ud;

    ne_session_status_info status;

    /* Error string */
    char error[512];
};

/* Pushes block of 'count' bytes at 'buf'. Returns non-zero on
 * error. */
typedef int (*ne_push_fn)(void *userdata, const char *buf, size_t count);

/* Do the SSL negotiation. */
int ne__negotiate_ssl(ne_session *sess);

/* Set the session error appropriate for SSL verification failures. */
void ne__ssl_set_verify_err(ne_session *sess, int failures);

#endif /* HTTP_PRIVATE_H */
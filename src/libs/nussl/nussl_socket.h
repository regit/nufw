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
   socket handling interface
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

#ifndef NUSSL_SOCKET_H
#define NUSSL_SOCKET_H

#include <sys/types.h>

#include "nussl_defs.h"
#include "nussl_ssl.h" /* for nussl_ssl_context */

NUSSL_BEGIN_DECLS

/* nussl_socket represents a TCP socket. */
typedef struct nussl_socket_s nussl_socket;

/* nussl_sock_addr represents an address object. */
typedef struct nussl_sock_addr_s nussl_sock_addr;

#ifndef NUSSL_INET_ADDR_DEFINED
typedef struct nussl_inet_addr_s nussl_inet_addr;
#endif

/* Perform process-global initialization of any libraries in use.
 * Returns non-zero on error. */
int nussl_sock_init(void);

/* Perform process-global shutdown of any libraries in use.  This
 * function only has effect when it has been called an equal number of
 * times to nussl_sock_init() for the process. */
void nussl_sock_exit(void);

/* Resolve the given hostname.  'flags' must be zero.  Hex
 * string IPv6 addresses (e.g. `::1') may be enclosed in brackets
 * (e.g. `[::1]'). */
nussl_sock_addr *nussl_addr_resolve(const char *hostname, int flags);

/* Returns zero if name resolution was successful, non-zero on
 * error. */
int nussl_addr_result(const nussl_sock_addr *addr);

/* Returns the first network address associated with the 'addr'
 * object.  Undefined behaviour if nussl_addr_result returns non-zero for
 * 'addr'; otherwise, never returns NULL.  */
const nussl_inet_addr *nussl_addr_first(nussl_sock_addr *addr);

/* Returns the next network address associated with the 'addr' object,
 * or NULL if there are no more. */
const nussl_inet_addr *nussl_addr_next(nussl_sock_addr *addr);

/* NB: the pointers returned by nussl_addr_first and nussl_addr_next are
 * valid until nussl_addr_destroy is called for the corresponding
 * nussl_sock_addr object.  They must not be passed to nussl_iaddr_free. */

/* If name resolution fails, copies the error string into 'buffer',
 * which is of size 'bufsiz'.  'buffer' is returned. */
char *nussl_addr_error(const nussl_sock_addr *addr, char *buffer, size_t bufsiz);

/* Destroys an address object created by nussl_addr_resolve. */
void nussl_addr_destroy(nussl_sock_addr *addr);

/* Network address type; IPv4 or IPv6 */
typedef enum {
    nussl_iaddr_ipv4 = 0,
    nussl_iaddr_ipv6
} nussl_iaddr_type;

/* Create a network address object from raw byte representation (in
 * network byte order) of given type.  'raw' must be four bytes for an
 * IPv4 address, 16 bytes for an IPv6 address.  May return NULL if
 * address type is not supported. */
nussl_inet_addr *nussl_iaddr_make(nussl_iaddr_type type, const unsigned char *raw);

/* Compare two network address objects i1 and i2; returns zero if they
 * are equivalent or non-zero otherwise.  */
int nussl_iaddr_cmp(const nussl_inet_addr *i1, const nussl_inet_addr *i2);

/* Return the type of the given network address object. */
nussl_iaddr_type nussl_iaddr_typeof(const nussl_inet_addr *ia);

/* Print the string representation of network address 'ia' into the
 * buffer 'buffer', which is of length 'bufsiz'.  Returns 'buffer'. */
char *nussl_iaddr_print(const nussl_inet_addr *ia, char *buffer, size_t bufsiz);

/* Perform the reverse name lookup on network address 'ia', placing
 * the returned name in the 'buf' buffer (of length 'bufsiz') if
 * successful.  Returns zero on success, or non-zero on error. */
int nussl_iaddr_reverse(const nussl_inet_addr *ia, char *buf, size_t bufsiz);

/* Destroy a network address object created using nussl_iaddr_make. */
void nussl_iaddr_free(nussl_inet_addr *addr);

/* Create a socket object; returns NULL on error. */
nussl_socket *nussl_sock_create(void);

/* Specify an address to which the local end of the socket will be
 * bound during a subsequent nussl_sock_connect() call.  If the address
 * passed to nussl_sock_connect() is of a different type (family) to
 * 'addr', 'addr' is ignored.  Either 'addr' may be NULL, to use the
 * given port with unspecified address, or 'port' may be 0, to use the
 * given address with an unspecified port.
 *
 * (Note: This function is not equivalent to a BSD socket bind(), it
 * only takes effect during the _connect() call). */
void nussl_sock_prebind(nussl_socket *sock, const nussl_inet_addr *addr,
                     unsigned int port);

/* Connect the socket to server at address 'addr' on port 'port'.
 * Returns zero on success, NUSSL_SOCK_TIMEOUT if a timeout occurs when a
 * non-zero connect timeout is configured (and is supported), or
 * NUSSL_SOCK_ERROR on failure.  */
int nussl_sock_connect(nussl_socket *sock, const nussl_inet_addr *addr,
                    unsigned int port);

/* Read up to 'count' bytes from socket into 'buffer'.  Returns:
 *   NUSSL_SOCK_* on error,
 *   >0 length of data read into buffer (may be less than 'count')
 */
ssize_t nussl_sock_read(nussl_socket *sock, char *buffer, size_t count);

/* Read up to 'count' bytes into 'buffer', leaving the data available
 * in the socket buffer to be returned by a subsequent call to
 * nussl_sock_read or nussl_sock_peek. Returns:
 *   NUSSL_SOCK_* on error,
 *   >0 length of data read into buffer.
 */
ssize_t nussl_sock_peek(nussl_socket *sock, char *buffer, size_t count);

/* Block for up to 'n' seconds until data becomes available for reading
 * from the socket. Returns:
 *  NUSSL_SOCK_* on error,
 *  NUSSL_SOCK_TIMEOUT if no data arrives in 'n' seconds,
 *  0 if data arrived on the socket.
 */
int nussl_sock_block(nussl_socket *sock, int n);

/* Write 'count' bytes of 'data' to the socket.  Guarantees to either
 * write all the bytes or to fail.  Returns 0 on success, or NUSSL_SOCK_*
 * on error. */
int nussl_sock_fullwrite(nussl_socket *sock, const char *data, size_t count);

/* Read an LF-terminated line into 'buffer', and NUL-terminate it.
 * At most 'len' bytes are read (including the NUL terminator).
 * Returns:
 * NUSSL_SOCK_* on error,
 * >0 number of bytes read (including NUL terminator)
 */
ssize_t nussl_sock_readline(nussl_socket *sock, char *buffer, size_t len);

/* Read exactly 'len' bytes into buffer, or fail; returns 0 on
 * success, NUSSL_SOCK_* on error. */
ssize_t nussl_sock_fullread(nussl_socket *sock, char *buffer, size_t len);

/* Accepts a connection from listening socket 'fd' and places the
 * socket in 'sock'.  Returns zero on success or -1 on failure. */
int nussl_sock_accept(nussl_socket *sock, int fd);

/* Returns the file descriptor used for socket 'sock'. */
int nussl_sock_fd(const nussl_socket *sock);

/* Return address of peer, or NULL on error.  The returned address
 * must be destroyed by caller using nussl_iaddr_free. */
nussl_inet_addr *nussl_sock_peer(nussl_socket *sock, unsigned int *port);

/* Close the socket and destroy the socket object.  Returns zero on
 * success, or an errno value if close() failed. */
int nussl_sock_close(nussl_socket *sock);

/* Return current error string for socket. */
const char *nussl_sock_error(const nussl_socket *sock);

/* Set read timeout for socket, in seconds; must be a non-zero
 * positive integer. */
void nussl_sock_read_timeout(nussl_socket *sock, int timeout);

/* Set connect timeout for socket, in seconds; must be a positive
 * integer.  If a timeout of 'zero' is used then then no explicit
 * timeout handling will be used for nussl_sock_connect(), and the
 * connect call will only timeout as dictated by the TCP stack. */
void nussl_sock_connect_timeout(nussl_socket *sock, int timeout);

/* Negotiate an SSL connection on socket as an SSL server, using given
 * SSL context. */
int nussl_sock_accept_ssl(nussl_socket *sock, nussl_ssl_context *ctx);

/* Negotiate an SSL connection on socket as an SSL client, using given
 * SSL context.  The 'userdata' parameter is associated with the
 * underlying SSL library's socket structure for use in callbacks.
 * Returns zero on success, or non-zero on error. */
int nussl_sock_connect_ssl(nussl_socket *sock, nussl_ssl_context *ctx,
                        void *userdata);

/* Retrieve the session ID of the current SSL session.  If 'buf' is
 * non-NULL, on success, copies at most *buflen bytes to 'buf' and
 * sets *buflen to the exact number of bytes copied.  If 'buf' is
 * NULL, on success, sets *buflen to the length of the session ID.
 * Returns zero on success, non-zero on error. */
int nussl_sock_sessid(nussl_socket *sock, unsigned char *buf, size_t *buflen);

/* Return human-readable name of SSL/TLS cipher used for connection,
 * or NULL if none.  The format of this string is not intended to be
 * fixed or parseable, but is informational only.  Return value is
 * NUL-terminated malloc-allocated string if not NULL, which must be
 * freed by the caller. */
char *nussl_sock_cipher(nussl_socket *sock);

NUSSL_END_DECLS

#endif /* NUSSL_SOCKET_H */

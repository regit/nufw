/*
 ** Copyright 2004-2007 - INL
 ** Written by Eric Leblond <regit@inl.fr>
 **            Vincent Deffontaines <vincent@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** $Id$
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, version 3 of the License.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software
 ** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#define NULL_THREAD 0

extern char* nu_locale_charset;

int init_socket(nuauth_session_t * session,
		const char *hostname, const char *service,
		nuclient_error_t *err);

int tls_handshake(nuauth_session_t * session, nuclient_error_t * err);

int init_sasl(nuauth_session_t * session, nuclient_error_t * err);

int send_os(nuauth_session_t * session, nuclient_error_t * err);

char *secure_str_copy(const char *orig);

void ask_session_end(nuauth_session_t * session);

/**
 * Free a string allocated by secure_str_copy().
 *
 * If USE_GCRYPT_MALLOC_SECURE compilation option in not set,
 * free() is used.
 *
 * \return Copy of the string, or NULL on error.
 */
/*#ifdef USE_GCRYPT_MALLOC_SECURE
#   define secure_str_free(text) gcry_free(text)
#else*/
#   define secure_str_free(text) free(text)
/*#endif*/



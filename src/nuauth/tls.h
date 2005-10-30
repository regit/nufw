/*
** Copyright(C) 2005 Eric Leblond <regit@inl.fr>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation, version 2 of the License.
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
#ifndef TLS_H
#define TLS_H

#define KEYFILE "privkey.pem"
#define CERTFILE "cacert.pem"
#define CAFILE "/etc/nufw/cacert.pem"
#define CRLFILE "/etc/nufw/crl.pem"

#define MAX_BUF 1024
#define DH_BITS 1024

#define NB_AUTHCHECK 10

GAsyncQueue* mx_queue;
GAsyncQueue* mx_nufw_queue;

int tls_connect(int c,gnutls_session** session_ptr);

/* cache system related */
struct client_connection {
	int socket;
	struct sockaddr_in addr;
};

/**
 * structure used to sent data from
 * tls function to core functions
 */

struct buffer_read {
        int socket;
        gnutls_session* tls;
        char * userid;
	uint16_t uid;
        GSList * groups;
	char * sysname;
	char * release;
	char * version;
        char* buf;
};

typedef struct Nufw_session {
        gnutls_session* tls;
	gint usage;
	gboolean alive;
} nufw_session;

void clean_nufw_session(nufw_session * c_session);


void create_x509_credentials();
void* tls_nufw_authsrv();
GHashTable* nufw_servers;
#endif

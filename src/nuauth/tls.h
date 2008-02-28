/*
** Copyright(C) 2005,2006,2007 INL
** Written by Eric Leblond <regit@inl.fr>
**
** $Id$
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

#include <nussl.h>
/**
 * \ingroup Nuauth
 * \defgroup TLS TLS servers
 *
 */


/**
 * Number of bits for use in an Diffie Hellman key exchange,
 * used in gnutls_dh_set_prime_bits() call.
 */
#define DH_BITS 1024

/**
 * default interval between CRL refresh
 */
#define DEFAULT_REFRESH_CRL_INTERVAL 30

/**
 * Default number of thread in tls_sasl_connect() thread pool
 */
#define NB_AUTHCHECK 10

typedef enum {
	NO_AUTH_BY_CERT = 0x0,
	DO_AUTH_BY_CERT = 0x1,
	MANDATORY_AUTH_BY_CERT = 0x2,
	MAX_AUTH_BY_CERT
} auth_cert_type_t;

/**
 * Queue used to exchange messages between tls_sasl_connect_ok()
 * function and tls_user_authsrv() thread
 */
GAsyncQueue *mx_queue;

nussl_session *ssl_connect(int socket_fd);
int tls_connect(int c, gnutls_session ** session_ptr);

/* cache system related */
struct client_connection {
	/** Socket file descriptor, init. with accept() and set to SO_KEEPALIVE mode */
	int socket;

	/** IPv6 address */
	struct in6_addr addr;

	/** Source port */
	int sport;

	/** Nussl server structure */
	nussl_session* nussl;
};

/**
 * Store information from an user packet read on a TLS connection.
 * Structure is feeded by function treat_user_request() which is part of
 * the thread tls_user_authsrv().
 */
struct tls_buffer_read {
	int socket;		/*!< Socket file descriptor (value from accept()) */
	struct in6_addr ip_addr;	/*!< User IPv6 address */
	gnutls_session *tls;	/*!< TLS session */
	char *user_name;	/*!< User name string */
	uint32_t user_id;	/*!< User identifier (16 bits */
	GSList *groups;		/*!< User groups */
	char *os_sysname;	/*!< Operation system name */
	char *os_release;	/*!< Operation system release */
	char *os_version;	/*!< Operation system version */
	char *buffer;		/*!< Content of the received packet */
	int32_t buffer_len;	/*!< Length of the buffer */
	int client_version;	/*!< Protocol version of client */
};

/**
 * This structure stores all information relative to a connection
 * from a nufw server.
 */
typedef struct {
	/* nussl_session_server is in tls_nufw_context_t */
	nussl_session *nufw_client;

#if 0
	gnutls_session *tls;
#endif
	/**
	 * This lock has to be used before any call to gnutls_record function
	 * on TLS session pointed by the ::nufw_session_t
	 */
	GMutex *tls_lock;

	struct in6_addr peername;
	unsigned char proto_version;
	/**
	 * usage stores the number of packets currently depending of this session
	 * for their answer. It is modified by atomic operation.
	 */
	gint usage;
	/** This flag is used to indicate that current session is dead and
	 * wait for cleaning (when set to FALSE). This is needed to avoid a
	 * structure destruction whereas there is ::connection_t that depends
	 * on it to send answer to nufw server.
	 */
	gboolean alive;
	/** Connection timestamp */
	time_t connect_timestamp;
} nufw_session_t;

struct tls_insert_data {
	int socket;
	gpointer data;
};

#if 0
struct nuauth_ssl_t {
	nussl_session *session;

	int request_cert;
	int auth_by_cert;

	int crl_refresh;
	int crl_refresh_counter;
};
#endif

/* TODO: move-me into tls_user.h */
struct nuauth_tls_t {
	nussl_session_server *nussl_server;
	int request_cert;
	auth_cert_type_t auth_by_cert;
#ifdef XXX /* Move this into nussl */
	gnutls_certificate_credentials x509_cred;
	int crl_refresh;
	int crl_refresh_counter;
	gchar *crl_file;
	time_t crl_file_mtime;
	gnutls_dh_params dh_params;
#endif
};

void clean_nufw_session(nufw_session_t * c_session);
int create_x509_credentials();
void *tls_nufw_authsrv(struct nuauth_thread_t *thread);
void tls_nufw_start_servers(GSList *servers);

extern GHashTable *nufw_servers;
extern GStaticMutex nufw_servers_mutex;

void close_nufw_servers();

/*
 * For user authentication
 */

void *tls_user_authsrv(struct nuauth_thread_t *thread);
void *push_worker(GMutex * mutex);


/** end tls stuff */
void end_tls();

gboolean remove_socket_from_pre_client_list(int c);

void tls_sasl_connect(gpointer userdata, gpointer data);
gint check_certs_for_tls_session(gnutls_session session);
void close_tls_session(int c, gnutls_session * session);

void refresh_crl_file();

struct tls_user_context_t {
	int mx;
	int sck_inet;
	fd_set tls_rx_set;	/* read set */
	unsigned int nuauth_tls_max_clients;
	int nuauth_number_authcheckers;
	int nuauth_auth_nego_timeout;
	char *addr;
	char *port;
	GAsyncQueue* cmd_queue;
	nussl_session_server* nussl;
};

typedef struct {
	int socket;
	GMutex *mutex;
	int result;
} disconnect_user_msg_t;

extern struct tls_user_context_t tls_user_context;

void tls_user_remove_client(int sock);
void tls_user_start_servers(GSList *servers);

#endif

/*
 ** Copyright 2004-2009 - INL
 ** Written by Eric Leblond <regit@inl.fr>
 **            Vincent Deffontaines <vincent@inl.fr>
 ** INL http://www.inl.fr/
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

#ifndef NUCLIENT_H
#define NUCLIENT_H

#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#if 0
	/* dummy code to make vim indentation works */
}
#endif
#endif

#define NUCLIENT_VERSION_MAJOR 4
#define NUCLIENT_VERSION_MINOR 0
#define NUCLIENT_VERSION_REVISION 0

#define NUCLIENT_VERSION "4.0.0"

/** Default nuauth IP address */
#define NUAUTH_IP "192.168.1.1"

/** Default Kerberos realm */
#define DEFAULT_KRB5_REALM "nuauth"

/** Timeout of UDP connections */
#define UDP_TIMEOUT 30

enum {
	ERROR_OK = 0,
	ERROR_LOGIN = 1,
	ERROR_NETWORK = 2
};

/** Error family */
typedef enum {
	INTERNAL_ERROR = 0,
	NUSSL_ERR = 1,
	SASL_ERROR = 2
} nuclient_error_family_t;

/* INTERNAL ERROR CODES */
enum {
	NO_ERR = 0,	     /** No error */
	SESSION_NOT_CONNECTED_ERR = 1,
	/** Session not connected */
	UNKNOWN_ERR = 2,     /** Unknown error */
	TIMEOUT_ERR = 3,     /** Connection timeout */
	DNS_RESOLUTION_ERR = 4,
	/** DNS resolution error */
	NO_ADDR_ERR = 5,     /** Address not recognized */
	FILE_ACCESS_ERR = 6, /** File access error */
	CANT_CONNECT_ERR = 7,/** Connection failed */
	MEMORY_ERR = 8,	     /** No more memory */
	TCPTABLE_ERR = 9,    /** Fail to read connection table */
	SEND_ERR = 10,	     /** Fail to send packet to nuauth */
	BAD_CREDENTIALS_ERR, /** Username/password error */
	BINDING_ERR,	     /** bind() call failed */
	NUSSL_INIT_ERR,	     /** NuSSL initialisation failed */
};

/* Define for backward compatibility */
#define nuclient_error nuclient_error_t

typedef struct nuauth_session nuauth_session_t;

/* libnuclient return code structure */
typedef struct {
	nuclient_error_family_t family;
	int error;
} nuclient_error_t;

/* Exported functions */
int nu_client_check(nuauth_session_t *session, nuclient_error_t *err);

int nu_client_error_init(nuclient_error_t **err);
void nu_client_error_destroy(nuclient_error_t *err);

const char *nu_client_strerror(nuauth_session_t *session, nuclient_error_t *err);

int nu_client_global_init(nuclient_error_t *err);
void nu_client_global_deinit();

int nu_client_init_config();
int nu_client_init_plugins();

nuauth_session_t *nu_client_new(const char *username,
		const char *password,
		unsigned char diffie_hellman,
		nuclient_error_t *err);

nuauth_session_t *nu_client_new_callback(void *username_callback,
		void *passwd_callback,
		unsigned char diffie_hellman,
		nuclient_error_t * err);

void nu_client_set_username(nuauth_session_t *session,
		const char *username);

void nu_client_set_password(nuauth_session_t *session,
		const char *password);

const char* nu_client_default_hostname();

const char* nu_client_default_port();

const char* nu_client_default_tls_ca();
const char* nu_client_default_tls_cert();
const char* nu_client_default_tls_key();
const char* nu_client_default_tls_crl();

int nu_client_default_suppress_fqdn_verif();

void nu_client_set_client_info(nuauth_session_t *session,
		const char *client_name, const char *client_version);

void nu_client_set_debug(nuauth_session_t * session, unsigned char enabled);
void nu_client_set_verbose(nuauth_session_t * session,
		unsigned char enabled);
void nu_client_set_source(nuauth_session_t *session, struct sockaddr_storage *addr);

int nu_client_set_key(nuauth_session_t * session,
		const char *keyfile, const char *certfile,
		nuclient_error_t *err);

int nu_client_set_pkcs12(nuauth_session_t * session,
		char *pkcs12file, char *pkcs12password,
		nuclient_error_t *err);

int nu_client_set_ca(nuauth_session_t * session,
		const char *cafile, nuclient_error_t *err);

int nu_client_set_nuauth_cert_dn(nuauth_session_t * session,
		char *nuauth_cert_dn,
		nuclient_error_t *err);

int nu_client_set_crlfile(nuauth_session_t * session,
				const char *crlfile,
				nuclient_error_t *err);

char* nu_client_get_cipher(nuauth_session_t * session);
char* nu_client_get_cert_info(nuauth_session_t * session);
char* nu_client_get_server_cert_info(nuauth_session_t * session);

int nu_client_set_crlfile(nuauth_session_t * session,
		const char *crlfile,
		nuclient_error_t *err);

int nu_client_set_krb5_service(nuauth_session_t * session,
		char *service);

int nu_client_set_ca_suppress_warning(nuauth_session_t * session,
		int suppress_ca_warning);

int nu_client_set_fqdn_suppress_verif(nuauth_session_t * session,
		int suppress_fqdn_verif);

int nu_client_set_cert_suppress_verif(nuauth_session_t * session,
		int suppress_cert_verif);

int nu_client_connect(nuauth_session_t * session,
		const char *hostname,
		const char *service,
		nuclient_error_t *err);

void nu_client_reset(nuauth_session_t * session);

void nu_client_delete(nuauth_session_t * session);

char *nu_client_to_utf8(const char *inbuf, char *from_charset);

const char *nu_get_version();
int nu_check_version(const char *version);

void nu_client_set_min_delay(nuauth_session_t * session, unsigned int delay);
void nu_client_set_max_delay(nuauth_session_t * session, unsigned int delay);

int nu_client_set_capability(const char *capa);
int nu_client_unset_capability(const char *capa);

int nu_client_set_session_capability(nuauth_session_t * session, const char *capa);
int nu_client_unset_session_capability(nuauth_session_t * session, const char *capa);

char *nu_get_home_dir();
char *nu_get_user_name();


#ifdef __cplusplus
}
#endif
#endif   /* #ifndef NUCLIENT_H */


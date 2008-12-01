/*
 ** Copyright 2004-2008 - INL
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

/**
 * \defgroup libnuclient Libnuclient
 * @{
 */

/*! \file libnuclient.c
 * \brief Main file for libnuclient
 *
 * It contains all the exported functions
 * */

/**
 * Use gcry_malloc_secure() to disallow a memory page
 * to be moved to the swap
 */
#define USE_GCRYPT_MALLOC_SECURE

#include "libnuclient.h"
#include "nuclient.h"
#include "nufw_source.h"
#include <sasl/sasl.h>
#include <sasl/saslutil.h>
#include <stdarg.h>		/* va_list, va_start, ... */
#include <langinfo.h>
#include <proto.h>
#include "security.h"
#include "sys_config.h"
#include "internal.h"
#include "tcptable.h"
#include <sys/utsname.h>

#include <nussl.h>
#include <nubase.h>


void nu_exit_clean(nuauth_session_t * session)
{
	if (session->ct) {
		tcptable_free(session->ct);
	}

	if(session->nussl)
	{
		nussl_session_destroy(session->nussl);
		session->nussl = NULL;
	}

	secure_str_free(session->username);
	secure_str_free(session->password);

	free(session);
}

/**
 * \defgroup nuclientAPI API of libnuclient
 * \brief The high level API of libnuclient can be used to build a NuFW client
 *
 * A client needs to call a few functions in the correct order to be able to authenticate:
 *  - nu_client_global_init(): To be called once at program start
 *  - nu_client_new() or nu_client_new_callback(): start user session
 *  - nu_client_setup_tls(): (optionnal) setup TLS key/certificate files
 *  - nu_client_connect(): try to connect to nuauth server
 *  - nu_client_check(): check if there is packet to authenticate and send authentication 
 *  request to nuauth if needed. It has to be run in a endless loop.
 *  - nu_client_delete(): free a user session
 *  - nu_client_global_deinit(): To be called once at program end
 *
 * On error, don't forget to delete session with nu_client_delete()
 */

/**
 * \ingroup nuclientAPI
 * \brief Destroy a client session: free all used memory
 *
 * This destroy a session and free all related structures.
 *
 * \param session A ::nuauth_session_t session to be cleaned
 */
void nu_client_delete(nuauth_session_t * session)
{
	ask_session_end(session);
	/* destroy session */
	nu_exit_clean(session);
}

/**
 * \ingroup nuclientAPI
 * \brief global initialisation function
 *
 * This function inits all library needed to initiate a connection to a nuauth server
 *
 * \param err A pointer to a ::nuclient_error_t which contains at exit the error
 *
 * \warning To be called only once.
 */
int nu_client_global_init(nuclient_error_t * err)
{
	int ret;

	if (nussl_init() != NUSSL_OK)
	{
		SET_ERROR(err, INTERNAL_ERROR, NUSSL_INIT_ERR); /* TODO: patch nussl to handle errors correctly in nussl_sock_init */
		return 0;
	}

	/* initialize the sasl library */
	ret = sasl_client_init(NULL);
	if (ret != SASL_OK) {
		SET_ERROR(err, SASL_ERROR, ret);
		return 0;
	}
	/* get local charset */
	nu_locale_charset = nl_langinfo(CODESET);
	if (nu_locale_charset == NULL) {
		fprintf(stderr, "Can't get locale charset!\n");
		exit(EXIT_FAILURE);
	}

	load_sys_config();

	return 1;
}

/**
 * \ingroup nuclientAPI
 * \brief  Global de init function
 *
 * \warning To be called once, when leaving.
 */
void nu_client_global_deinit()
{
	sasl_done();
}

/**
 * \ingroup nuclientAPI
 * \brief Set username
 *
 */
void nu_client_set_username(nuauth_session_t *session,
			    const char *username)
{
	char *utf8username = nu_client_to_utf8(username, nu_locale_charset);
	session->username = secure_str_copy(utf8username);
	free(utf8username);
}

/**
 * \ingroup nuclientAPI
 * \brief Set password
 *
 */
void nu_client_set_password(nuauth_session_t *session,
				    const char *password)
{
	char *utf8pass = nu_client_to_utf8(password, nu_locale_charset);
	session->password = secure_str_copy(utf8pass);
	free(utf8pass);
}

void nu_client_set_debug(nuauth_session_t * session, unsigned char enabled);

/**
 * \ingroup nuclientAPI
 * Get user home directory
 *
 * \return A string that need to be freed
 */

char *nu_get_home_dir()
{
	uid_t uid;
	struct passwd *pwd;
	char *dir = NULL;

	uid = getuid();
	if (!(pwd = getpwuid(uid))) {
		printf("Unable to get password file record\n");
		endpwent();
		return NULL;
	}
	dir = strdup(pwd->pw_dir);
	endpwent();
	return dir;
}

/**
 * \ingroup nuclientAPI
 * Get user name
 *
 * \return A string that need to be freed
 */

char *nu_get_user_name()
{
	uid_t uid;
	struct passwd *pwd;
	char *name = NULL;

	uid = getuid();
	if (!(pwd = getpwuid(uid))) {
		printf("Unable to get password file record\n");
		endpwent();
		return NULL;
	}
	name = strdup(pwd->pw_name);
	endpwent();
	return name;
}

int nu_client_set_key(nuauth_session_t* session, char* keyfile, char* certfile, nuclient_error_t* err)
{
	if (session->pem_key)
		free(session->pem_key);

	if (session->pem_cert)
		free(session->pem_cert);

	if (keyfile)
	{
		session->pem_key = strdup(keyfile);
		printf("Using key: %s\n", keyfile);
	}

	if (certfile)
	{
		session->pem_cert = strdup(certfile);
		printf("Using certificate: %s\n", certfile);
	}

	return 1;
}

int nu_client_set_ca(nuauth_session_t* session, char* cafile, nuclient_error_t* err)
{
	if (session->pem_ca)
		free(session->pem_ca);

	if (cafile)
		session->pem_ca = strdup(cafile);

	printf("Using CA: %s\n", cafile);
	return 1;
}

int nu_client_set_pkcs12(nuauth_session_t* session, char* key_file, char* key_password, nuclient_error_t* err)
{
	if (session->pkcs12_file)
		free(session->pkcs12_file);

	if (session->pkcs12_password)
		free(session->pkcs12_password);

	if (key_file)
	{
		printf("Using key: %s\n", key_file);
		session->pkcs12_file = strdup(key_file);
	}

	if (key_password)
		session->pkcs12_password = strdup(key_password);

	return 1;
}
/**
 * \ingroup nuclientAPI
 * Initialize TLS:
 *    - Set key filename (and test if the file does exist)
 *    - Set certificate (if key and cert. are present)
 *
 * \param session Pointer to client session
 * \param keyfile Complete path to a key file stored in PEM format (can be NULL)
 * \param certfile Complete path to a certificate file stored in PEM format (can be NULL)
 * \param err Pointer to a nuclient_error_t: which contains the error
 * \return Returns 0 on error (error description in err), 1 otherwise
 */
int nu_client_load_key(nuauth_session_t * session,
			char *keyfile, char *certfile,
			nuclient_error_t * err)
{
	char certstring[256];
	char keystring[256];
	char *home = nu_get_home_dir();
	int exit_on_error = 0;
	int ret;

	/* If the user specified a certficate and a key on command line,
	 * exit if we fail loading them.
	 * Elsewise, try loading certs from ~/.nufw/, but continue if we fail
	 */
	if (certfile || keyfile)
		exit_on_error = 1;

	/* compute patch keyfile */
	if (keyfile == NULL && home != NULL) {
		ret = secure_snprintf(keystring, sizeof(keystring),
				     "%s/.nufw/key.pem", home);
		if (ret)
			keyfile = keystring;
	}

	if (certfile == NULL && home != NULL) {
		ret = secure_snprintf(certstring, sizeof(certstring),
				     "%s/.nufw/cert.pem", home);
		if (ret)
			certfile = certstring;
	}

	if (certfile != NULL || keyfile != NULL) {
		ret =
		    nussl_ssl_set_keypair(session->nussl, certfile, keyfile);

		if (ret != NUSSL_OK) {
			if (exit_on_error) {
				if (home)
					free(home);
				SET_ERROR(err, NUSSL_ERR, ret);
				return 0;
			}
			else {
				printf("Warning: Failed to load default certificate and key.\n");
			}
		}
	}

	if (home)
		free(home);

	return 1;
}


/**
 * \ingroup nuclientAPI
 * Initialize TLS:
 *    - Set PKCS12 key/certificate filename (and test if the file does exist)
 *    - Set PKCS12 password
 *
 * \param session Pointer to client session
 * \param pkcs12file Complete path to a key and a certificate file stored in PEM format (can be NULL)
 * \param pkcs12password Password of the pkcs12 file
 * \param err Pointer to a nuclient_error_t: which contains the error
 * \return Returns 0 on error (error description in err), 1 otherwise
 */
int nu_client_load_pkcs12(nuauth_session_t * session,
			char *pkcs12file, char *pkcs12password,
			nuclient_error_t * err)
{
	int ret = nussl_ssl_set_pkcs12_keypair(session->nussl, pkcs12file, pkcs12password);
	if (ret != NUSSL_OK)
	{
		SET_ERROR(err, NUSSL_ERR, ret);
		return 0;
	}
	return 1;
}


/**
 * \ingroup nuclientAPI
 * Initialize TLS:
 *    - Set trust file of credentials (if needed)
 *
 * \param session Pointer to client session
 * \param cafile Complete path to a certificate authority file stored in PEM format (can be NULL)
 * \param err Pointer to a nuclient_error_t: which contains the error
 * \return Returns 0 on error (error description in err), 1 otherwise
 */
int nu_client_load_ca(nuauth_session_t * session,
			char *cafile,
			nuclient_error_t * err)
{
	char castring[256];
	char *home = nu_get_home_dir();
	int exit_on_error = 0;
	int ret;

	if (cafile != NULL)
		exit_on_error = 1;

	if (cafile == NULL && home != NULL) {
		ret = secure_snprintf(castring, sizeof(castring),
				     "%s/.nufw/cacert.pem", home);
		if (ret)
			cafile = castring;
	}

	if (cafile != NULL) {
		ret = nussl_ssl_trust_cert_file(session->nussl, cafile);
		if (ret != NUSSL_OK) {
			if (exit_on_error) {
				if (home)
					free(home);
				SET_ERROR(err, NUSSL_ERR, ret);
				return 0;
			}
			else {
				if (!session->suppress_ca_warning) {
					fprintf(stderr,"\nWARNING: you have not provided any certificate authority.\n"
							"nutcpc will *NOT* verify server certificate trust.\n"
							"Use the -A <cafile> option to set up CA.\n\n"
					       );
				}
				session->suppress_fqdn_verif = 1;
				nussl_set_session_flag(session->nussl, NUSSL_SESSFLAG_IGNORE_ID_MISMATCH, 1);
			}
		}
	} else {
		fprintf(stderr, "Could not load any CA !\n");
		return 0;
	}
	return 1;
}

int nu_client_load_crl(nuauth_session_t *session, const char *crlfile,
	const char *cafile, nuclient_error_t * err)
{
	int ret;
	if (crlfile && *crlfile) {
		ret = nussl_ssl_set_crl_file(session->nussl, crlfile, cafile);
		if (ret != NUSSL_OK) {
			fprintf(stderr,"TLS error with CRL: %s",
				nussl_get_error(session->nussl));
			return 0;
		}
		printf("Using crl: %s\n", crlfile);
	}
	return 1;
}

/**
 * \ingroup nuclientAPI
 * Returns a formated string containing information about the user certificate
 *
 * \param session Pointer to client session
 * \return
 */
char* nu_client_get_cert_infos(nuauth_session_t * session)
{
	return nussl_get_cert_infos(session->nussl);
}


/**
 * \ingroup nuclientAPI
 * Returns a formated string containing information about the server certificate
 *
 * \param session Pointer to client session
 * \return
 */
char* nu_client_get_server_cert_infos(nuauth_session_t * session)
{
	return nussl_get_server_cert_infos(session->nussl);
}


/**
 * \ingroup nuclientAPI
 */
int nu_client_set_nuauth_cert_dn(nuauth_session_t * session,
				char *nuauth_cert_dn,
				nuclient_error_t *err)
{
	if (*nuauth_cert_dn) {
		session->nuauth_cert_dn = nuauth_cert_dn;
	}
	return 1;
}

 /**
  * \ingroup nuclientAPI
  */
int nu_client_set_crlfile(nuauth_session_t * session,
		char *crlfile,
		nuclient_error_t *err)
{
	if (session->pem_crl)
		free(session->pem_crl);

	if (crlfile)
		session->pem_crl = strdup(crlfile);

	return 1;
}

/**
 * \ingroup nuclientAPI
 */
int nu_client_set_krb5_service(nuauth_session_t * session,
				char *service)
{
	if (service) {
		session->krb5_service = service;
	}
	return 1;
}

/**
 * \ingroup nuclientAPI
 */
int nu_client_set_ca_suppress_warning(nuauth_session_t * session,
				int suppress_ca_warning)
{
	session->suppress_ca_warning = suppress_ca_warning;
	return 1;
}

/**
 * \ingroup nuclientAPI
 */
int nu_client_set_fqdn_suppress_verif(nuauth_session_t * session,
				int suppress_fqdn_verif)
{
	session->suppress_fqdn_verif = suppress_fqdn_verif;
	return 1;
}

/**
 * \ingroup nuclientAPI
 */
int nu_client_set_cert_suppress_verif(nuauth_session_t * session,
				int suppress_cert_verif)
{
	session->suppress_cert_verif = suppress_cert_verif;
	if (suppress_cert_verif)
		session-> suppress_fqdn_verif = 1;
	return 1;
}

/**
 * \ingroup nuclientAPI
 * Set IP source of the socket used to connect to nuauth server
 *
 * \param session Pointer to client session
 * \param addr Address of the socket
 */
void nu_client_set_source(nuauth_session_t *session, struct sockaddr_storage *addr)
{
	session->has_src_addr = 1;
	session->src_addr = *addr;
}

/**
 * \brief Init connection to nuauth server
 *
 * (very secure but initialization is slower)
 * \param err Pointer to a nuclient_error_t: which contains the error
 * \return A pointer to a valid ::nuauth_session_t structure or NULL if init has failed
 *
 * \par Internal
 * Initialisation of nufw authentication session:
 *    - set basic fields and then ;
 *    - allocate x509 credentials ;
 *    - generate Diffie Hellman params.
 *
 * If everything is ok, create the connection table using tcptable_init().
 */
nuauth_session_t *_nu_client_new(nuclient_error_t * err)
{
	conntable_t *new;
	nuauth_session_t *session;

	/* First reset error */
	SET_ERROR(err, INTERNAL_ERROR, NO_ERR);

	/* Allocate a new session */
	session = (nuauth_session_t *) calloc(1, sizeof(nuauth_session_t));
	if (session == NULL) {
		SET_ERROR(err, INTERNAL_ERROR, MEMORY_ERR);
		return NULL;
	}

	/* Set basic fields */
	session->userid = getuid();
	session->connected = 0;
	session->auth_by_default = 1;
	session->packet_seq = 0;
	session->ct = NULL;
	session->debug_mode = 0;
	session->verbose = 1;
	session->timestamp_last_sent = time(NULL);
	session->min_sleep_delay.tv_sec = MIN_DELAY_SEC;
	session->min_sleep_delay.tv_usec = MIN_DELAY_USEC;
	session->max_sleep_delay.tv_sec = MAX_DELAY_SEC;
	session->max_sleep_delay.tv_usec = MAX_DELAY_USEC;
	session->sleep_delay.tv_sec = MIN_DELAY_SEC;
	session->sleep_delay.tv_usec = MIN_DELAY_USEC;

	if (tcptable_init(&new) == 0) {
		SET_ERROR(err, INTERNAL_ERROR, MEMORY_ERR);
		nu_exit_clean(session);
		return NULL;
	}
	session->ct = new;

	return session;
}

/**
 * \ingroup nuclientAPI
 * \brief Create new session and use callbacks.
 *
 * Callbacks are used to fetch username and password if they are
 * necessary for SASL negotiation.
 *
 * \param username_callback User name retrieving callback
 * \param passwd_callback Password retrieving callback
 * \param diffie_hellman If equals to 1, use Diffie Hellman for key exchange
 * (very secure but initialization is slower)
 * \param err Pointer to a nuclient_error_t: which contains the error
 * \return A pointer to a valid ::nuauth_session_t structure or NULL if init has failed
 */

nuauth_session_t *nu_client_new_callback(void *username_callback,
		      void *passwd_callback,
		      unsigned char diffie_hellman, nuclient_error_t * err)
{
	nuauth_session_t *session = NULL;

	if (username_callback == NULL || passwd_callback == NULL) {
		SET_ERROR(err, INTERNAL_ERROR, BAD_CREDENTIALS_ERR);
		return NULL;
	}

	session = _nu_client_new(err);

	session->username_callback = username_callback;
	session->passwd_callback = passwd_callback;

	return session;
}

/**
 * \ingroup nuclientAPI
 * \brief Create new session.
 *
 * This function has to be used to create a new ::nuauth_session_t if there
 * is no plan to use a callback for getting username or password.
 *
 * \param username User name string
 * \param password Password string
 * \param diffie_hellman If equals to 1, use Diffie Hellman for key exchange
 * (very secure but initialization is slower)
 * \param err Pointer to a nuclient_error_t: which contains the error
 * \return A pointer to a valid ::nuauth_session_t structure or NULL if init has failed
 */

nuauth_session_t *nu_client_new(const char *username,
		      const char *password,
		      unsigned char diffie_hellman, nuclient_error_t * err)
{
	nuauth_session_t *session = NULL;

	if (username == NULL || password == NULL) {
		SET_ERROR(err, INTERNAL_ERROR, BAD_CREDENTIALS_ERR);
		return NULL;
	}

	session = _nu_client_new(err);

	session->username = secure_str_copy(username);
	session->password = secure_str_copy(password);
	if (session->username == NULL || session->password == NULL) {
		SET_ERROR(err, INTERNAL_ERROR, MEMORY_ERR);
		return NULL;
	}

	return session;
}

/**
 * \ingroup nuclientAPI
 * Reset a session: close the connection and reset attributes. So the session
 * can be used as nu_client_connect() input.
 */
void nu_client_reset(nuauth_session_t * session)
{
	ask_session_end(session);

	/* reset fields */
	session->connected = 0;
	session->timestamp_last_sent = time(NULL);
}

/**
 * \ingroup nuclientAPI
 * Try to connect to nuauth server:
 *    - init_socket(): create socket to server ;
 *    - tls_handshake(): TLS handshake ;
 *    - init_sasl(): authentication with SASL ;
 *    - send_os(): send OS field.
 *
 * \param session Pointer to client session
 * \param hostname String containing hostname of nuauth server (default: #NUAUTH_IP)
 * \param service Port number (or string) on which nuauth server is listening (default: #USERPCKT_SERVICE)
 * \param err Pointer to a nuclient_error_t: which contains the error
 * \return Returns 0 on error (error description in err), 1 otherwise
 */
int nu_client_connect(nuauth_session_t * session,
		      const char *hostname, const char *service,
		      nuclient_error_t * err)
{
	int ret;
	unsigned int port = atoi(service);

	session->nussl = nussl_session_create();

	if (session->suppress_cert_verif)
		nussl_ssl_disable_certificate_check(session->nussl,1);

	if (session->suppress_fqdn_verif)
		nussl_set_session_flag(session->nussl, NUSSL_SESSFLAG_IGNORE_ID_MISMATCH, 1);

	nussl_set_hostinfo(session->nussl, hostname, port);
	if(session->pkcs12_file)
	{
		if (!nu_client_load_pkcs12(session, session->pkcs12_file, session->pkcs12_password, err))
			return 0;
	}
	else
	{
		if (!nu_client_load_key(session, session->pem_key, session->pem_cert, err))
			return 0;
	}

	if (!nu_client_load_ca(session, session->pem_ca, err))
		return 0;

	if (session->pem_crl) {
		if (!nu_client_load_crl(session, session->pem_crl, session->pem_ca, err))
			return 0;
	}

	ret = nussl_open_connection(session->nussl);
	if (ret != NUSSL_OK) {
		nussl_session_destroy(session->nussl);
		session->nussl = NULL;
		SET_ERROR(err, NUSSL_ERR, ret);
		return 0;
	}

	if (!init_sasl(session, hostname, err)) {
		return 0;
	}

	if (!send_os(session, err)) {
		return 0;
	}
	session->connected = 1;
	return 1;
}

/**
 * \ingroup nuclientAPI
 * Enable or disabled debug mode
 *
 * \param session Pointer to client session
 * \param enabled Enable debug if different than zero (1), disable otherwise
 */
void nu_client_set_debug(nuauth_session_t * session, unsigned char enabled)
{
	session->debug_mode = enabled;
}


/**
 * \ingroup nuclientAPI
 * Enable or disabled verbose mode
 *
 * \param session Pointer to client session
 * \param enabled Enable verbose mode if different than zero (1), disable otherwise
 */
void nu_client_set_verbose(nuauth_session_t * session, unsigned char enabled)
{
	session->verbose = enabled;
}

/**
 * \ingroup nuclientAPI
 * Set minimum delay
 *
 * \param session Pointer to client session
 * \param delay a timeval which will be equal to the minimum delay
 * between two checks (in ms)
 */
void nu_client_set_min_delay(nuauth_session_t * session, unsigned int delay)
{
	session->min_sleep_delay.tv_sec = delay / 1000;
	session->min_sleep_delay.tv_usec = (delay * 1000) % 1000000;
}

/**
 * \ingroup nuclientAPI
 * Set maximum delay
 *
 * \param session Pointer to client session
 * \param delay a timeval which will be equal to the maximum delay 
 * between two checks (in ms)
 */
void nu_client_set_max_delay(nuauth_session_t * session, unsigned int delay)
{
	session->max_sleep_delay.tv_sec = delay / 1000;
	session->max_sleep_delay.tv_usec = (delay * 1000) % 1000000;
}

/**
 * \ingroup nuclientAPI
 * \brief Allocate a structure to store client error
 */
int nu_client_error_init(nuclient_error_t ** err)
{
	if (*err != NULL)
		return -1;
	*err = malloc(sizeof(nuclient_error_t));
	if (*err == NULL)
		return -1;
	return 0;
}

/**
 * \ingroup nuclientAPI
 * \brief Destroy an error (free memory)
 */
void nu_client_error_destroy(nuclient_error_t * err)
{
	if (err != NULL)
		free(err);
}

/**
 * \ingroup nuclientAPI
 * \brief Convert an error to an human readable string
 */
const char *nu_client_strerror(nuauth_session_t * session, nuclient_error_t * err)
{
	if (err == NULL) {
		return "Error structure was not initialised";
	}

	switch (err->family) {
	case NUSSL_ERR:
		if(session == NULL || session->nussl == NULL)
			return "NuSSL initialization error.";
		return nussl_get_error(session->nussl);
	case SASL_ERROR:
		return sasl_errstring(err->error, NULL, NULL);
		break;
	case INTERNAL_ERROR:
		switch (err->error) {
		case NO_ERR:
			return "No error";
		case SESSION_NOT_CONNECTED_ERR:
			return "Session not connected";
		case TIMEOUT_ERR:
			return "Connection timeout";
		case DNS_RESOLUTION_ERR:
			return "DNS resolution error";
		case NO_ADDR_ERR:
			return "Address not recognized";
		case FILE_ACCESS_ERR:
			return "File access error";
		case CANT_CONNECT_ERR:
			return "Connection failed";
		case MEMORY_ERR:
			return "No more memory";
		case TCPTABLE_ERR:
			return "Unable to read connection table";
		case SEND_ERR:
			return "Unable to send packet to nuauth";
		case BAD_CREDENTIALS_ERR:
			return "Bad credentials";
		case BINDING_ERR:
			return "Binding (source address) error";
		case NUSSL_INIT_ERR:
			return "NuSSL initialisation failed.";
		default:
			return "Unknown internal error code";
		}
		break;
	default:
		return "Unknown family error";
	}
}

/**
 * \ingroup nuclientAPI
 * Get version of nuclient library (eg. "2.1.1-3")
 *
 * \return Nuclient version string
 */
const char *nu_get_version()
{
	return NUCLIENT_VERSION;
}

/**
 * \ingroup nuclientAPI
 * Check if libnuclient if the specified version. Use #NUCLIENT_VERSION
 * as argument. See also function nu_get_version().
 *
 * \return Return 1 if ok, 0 if versions are different.
 */
int nu_check_version(const char *version)
{
	if (strcmp(NUCLIENT_VERSION, version) == 0)
		return 1;
	else
		return 0;
}

/** @} */

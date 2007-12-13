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

/**
 * \defgroup libnuclient Libnuclient
 * @{
 */

/*! \file libnuclient.c
  \brief Main file for libnuclient

  It contains all the exported functions
  */

/**
 * Use gcry_malloc_secure() to disallow a memory page
 * to be moved to the swap
 */
#define USE_GCRYPT_MALLOC_SECURE

#include "nufw_source.h"
#include "nuclient.h"
#include <pthread.h>
#include <sasl/sasl.h>
#include <sasl/saslutil.h>
#include <stdarg.h>		/* va_list, va_start, ... */
#include <langinfo.h>
#include <proto.h>
#include "client.h"
#include "security.h"
#include "sys_config.h"
#include "internal.h"
#include <sys/utsname.h>
#include <nussl_ssl.h>
#include <nussl_session.h>
#include <nussl_request.h> /* ne__negotiate_ssl */
#include <nussl_utils.h> /* NE_OK definition */

/*
 * #ifndef NUCLIENT_WITHOUT_DIFFIE_HELLMAN
#  define DH_BITS 1024
#endif
*/
/* static const int cert_type_priority[3] = { GNUTLS_CRT_X509, 0 }; */


void nu_exit_clean(nuauth_session_t * session)
{
	if (session->ct) {
		tcptable_free(session->ct);
	}
	/*if (session->socket > 0) {
		shutdown(session->socket, SHUT_WR);
		close(session->socket);
		session->socket = 0;
	}*/

	secure_str_free(session->username);
	secure_str_free(session->password);

	pthread_cond_destroy(&(session->check_cond));
	pthread_mutex_destroy(&(session->check_count_mutex));
	pthread_mutex_destroy(&(session->mutex));
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
 *  - nu_client_check(): do a check, it has to be run at regular interval
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
	/* kill all threads */
	ask_session_end(session);
	/* all threads are dead, we are the one who can access to it */
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

	/*gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);*/
	/* ret = gnutls_global_init(); */

/*
	if (ret != 0) {
		SET_ERROR(err, GNUTLS_ERROR, ret);
		return 0;
	}
*/

	ne_sock_init();

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
/*	gnutls_global_deinit();_password
 *	*/
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
 * Initialize TLS:
 *    - Set key filename (and test if the file does exist)
 *    - Set certificate filename (and test if the file does exist)
 *    - Set trust file of credentials (if needed)
 *    - Set certificate (if key and cert. are present)
 *    - Init. TLS session
 *
 * \param session Pointer to client session
 * \param keyfile Complete path to a key file stored in PEM format (can be NULL)
 * \param certfile Complete path to a certificate file stored in PEM format (can be NULL)
 * \param cafile Complete path to a certificate authority file stored in PEM format (can be NULL)
 * \param tls_password Certificate password string
 * \param err Pointer to a nuclient_error_t: which contains the error
 * \return Returns 0 on error (error description in err), 1 otherwise
 */
int nu_client_setup_tls(nuauth_session_t * session,
			char *keyfile, char *certfile, char *cafile,
			char *tls_password, nuclient_error_t * err)
{
	char castring[256];
	char certstring[256];
	char keystring[256];
	char *home = nu_get_home_dir();
	int exit_on_error = 0;
	int ok;
	int ret;

	session->tls_password = tls_password;

	/* If the user specified a certficate and a key on command line,
	 * exit if we fail loading them.
	 * Elsewise, try loading certs from ~/.nufw/, but continue if we fail
	 */
	if (certfile || keyfile)
		exit_on_error = 1;
#if XXX

	/* compute patch keyfile */
	if (keyfile == NULL && home != NULL) {
		ok = secure_snprintf(keystring, sizeof(keystring),
				     "%s/.nufw/key.pem", home);
		if (ok)
			keyfile = keystring;
	}

	/* test if key file exists */
	if (keyfile != NULL && access(keyfile, R_OK) != 0) {
		if (exit_on_error) {
			if (session->verbose)
			    printf("Unable to load key file: %s\n", keyfile);
			SET_ERROR(err, INTERNAL_ERROR, FILE_ACCESS_ERR);
			if (home) {
				free(home);
			}
			errno = EBADF;
			return 0;
		}
		keyfile = NULL;
	}

	if (certfile == NULL && home != NULL) {
		ok = secure_snprintf(certstring, sizeof(certstring),
				     "%s/.nufw/cert.pem", home);
		if (ok)
			certfile = certstring;
	}
	/* test if cert exists */
	if (certfile != NULL && access(certfile, R_OK) != 0) {
		if (exit_on_error) {
			printf("Unable to load certificate file : %s\n", certfile);
			SET_ERROR(err, INTERNAL_ERROR, FILE_ACCESS_ERR);
			if (home) {
				free(home);
			}
			errno = EBADF;
			return 0;
		}
		certfile = NULL;
	}
	if (cafile == NULL && home != NULL) {
		ok = secure_snprintf(castring, sizeof(castring),
				     "%s/.nufw/cacert.pem", home);
		if (ok)
			cafile = castring;
		/* if computed cafile is not present we reset to cafile to NULL */
		if (access(cafile, R_OK) != 0) {
			if (errno == EACCES) {
				printf("Warning, unable to access CA file : %s\n", cafile);
			}
			cafile = NULL;
		}
	}
	/* test if cert exists */
	if (cafile != NULL && access(cafile, R_OK) != 0) {
		if (exit_on_error) {
			printf("Unable to load CA file : %s\n", cafile);
			SET_ERROR(err, INTERNAL_ERROR, FILE_ACCESS_ERR);
			errno = EBADF;
			if (home) {
				free(home);
			}
			return 0;
		}
		cafile = NULL;
	}

	/* sets the trusted cas file */
	if (cafile != NULL)
	{
		ret =
		    gnutls_certificate_set_x509_trust_file(session->cred, cafile,
							   GNUTLS_X509_FMT_PEM);
		if (ret < 0) {
			SET_ERROR(err, GNUTLS_ERROR, ret);
			return 0;
		}
		session->need_ca_verif = 1;
	}

	if (certfile != NULL && keyfile != NULL) {
		ret =
		    gnutls_certificate_set_x509_key_file(session->cred,
							 certfile, keyfile,
							 GNUTLS_X509_FMT_PEM);
		if (ret < 0) {
			SET_ERROR(err, GNUTLS_ERROR, ret);
			if (home) {
				free(home);
			}
			return 0;
		}
	}

	/* put the x509 credentials to the current session */
	ret =
	    gnutls_credentials_set(session->tls, GNUTLS_CRD_CERTIFICATE,
				   session->cred);
	if (ret < 0) {
		SET_ERROR(err, GNUTLS_ERROR, ret);
		if (home) {
			free(home);
		}
		return 0;
	}
	session->need_set_cred = 0;
	if (home) {
		free(home);
	}
#endif
	return 1;
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
	int ret;

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
	session->count_msg_cond = -1;
	session->auth_by_default = 1;
	session->packet_seq = 0;
	session->checkthread = NULL_THREAD;
	session->recvthread = NULL_THREAD;
	session->ct = NULL;
	session->tls_password = NULL;
	session->debug_mode = 0;
	session->verbose = 1;
	session->timestamp_last_sent = time(NULL);
	session->need_set_cred = 1;
	session->need_ca_verif = 0;
	session->default_hostname = NULL;
	session->default_port = NULL;

	load_sys_config(session);

	/* create session mutex */
	pthread_mutex_init(&(session->mutex), NULL);
	pthread_mutex_init(&(session->check_count_mutex), NULL);
	pthread_cond_init(&(session->check_cond), NULL);

	if (tcptable_init(&new) == 0) {
		SET_ERROR(err, INTERNAL_ERROR, MEMORY_ERR);
		nu_exit_clean(session);
		return NULL;
	}
	session->ct = new;

	session->nussl = ne_session_create(session->default_hostname, 4129); /* XXX: don't use default values */
	/* X509 stuff */
#if XXX
	ret = gnutls_certificate_allocate_credentials(&(session->cred));

	if (ret != 0) {
		SET_ERROR(err, GNUTLS_ERROR, ret);
		nu_exit_clean(session);
		return NULL;
	}

	if (!nu_client_reset_tls(session))
	{
		SET_ERROR(err, GNUTLS_ERROR, ret);
		nu_exit_clean(session);
	}
#endif
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
		      /* TODO: To remove */ unsigned char diffie_hellman, nuclient_error_t * err)
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
		      /* TODO: To remove */ unsigned char diffie_hellman, nuclient_error_t * err)
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
	/* close TLS conneciton */
	ask_session_end(session);

	/* delete old TLS session and create a new TLS session */
/*	gnutls_deinit(session->tls);
	gnutls_init(&session->tls, GNUTLS_CLIENT);
	gnutls_set_default_priority(session->tls);
	gnutls_certificate_type_set_priority(session->tls,
					     cert_type_priority);*/
	session->need_set_cred = 1;

	/* close socket */
/*	if (session->socket > 0) {
		shutdown(session->socket, SHUT_WR);
		close(session->socket);
	}
*/
	/* reset fields */
	session->connected = 0;
	session->count_msg_cond = -1;
	session->timestamp_last_sent = time(NULL);
/*	session->socket = -1; */
	session->checkthread = 0;
	session->recvthread = 0;
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
#if XXX
	if (session->need_set_cred) {
		/* put the x509 credentials to the current session */
		int ret =
		    gnutls_credentials_set(session->tls,
					   GNUTLS_CRD_CERTIFICATE,
					   session->cred);
		if (ret < 0) {
			SET_ERROR(err, GNUTLS_ERROR, ret);
			return 0;
		}
		session->need_set_cred = 0;
	}
	/* set field about host */
	if (!init_socket(session, hostname, service, err)) {
		return 0;
	}

	if (!tls_handshake(session, err)) {
		return 0;
	}
#endif
	session->need_set_cred = 0;

	if (open_connection(session->nussl) != NE_OK) {
		printf("%s\n", ne_get_error(session->nussl));
		return 0;
	}

	if (!init_sasl(session, err)) {
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
const char *nu_client_strerror(nuclient_error_t * err)
{
	if (err == NULL)
		return "Error structure was not initialised";
	switch (err->family) {
#if XXX
	case GNUTLS_ERROR:
		return gnutls_strerror(err->error);
		break;
#endif
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

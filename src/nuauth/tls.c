/*
 ** Copyright(C) 2004-2008 INL
 ** Written by  Eric Leblond <regit@inl.fr>
 **             Vincent Deffontaines <gryzor@inl.fr>
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
 **
 */

#include "auth_srv.h"
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <nubase.h>
#include <nussl.h>

/**
 * \addtogroup TLS
 * @{
 */

/* } <- Added to avoid false positive
 * with check_log introduced by the
 * comment just above ;-) */

/**
 * \file nuauth/tls.c
 * \brief Functions use to create/destroy a TLS connection
 *
 * Contain common functions tor TLS handling
 */


/* These are global */
struct nuauth_tls_t nuauth_tls;

/* XXX: *nuauth_ssl replaces nuauth_tls*/
struct nuauth_ssl_t nuauth_ssl;


extern int ssl_connect(const char *hostname, const char *service)
{
	unsigned int port = atoi(service);

	nuauth_ssl.session = nussl_session_create();
	if ( ! nuauth_ssl.session ) {
		log_message(CRITICAL, DEBUG_AREA_AUTH,
				"Cannot allocate nussl session!");
	return -1;
	}

/*       nussl_set_hostinfo(nussl, hostname, port);*/
	return 0;
}

/**
 * Strictly close a TLS session: call gnutls_deinit() and free memory.
 * Nothing to care about client.
 *
 * \param session A session with a client
 * \param socket_fd File descriptor of the connection (created by accept() syscall)
 */
void close_tls_session(int socket_fd, gnutls_session * session)
{
	if (close(socket_fd))
		log_message(VERBOSE_DEBUG, DEBUG_AREA_USER,
			    "close_tls_session: close() failed (error code %i)!",
			    errno);
	gnutls_credentials_clear(*session);
	gnutls_deinit(*session);
	debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_USER | DEBUG_AREA_GW,
			  "gnutls_deinit() was called");
	g_free(session);
}

/**
 * Check certificates of a session. Only accept certificate of type x509.
 *
 * \return SASL_OK if ok, SASL error code else
 */
gint check_certs_for_tls_session(gnutls_session session)
{
	unsigned int status;
	int ret;
	/* This verification function uses the trusted CAs in the credentials
	 * structure. So you must have installed one or more CA certificates.
	 */
	ret = gnutls_certificate_verify_peers2(session, &status);
	if (ret < 0) {
		g_warning("Certificate verification failed: %s",
				gnutls_strerror(ret));
		return SASL_BADPARAM;
	}

	if (status) {
		if (status & GNUTLS_CERT_SIGNER_NOT_FOUND) {
			g_message("The certificate hasn't got a known issuer.");
			return SASL_NOVERIFY;
		}

		if (status & GNUTLS_CERT_REVOKED) {
			g_message("The certificate has been revoked.");
			return SASL_EXPIRED;
		}
		g_message("The certificate is not trusted.");
		return SASL_FAIL;
	}

	if (gnutls_certificate_type_get(session) == GNUTLS_CRT_X509) {
		return check_x509_certificate_validity(session);
	} else {
		/* we only support X509 for now */
		return SASL_BADPARAM;
	}
	return SASL_OK;
}

/**
 * Create the TLS server using the credentials ::x509_cred.
 *
 * \return Pointer to the TLS session
 */
gnutls_session *initialize_tls_session()
{
	gnutls_session *session;
#if 0
	const int cert_type_priority[2] = { GNUTLS_CRT_X509, 0 };
#endif

	session = g_new0(gnutls_session, 1);
	if (session == NULL)
		return NULL;

	if (gnutls_init(session, GNUTLS_SERVER) != 0) {
		g_free(session);
		return NULL;
	}

	/* avoid calling all the priority functions, since the defaults are adequate */
	if (gnutls_set_default_priority(*session) < 0) {
		g_free(session);
		return NULL;
	}
#if 0
	if (gnutls_certificate_type_set_priority
	    (*session, cert_type_priority) < 0)
		return NULL;
#endif

	if (gnutls_credentials_set
	    (*session, GNUTLS_CRD_CERTIFICATE, nuauth_tls.x509_cred) < 0) {
		g_free(session);
		return NULL;
	}
	/* request client certificate if any.  */
	gnutls_certificate_server_set_request(*session,
					      nuauth_ssl.request_cert);

	gnutls_dh_set_prime_bits(*session, DH_BITS);

	return session;
}

/**
 * Refresh crl file
 *
 * This function is run periodically because it is pushed with
 * cleanup_func_push() to the list of nuauth periodically run
 * function.
 */

void refresh_crl_file()
{
#if 0
XXX: crl not managed yet, nuauth_tls.crl_file_mtime used uninitialized

	nuauth_tls.crl_refresh_counter++;
	if (nuauth_tls.crl_refresh == nuauth_tls.crl_refresh_counter) {
		struct stat stats;
		stat(nuauth_tls.crl_file, &stats);
		if (nuauth_tls.crl_file_mtime < stats.st_mtime) {
			int ret;
			ret = gnutls_certificate_set_x509_crl_file(nuauth_tls.
							     x509_cred,
							     nuauth_tls.crl_file,
							     GNUTLS_X509_FMT_PEM);
			if(ret < 0)
			{
				log_message(INFO, DEBUG_AREA_PERF,
						"[%i] NuFW TLS: CRL file reloading failed (%s)",
						getpid(), gnutls_strerror(ret));
			}

		}
		nuauth_tls.crl_refresh_counter = 0;
	}
#endif
}

/**
 * TLS push function: send data to the socket in non-blocking mode.
 */
static ssize_t tls_push_func(gnutls_transport_ptr ptr, const void *buf,
			     size_t count)
{
	int fd = GPOINTER_TO_INT(ptr);
	return send(fd, buf, count, MSG_DONTWAIT);
}


/**
 * Realize a tls connection: call initialize_tls_session(), set tranport
 * pointer to the socket file descriptor (socket_fd), set push function to
 * tls_push_func(), then do the gnutls_handshake().
 *
 * Finally checks the certificate using check_certs_for_tls_session()
 * if needed.
 *
 * \param socket_fd Socket to established TLS session on
 * \param session_ptr Pointer of pointer to a gnutls session
 * \return Returns SASL_BADPARAM if fails, SASL_OK otherwise.
 */
int tls_connect(int socket_fd, gnutls_session ** session_ptr)
{
	int ret;
	gnutls_session *session;
#ifdef PERF_DISPLAY_ENABLE
	struct timeval leave_time, entry_time, elapsed_time;
#endif
	/* check arguments */
	if (session_ptr == NULL) {
		log_message(INFO, DEBUG_AREA_GW | DEBUG_AREA_USER,
			    "NuFW TLS Init failure (session_ptr is NULL)");
		close(socket_fd);
		return SASL_BADPARAM;
	}

	/* init. tls session */
	session = initialize_tls_session();
	if (session == NULL) {
		log_message(INFO, DEBUG_AREA_GW | DEBUG_AREA_USER,
			    "NuFW TLS Init failure (initialize_tls_session())");
		close(socket_fd);
		return SASL_BADPARAM;
	}

	gnutls_transport_set_ptr(*session, GINT_TO_POINTER(socket_fd));
	gnutls_transport_set_push_function(*session, tls_push_func);

	*session_ptr = session;
	ret = 0;

#ifdef PERF_DISPLAY_ENABLE
	if (nuauthconf->debug_areas & DEBUG_AREA_PERF) {
		gettimeofday(&entry_time, NULL);
	}
#endif
	do {
		log_message(INFO, DEBUG_AREA_GW | DEBUG_AREA_USER,
			    "NuFW TLS Handshaking (last error: %i)", ret);
		ret = gnutls_handshake(*session);
	} while (ret < 0 && !gnutls_error_is_fatal(ret));
#ifdef PERF_DISPLAY_ENABLE
	if (nuauthconf->debug_areas & DEBUG_AREA_PERF) {
		gettimeofday(&leave_time, NULL);
	}
#endif

	if (ret < 0) {
		close_tls_session(socket_fd, session);
		log_message(INFO, DEBUG_AREA_GW | DEBUG_AREA_USER,
			    "NuFW TLS Handshake has failed (%s)",
			    gnutls_strerror(ret));
		return SASL_BADPARAM;
	}
#ifdef PERF_DISPLAY_ENABLE
	if (nuauthconf->debug_areas & DEBUG_AREA_PERF) {
		timeval_substract(&elapsed_time, &leave_time, &entry_time);
		log_message(INFO, DEBUG_AREA_PERF,
				"TLS Handshake duration : %.1f msec",
				(double)elapsed_time.tv_sec*1000+
				(double)(elapsed_time.tv_usec/1000));
	}
#endif

	debug_log_message(DEBUG, DEBUG_AREA_GW | DEBUG_AREA_USER, "NuFW TLS Handshaked");

	debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_GW | DEBUG_AREA_USER, "NuFW TLS mac: %s",
			  gnutls_mac_get_name(gnutls_mac_get(*session)));
	debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_GW | DEBUG_AREA_USER, "NuFW TLS kx: %s",
			  gnutls_kx_get_name(gnutls_kx_get(*session)));

	debug_log_message(DEBUG, DEBUG_AREA_GW | DEBUG_AREA_USER,
			  "NuFW TLS Handshake was completed");

	if (nuauth_ssl.request_cert == NUSSL_CERT_REQUIRE) {
		/* certicate verification */
		ret = check_certs_for_tls_session(*session);
		if (ret != 0) {
			log_message(INFO, DEBUG_AREA_GW | DEBUG_AREA_USER,
				    "Certificate verification failed : %s",
				    gnutls_strerror(ret));
			close_tls_session(socket_fd, session);
			return SASL_BADPARAM;
		}
	} else {
		debug_log_message(DEBUG, DEBUG_AREA_GW | DEBUG_AREA_USER,
				  "Certificate verification is not done as requested");
	}

	return SASL_OK;
}

/**
 * Read conf file and allocate x509 credentials. This function should only be
 * called once because it uses the static variable ::dh_params
 */
int create_x509_credentials()
{
	char *nuauth_tls_key = NULL;
	char *nuauth_tls_cert = NULL;
	char *nuauth_tls_cacert = NULL;
	char *nuauth_tls_key_passwd = NULL;
	char *nuauth_tls_crl = NULL;
	char *configfile = DEFAULT_CONF_FILE;
	int ret;
	confparams_t nuauth_tls_vars[] = {
		{"nuauth_tls_key", G_TOKEN_STRING, 0,
		 g_strdup(NUAUTH_KEYFILE)},
		{"nuauth_tls_cert", G_TOKEN_STRING, 0,
		 g_strdup(NUAUTH_CERTFILE)},
		{"nuauth_tls_cacert", G_TOKEN_STRING, 0,
		 g_strdup(NUAUTH_CACERTFILE)},
		{"nuauth_tls_crl", G_TOKEN_STRING, 0, NULL},
		{"nuauth_tls_crl_refresh", G_TOKEN_INT,
		 DEFAULT_REFRESH_CRL_INTERVAL, NULL},
		{"nuauth_tls_key_passwd", G_TOKEN_STRING, 0, NULL},
		{"nuauth_tls_request_cert", G_TOKEN_INT, FALSE, NULL},
		{"nuauth_tls_auth_by_cert", G_TOKEN_INT, FALSE, NULL}
	};
	const unsigned int nb_params =
	    sizeof(nuauth_tls_vars) / sizeof(confparams_t);
	int int_authcert;
	int int_requestcert;

	if(!parse_conffile(configfile, nb_params, nuauth_tls_vars))
	{
	        log_message(FATAL, DEBUG_AREA_MAIN, "Failed to load config file %s", configfile);
		return 0;
	}

	/* We create the NuSSL object */
	nuauth_ssl.session = nussl_session_create();


#define READ_CONF(KEY) \
	get_confvar_value(nuauth_tls_vars, nb_params, KEY)

	nuauth_tls_key = (char *) READ_CONF("nuauth_tls_key");
	nuauth_tls_cert = (char *) READ_CONF("nuauth_tls_cert");
	nuauth_tls_cacert = (char *) READ_CONF("nuauth_tls_cacert");
	nuauth_tls_crl = (char *) READ_CONF("nuauth_tls_crl");
	nuauth_tls_key_passwd =
	    (char *) READ_CONF("nuauth_tls_key_passwd");
	int_requestcert =
	    *(int *) READ_CONF("nuauth_tls_request_cert");
	nuauth_tls.crl_refresh =
	    *(int *) READ_CONF("nuauth_tls_crl_refresh");
	int_authcert = *(int *) READ_CONF("nuauth_tls_auth_by_cert");
#undef READ_CONF

#if 0
/* XXX: Double check this and close ticket #120 */
	if ((int_authcert >= NO_AUTH_BY_CERT)
			&& (int_authcert < MAX_AUTH_BY_CERT)) {
		nuauth_tls.auth_by_cert = int_authcert;
	} else {
		g_warning("[%i] config : invalid nuauth_tls_auth_by_cert value: %d",
			getpid(), int_authcert);

		return 0;
	}

	if ((nuauth_tls.auth_by_cert == MANDATORY_AUTH_BY_CERT)
	&& (nuauth_tls.request_cert != GNUTLS_CERT_REQUIRE)) {
		log_message(INFO, DEBUG_AREA_AUTH | DEBUG_AREA_USER,
			    "Mandatory certificate authentication asked, asking certificate");
		nuauth_tls.request_cert = GNUTLS_CERT_REQUIRE;
	}
#endif

	if (NUSSL_VALID_REQ_TYPE(int_authcert)) {
		nuauth_ssl.auth_by_cert = int_authcert;
	} else {
		log_area_printf(DEBUG_AREA_AUTH, DEBUG_LEVEL_WARNING,
				"[%i] config: Invalid nuauth_tls_auth_by_cert value: %d",
				getpid(), int_authcert);

		return 0;
	}

	if ((nuauth_ssl.auth_by_cert == NUSSL_CERT_REQUIRE)
		&& (nuauth_ssl.request_cert != NUSSL_CERT_REQUIRE)) {
		log_area_printf(DEBUG_AREA_AUTH, DEBUG_LEVEL_INFO,
				"Mandatory certificate authentication asked, asking certificate");
		nuauth_tls.request_cert = NUSSL_CERT_REQUIRE;
	}

	/* free config struct */
	free_confparams(nuauth_tls_vars,
			sizeof(nuauth_tls_vars) / sizeof(confparams_t));

	if (access(nuauth_tls_key, R_OK)) {
		g_warning("[%i] TLS : can not access key file %s",
			getpid(), nuauth_tls_key);

		return 0;
	}
	if (access(nuauth_tls_cert, R_OK)) {
		g_warning("[%i] TLS : can not access cert file %s",
			getpid(), nuauth_tls_cert);

		return 0;
	}

	/* don't refresh crl if there is none */

	if (nuauth_tls_crl) {
		nussl_set_crl_refresh(nuauth_ssl.session, 1);
	}

	ret = nussl_ssl_context_set_verify(nuauth_ssl.session, nuauth_ssl.request_cert, nuauth_tls_cacert);
	if (ret <= 0) {
		g_warning
		    ("[%i] Problem with certificate trust file : %s",
		     getpid(), gnutls_strerror(ret));

		if (nuauth_ssl.request_cert == NUSSL_CERT_REQUIRE
			|| nuauth_ssl.auth_by_cert == NUSSL_CERT_REQUIRE)
			return 0;
	}

	ret = nussl_ssl_set_keypair(nuauth_ssl.session, nuauth_tls_cert, nuauth_tls_key);
	if (ret < 0) {
		g_warning("[%i] Problem with certificate key file : %s",
			getpid(), gnutls_strerror(ret));

		return 0;
	}
#ifdef DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG, DEBUG_AREA_USER)) {
		g_message("TLS using key %s and cert %s", nuauth_tls_key,
			  nuauth_tls_cert);
		if (nuauth_ssl.request_cert == NUSSL_CERT_REQUIRE)
			g_message("TLS require cert from client");

#endif
	g_free(nuauth_tls_key);
	g_free(nuauth_tls_cert);
	g_free(nuauth_tls_cacert);

	if (nuauth_tls_crl) {
		log_message(VERBOSE_DEBUG, DEBUG_AREA_GW | DEBUG_AREA_USER,
			    "Certificate revocation list: %s",
			    nuauth_tls_crl);

		if (access(nuauth_tls_crl, R_OK)) {
			g_warning("[%i] TLS : can not access crl file %s",
				getpid(), nuauth_tls_crl);

			return 0;
		}
		nuauth_tls.crl_file = nuauth_tls_crl;
		ret = nussl_ssl_cert_set_x509_crl_file(nuauth_ssl.session,
						       nuauth_tls.crl_file);
		if (ret < 0) {
			g_warning("[%i] Problem with certificate key file : %s",
				getpid(), gnutls_strerror(ret));

			return 0;
		}
	}

	ret = nussl_ssl_cert_generate_dh_params(nuauth_ssl.session);
	if (ret < 0) {
		g_warning("[%i] Problem generating dh params",
			getpid());

		return 0;
	}

	nussl_ssl_cert_dh_params(nuauth_ssl.session);

	cleanup_func_push(refresh_crl_file);

	return 1;
}

/**
 * Free memory (of ::x509_cred) and call gnutls_global_deinit().
 */
void end_tls()
{
	gnutls_certificate_free_keys(nuauth_tls.x509_cred);
	gnutls_certificate_free_credentials(nuauth_tls.x509_cred);
	gnutls_dh_params_deinit(nuauth_tls.dh_params);
	gnutls_global_deinit();
}

/**@}*/

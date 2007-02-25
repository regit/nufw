/*
 ** Copyright(C) 2004-2006 INL
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


/**
 * \addtogroup TLS
 * @{
 */

/**
 * \file nuauth/tls.c
 * \brief Functions use to create/destroy a TLS connection
 *
 * Contain common functions tor TLS handling
 */


/* These are global */
struct nuauth_tls_t nuauth_tls;

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
		log_message(VERBOSE_DEBUG, AREA_USER,
			    "close_tls_session: close() failed (error code %i)!",
			    errno);
	gnutls_credentials_clear(*session);
	gnutls_deinit(*session);
	debug_log_message(VERBOSE_DEBUG, AREA_USER,
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
		g_warning("Certificate verification failed\n");
		return SASL_BADPARAM;
	}

	if (status & GNUTLS_CERT_INVALID) {
		g_message("The certificate is not trusted.");
		return SASL_FAIL;
	}

	if (status & GNUTLS_CERT_SIGNER_NOT_FOUND) {
		g_message("The certificate hasn't got a known issuer.");
		return SASL_NOVERIFY;
	}

	if (status & GNUTLS_CERT_REVOKED) {
		g_message("The certificate has been revoked.");
		return SASL_EXPIRED;
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
					      nuauth_tls.request_cert);

	gnutls_dh_set_prime_bits(*session, DH_BITS);

	return session;
}

/**
 * Generate Diffie Hellman parameters - for use with DHE
 * (Ephemeral Diffie Hellman) kx algorithms. These should be discarded
 * and regenerated once a day, once a week or once a month. Depending on
 * the security requirements.
 *
 * \return If an error occurs returns -1, else return 0
 */
static int generate_dh_params(gnutls_dh_params * dh_params)
{
	if (gnutls_dh_params_init(dh_params) < 0)
		return -1;
	if (gnutls_dh_params_generate2(*dh_params, DH_BITS) < 0)
		return -1;
	return 0;
}

/**
 * return
 */

void refresh_crl_file()
{
	nuauth_tls.crl_refresh_counter++;
	if (nuauth_tls.crl_refresh == nuauth_tls.crl_refresh_counter) {
		struct stat stats;
		stat(nuauth_tls.crl_file, &stats);
		if (nuauth_tls.crl_file_mtime < stats.st_mtime) {
			gnutls_certificate_set_x509_crl_file(nuauth_tls.
							     x509_cred,
							     nuauth_tls.
							     crl_file,
							     GNUTLS_X509_FMT_PEM);
		}
		nuauth_tls.crl_refresh_counter = 0;
	}
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
		log_message(INFO, AREA_MAIN,
			    "NuFW TLS Init failure (session_ptr is NULL)");
		close(socket_fd);
		return SASL_BADPARAM;
	}

	/* init. tls session */
	session = initialize_tls_session();
	if (session == NULL) {
		log_message(INFO, AREA_MAIN,
			    "NuFW TLS Init failure (initialize_tls_session())");
		close(socket_fd);
		return SASL_BADPARAM;
	}

	gnutls_transport_set_ptr(*session, GINT_TO_POINTER(socket_fd));
	gnutls_transport_set_push_function(*session, tls_push_func);

	*session_ptr = session;
	ret = 0;

#ifdef PERF_DISPLAY_ENABLE
	gettimeofday(&entry_time, NULL);
#endif
	do {
		debug_log_message(DEBUG, AREA_MAIN,
				  "NuFW TLS Handshaking (last error: %i)",
				  ret);
		ret = gnutls_handshake(*session);
	} while (ret < 0 && !gnutls_error_is_fatal(ret));
#ifdef PERF_DISPLAY_ENABLE
	gettimeofday(&leave_time, NULL);
#endif

	if (ret < 0) {
		close_tls_session(socket_fd, session);
		log_message(DEBUG, AREA_MAIN,
			    "NuFW TLS Handshake has failed (%s)\n\n",
			    gnutls_strerror(ret));
		return SASL_BADPARAM;
	}
#ifdef PERF_DISPLAY_ENABLE
	timeval_substract(&elapsed_time, &leave_time, &entry_time);
	log_message(INFO, AREA_MAIN,
		    "Handshake duration : %ld sec %03ld msec",
		    elapsed_time.tv_sec, elapsed_time.tv_usec / 1000);
#endif

	debug_log_message(DEBUG, AREA_MAIN, "NuFW TLS Handshaked");

	debug_log_message(VERBOSE_DEBUG, AREA_MAIN, "NuFW TLS mac: %s",
			  gnutls_mac_get_name(gnutls_mac_get(*session)));
	debug_log_message(VERBOSE_DEBUG, AREA_MAIN, "NuFW TLS kx: %s",
			  gnutls_kx_get_name(gnutls_kx_get(*session)));

	debug_log_message(DEBUG, AREA_MAIN,
			  "NuFW TLS Handshake was completed");

	if (nuauth_tls.request_cert == GNUTLS_CERT_REQUIRE) {
		/* certicate verification */
		ret = check_certs_for_tls_session(*session);
		if (ret != 0) {
			log_message(INFO, AREA_MAIN,
				    "Certificate verification failed : %s",
				    gnutls_strerror(ret));
			close_tls_session(socket_fd, session);
			return SASL_BADPARAM;
		}
	} else {
		debug_log_message(DEBUG, AREA_MAIN,
				  "Certificate verification is not done as requested");
	}

	return SASL_OK;
}

/**
 * Read conf file and allocate x509 credentials. This function should only be
 * called once because it uses the static variable ::dh_params
 */
void create_x509_credentials()
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
	    sizeof(nuauth_tls_vars) / sizeof(confparams);

	parse_conffile(configfile, nb_params, nuauth_tls_vars);

#define READ_CONF(KEY) \
    get_confvar_value(nuauth_tls_vars, nb_params, KEY)

	nuauth_tls_key = (char *) READ_CONF("nuauth_tls_key");
	nuauth_tls_cert = (char *) READ_CONF("nuauth_tls_cert");
	nuauth_tls_cacert = (char *) READ_CONF("nuauth_tls_cacert");
	nuauth_tls_crl = (char *) READ_CONF("nuauth_tls_crl");
	nuauth_tls_key_passwd =
	    (char *) READ_CONF("nuauth_tls_key_passwd");
	nuauth_tls.request_cert =
	    *(int *) READ_CONF("nuauth_tls_request_cert");
	nuauth_tls.crl_refresh =
	    *(int *) READ_CONF("nuauth_tls_crl_refresh");
	nuauth_tls.auth_by_cert =
	    *(int *) READ_CONF("nuauth_tls_auth_by_cert");
#undef READ_CONF

	/* free config struct */
	free_confparams(nuauth_tls_vars,
			sizeof(nuauth_tls_vars) / sizeof(confparams));

	if (access(nuauth_tls_key, R_OK)) {
		g_error("[%i] TLS : can not access key file %s\n",
			getpid(), nuauth_tls_key);
	}
	if (access(nuauth_tls_cert, R_OK)) {
		g_error("[%i] TLS : can not access cert file %s\n",
			getpid(), nuauth_tls_cert);
	}

	/* don't refresh crl if there is none */
	if (nuauth_tls_crl == NULL) {
		nuauth_tls.crl_refresh = 0;
	}
	nuauth_tls.crl_refresh_counter = 0;

	ret =
	    gnutls_certificate_allocate_credentials(&nuauth_tls.x509_cred);
	if (ret != 0) {
		if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING, DEBUG_AREA_USER)) {
			g_message
			    ("Problem with gnutls_certificate_allocate_credentials() : %s",
			     gnutls_strerror(ret));
		}
	}

	ret =
	    gnutls_certificate_set_x509_trust_file(nuauth_tls.x509_cred,
						   nuauth_tls_cacert,
						   GNUTLS_X509_FMT_PEM);
	if (ret <= 0) {
		if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING, DEBUG_AREA_USER)) {
			g_message
			    ("Problem with certificate trust file : %s",
			     gnutls_strerror(ret));
		}
	}
	ret =
	    gnutls_certificate_set_x509_key_file(nuauth_tls.x509_cred,
						 nuauth_tls_cert,
						 nuauth_tls_key,
						 GNUTLS_X509_FMT_PEM);
	if (ret < 0) {
		if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING, DEBUG_AREA_USER)) {
			g_message("Problem with certificate key file : %s",
				  gnutls_strerror(ret));
		}
	}
#ifdef DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG, DEBUG_AREA_USER)) {
		g_message("TLS using key %s and cert %s", nuauth_tls_key,
			  nuauth_tls_cert);
		if (nuauth_tls.request_cert == GNUTLS_CERT_REQUIRE)
			g_message("TLS require cert from client");
	}
#endif
	g_free(nuauth_tls_key);
	g_free(nuauth_tls_cert);
	g_free(nuauth_tls_cacert);

	if (nuauth_tls_crl) {
		log_message(VERBOSE_DEBUG, AREA_USER,
			    "Certificate revocation list: %s\n",
			    nuauth_tls_crl);

		if (access(nuauth_tls_crl, R_OK)) {
			g_error("[%i] TLS : can not access crl file %s\n",
				getpid(), nuauth_tls_crl);
		}
		nuauth_tls.crl_file = nuauth_tls_crl;
		gnutls_certificate_set_x509_crl_file(nuauth_tls.x509_cred,
						     nuauth_tls.crl_file,
						     GNUTLS_X509_FMT_PEM);
	}
	ret = generate_dh_params(&nuauth_tls.dh_params);
#ifdef DEBUG_ENABLE
	if (ret < 0)
		log_message(INFO, AREA_USER,
			    "generate_dh_params() failed");
#endif

	/*
	 * Gryzor doesnt understand wht dh_params is passed as 2nd argument, where a gnutls_dh_params_t structure is awaited
	 * gnutls_certificate_set_dh_params( x509_cred, 0);
	 */
	gnutls_certificate_set_dh_params(nuauth_tls.x509_cred,
					 nuauth_tls.dh_params);

	cleanup_func_push(refresh_crl_file);
}

/**
 * Thread which process addresses on tls push queue (tls_push_queue member
 * of ::nuauthdatas) which need an authentification.
 *
 * Lock is only needed when modifications are done, because when this thread
 * work (push mode) it's the only one who can modify the hash.
 *
 * Use a switch:
 *   - #WARN_MESSAGE: call warn_clients() (and may call ip_authentication_workers())
 *   - #FREE_MESSAGE: call delete_client_by_socket()
 *   - #INSERT_MESSAGE: call add_client()
 */
void *push_worker(GMutex * mutex)
{
	struct msg_addr_set *global_msg = g_new0(struct msg_addr_set, 1);
	struct nu_srv_message *msg = g_new0(struct nu_srv_message, 1);
	struct internal_message *message;
	GTimeVal tv;

	msg->type = SRV_REQUIRED_PACKET;
	msg->option = 0;
	msg->length = htons(4);
	global_msg->msg = msg;

	g_async_queue_ref(nuauthdatas->tls_push_queue);

	/* wait for message */
	while (g_mutex_trylock(mutex)) {
		g_mutex_unlock(mutex);

		/* wait a message during 1000ms */
		g_get_current_time(&tv);
		g_time_val_add(&tv, 1000);
		message =
		    g_async_queue_timed_pop(nuauthdatas->tls_push_queue,
					    &tv);
		if (message == NULL)
			continue;

		switch (message->type) {
		case WARN_MESSAGE:
			global_msg->addr =
			    ((tracking_t *) message->datas)->saddr;
			global_msg->found = FALSE;
			/* search in client array */
			warn_clients(global_msg);
			/* do we have found something */
			if (memcmp
			    (&global_msg->addr, &in6addr_any,
			     sizeof(in6addr_any)) != 0) {
				if (global_msg->found == FALSE) {
					/* if we do ip authentication send request to pool */
					if (nuauthconf->
					    do_ip_authentication) {
						g_thread_pool_push
						    (nuauthdatas->
						     ip_authentication_workers,
						     message->datas, NULL);
					} else {
						g_free(message->datas);
					}
				} else {
					/* free header */
					g_free(message->datas);
				}
			}
			break;

		case FREE_MESSAGE:
			delete_client_by_socket(GPOINTER_TO_INT
						(message->datas));
			break;

		case INSERT_MESSAGE:
			{
				struct tls_insert_data *datas =
				    message->datas;
				if (datas->data) {
					add_client(datas->socket,
						   datas->data);
				}
				g_free(datas);
			}
			break;
		default:
			g_message("lost");
		}
		g_free(message);
	}

	g_free(msg);
	g_free(global_msg);
	g_async_queue_unref(nuauthdatas->tls_push_queue);
	return NULL;
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

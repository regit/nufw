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

#define NULL_THREAD 0

#include "nuclient.h"
#include <sasl/saslutil.h>
#include <stdarg.h>		/* va_list, va_start, ... */
#include <gnutls/x509.h>
#include <langinfo.h>
#include <proto.h>
#include "client.h"
#include "security.h"

#ifndef GCRY_THREAD
#define GCRY_THREAD 1
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif

#ifndef NUCLIENT_WITHOUT_DIFFIE_HELLMAN
#  define DH_BITS 1024
#endif

#define REQUEST_CERT 0

static char *secure_str_copy(const char *orig);

static const int cert_type_priority[3] = { GNUTLS_CRT_X509, 0 };
char* nu_locale_charset;

#include <sys/utsname.h>

/**
 * Free a string allocated by secure_str_copy().
 *
 * If USE_GCRYPT_MALLOC_SECURE compilation option in not set,
 * free() is used.
 *
 * \return Copy of the string, or NULL on error.
 */
#ifdef USE_GCRYPT_MALLOC_SECURE
#   define secure_str_free(text) gcry_free(text)
#else
#   define secure_str_free(text) free(text)
#endif


/**
 * SASL callback used to get password
 *
 * \return SASL_OK if ok, EXIT_FAILURE on error
 */
int nu_get_usersecret(sasl_conn_t * conn __attribute__ ((unused)),
		      void *context __attribute__ ((unused)), int id,
		      sasl_secret_t ** psecret)
{
	size_t len;
	nuauth_session_t *session = (nuauth_session_t *) context;
	if (id != SASL_CB_PASS) {
		if (session->verbose)
			printf("getsecret not looking for pass");
		return SASL_BADPARAM;
	}
	if ((session->password == NULL) && session->passwd_callback) {
#if USE_UTF8
		char *utf8pass;
#endif
		char *givenpass=session->passwd_callback();
		if (!givenpass){
			return SASL_FAIL;
		}
#if USE_UTF8
		utf8pass = nu_client_to_utf8(givenpass, nu_locale_charset);
		free(givenpass);
		givenpass = utf8pass;
		if (!givenpass){
			return SASL_FAIL;
		}
#endif
		session->password = givenpass;
	}
	if (!psecret)
		return SASL_BADPARAM;

	len = strlen(session->password);
	*psecret =
	    (sasl_secret_t *) calloc(sizeof(sasl_secret_t) + len + 1,
				     sizeof(char));
	(*psecret)->len = len;
	SECURE_STRNCPY((char *) (*psecret)->data, session->password,
		       len + 1);
	return SASL_OK;
}

static int nu_get_userdatas(void *context __attribute__ ((unused)),
			    int id, const char **result, unsigned *len)
{
	nuauth_session_t *session = (nuauth_session_t *) context;
	/* paranoia check */
	if (!result)
		return SASL_BADPARAM;

	switch (id) {
	case SASL_CB_USER:
	case SASL_CB_AUTHNAME:
		if ((session->username == NULL) && session->username_callback) {
#if USE_UTF8
			char *utf8name;
#endif
			char *givenuser=session->username_callback();
#if USE_UTF8
			utf8name = nu_client_to_utf8(givenuser, nu_locale_charset);
			free(givenuser);
			givenuser = utf8name;
			if (givenuser == NULL){
				return SASL_FAIL;
			}
#endif
			session->username = givenuser;
		}
		*result = session->username;
		break;
	default:
		return SASL_BADPARAM;
	}

	if (len)
		*len = strlen(*result);

	return SASL_OK;
}

/**
 * Display an error message, prefixed by "Fatal error: ", and then exit the
 * program. If filename is not NULL and line different than zero, also prefix
 * the message with them.
 *
 * Example: "checks.c:45:Fatal error: Message ..."
 */
void do_panic(const char *filename, unsigned long line, const char *fmt,
	      ...)
{
	va_list args;
	va_start(args, fmt);
	printf("\n");
	if (filename != NULL && line != 0) {
		printf("%s:%lu:", filename, line);
	}
	printf("Fatal error: ");
	vprintf(fmt, args);
	printf("\n");
	fflush(stdout);
	exit(EXIT_FAILURE);
	va_end(args);
}

void nu_exit_clean(nuauth_session_t * session)
{
	if (session->ct) {
		tcptable_free(session->ct);
	}
	if (session->socket > 0) {
		shutdown(session->socket, SHUT_WR);
		close(session->socket);
		session->socket = 0;
	}

	secure_str_free(session->username);
	secure_str_free(session->password);

	if (session->cred) {
		gnutls_certificate_free_keys(session->cred);
		gnutls_certificate_free_credentials(session->cred);
	}
	if (session->diffie_hellman) {
		gnutls_dh_params_deinit(session->dh_params);
	}
	gnutls_deinit(session->tls);

	pthread_cond_destroy(&(session->check_cond));
	pthread_mutex_destroy(&(session->check_count_mutex));
	pthread_mutex_destroy(&(session->mutex));
	free(session);
}


static int samp_send(gnutls_session session, const char *buffer,
		     unsigned length, nuclient_error_t * err)
{
	char *buf;
	unsigned len, alloclen;
	int result;

	alloclen = ((length / 3) + 1) * 4 + 4;
	buf = malloc(alloclen);
	if (buf == NULL) {
		SET_ERROR(err, INTERNAL_ERROR, MEMORY_ERR);
		return 0;
	}

	result = sasl_encode64(buffer, length, buf + 3, alloclen, &len);
	if (result != SASL_OK) {
		SET_ERROR(err, SASL_ERROR, result);
		free(buf);
		return 0;
	}

	memcpy(buf, "C: ", 3);

	result = gnutls_record_send(session, buf, len + 3);
	free(buf);
	if (result < 0) {
		SET_ERROR(err, GNUTLS_ERROR, result);
		return 0;
	}
	return 1;
}



static unsigned samp_recv(gnutls_session session, char *buf, int bufsize,
			  nuclient_error_t * err)
{
	unsigned len;
	int result;
	int tls_len;

	tls_len = gnutls_record_recv(session, buf, bufsize);
	if (tls_len <= 0) {
		SET_ERROR(err, GNUTLS_ERROR, tls_len);
		return 0;
	}

	result = sasl_decode64(buf + 3, (unsigned) strlen(buf + 3), buf,
			       bufsize, &len);
	if (result != SASL_OK) {
		SET_ERROR(err, SASL_ERROR, result);
		return 0;
	}
	buf[len] = '\0';
	return len;
}



int mysasl_negotiate(nuauth_session_t * user_session, sasl_conn_t * conn,
		     nuclient_error_t * err)
{
	char buf[8192];
	const char *data;
	const char *chosenmech;
	unsigned len;
	int result;
	gnutls_session session = user_session->tls;

	memset(buf, 0, sizeof buf);
	/* get the capability list */
	len = samp_recv(session, buf, 8192, err);
	if (len == 0) {
		return SASL_FAIL;
	}

	result = sasl_client_start(conn,
				   buf, NULL, &data, &len, &chosenmech);

	if (user_session->verbose) {
		printf("Using mechanism %s\n", chosenmech);
	}

	if (result != SASL_OK && result != SASL_CONTINUE) {
		if (user_session->verbose) {
			printf("Error starting SASL negotiation");
			printf("\n%s\n", sasl_errdetail(conn));
		}
		SET_ERROR(err, SASL_ERROR, result);
		return SASL_FAIL;
	}

	strcpy(buf, chosenmech);
	if (data) {
		if (8192 - strlen(buf) - 1 < len) {
			return SASL_FAIL;
		}
		memcpy(buf + strlen(buf) + 1, data, len);
		len += (unsigned) strlen(buf) + 1;
		data = NULL;
	} else {
		len = (unsigned) strlen(buf);
	}

	if (!samp_send(session, buf, len, err)) {
		return SASL_FAIL;
	}

	while (result == SASL_CONTINUE) {
		if (user_session->verbose) {
			printf("Waiting for server reply...\n");
		}
		memset(buf, 0, sizeof(buf));
		len = samp_recv(session, buf, sizeof(buf), err);
		if (len <= 0) {
			printf("server problem, recv fail...\n");
			return SASL_FAIL;
		}
		result =
		    sasl_client_step(conn, buf, len, NULL, &data, &len);
		if (result != SASL_OK && result != SASL_CONTINUE) {
			if (user_session->verbose)
				printf("Performing SASL negotiation\n");
			SET_ERROR(err, SASL_ERROR, result);
		}
		if (data && len) {
			if (user_session->verbose)
				puts("Sending response...\n");
			if (!samp_send(session, data, len, err)) {
				return SASL_FAIL;
			}
		} else if (result != SASL_OK) {
			if (!samp_send(session, "", 0, err)) {
				return SASL_FAIL;
			}
		}
	}

	if (result != SASL_OK) {
		if (user_session->verbose)
			puts("Authentication failed...");
		return SASL_FAIL;
	} else {
		if (user_session->verbose)
			puts("Authentication started...\n");
	}

	return SASL_OK;
}

static int add_packet_to_send(nuauth_session_t * session, conn_t ** auth,
			      int *count_p, conn_t * bucket)
{
	int count = *count_p;
	if (count < CONN_MAX - 1) {
		auth[count] = bucket;
		(*count_p)++;
	} else {
		int i;
		auth[count] = bucket;
		if (send_user_pckt(session, auth) != 1) {
			/* error sending */
#if DEBUG
			printf("error when sending\n");
#endif

			return -1;
		}
		for (i = 0; i < CONN_MAX; i++) {
			auth[i] = NULL;
		}
		*count_p = 0;
	}
	return 1;
}

/**
 * \brief Compare connection tables and send packets
 *
 * Compare the `old' and `new' tables, sending packet to nuauth
 * if differences are found.
 *
 * \return -1 if error (then disconnect is needed) or the number of
 * authenticated packets if it has succeeded
 */
int compare(nuauth_session_t * session, conntable_t * old, conntable_t * new,
	    nuclient_error_t * err)
{
	int i;
	int count = 0;
	conn_t *auth[CONN_MAX];
	int nb_packets = 0;

	assert(old != NULL);
	assert(new != NULL);
	for (i = 0; i < CONNTABLE_BUCKETS; i++) {
		conn_t *bucket;
		conn_t *same_bucket;

		bucket = new->buckets[i];
		while (bucket != NULL) {
			same_bucket = tcptable_find(old, bucket);
			if (same_bucket == NULL) {
#if DEBUG
				printf("sending new\n");
#endif
				if (add_packet_to_send
				    (session, auth, &count,
				     bucket) == -1) {
					/* problem when sending we exit */
					return -1;
				}
				nb_packets++;
			} else {
				/* compare values of retransmit */
				if (bucket->retransmit >
				    same_bucket->retransmit) {
#if DEBUG
					printf("sending retransmit\n");
#endif
					if (add_packet_to_send
					    (session, auth, &count,
					     bucket) == -1) {
						/* problem when sending we exit */
						return -1;

					}
					nb_packets++;
				}

				/* solve timeout issue on UDP */
				if (bucket->protocol == IPPROTO_UDP) {
					/* send an auth packet if netfilter timeout may have been reached */
					if (same_bucket->createtime <
					    time(NULL) - UDP_TIMEOUT) {
#if DEBUG
						printf
						    ("working on timeout issue\n");
#endif
						if (add_packet_to_send
						    (session, auth, &count,
						     bucket)) {
							return -1;
						}
						nb_packets++;
					} else {
						bucket->createtime =
						    same_bucket->
						    createtime;
					}
				}
			}
			bucket = bucket->next;
		}
	}
	if (count > 0) {
		if (count < CONN_MAX) {
			auth[count] = NULL;
		}
		if (send_user_pckt(session, auth) != 1) {
			/* error sending */
			return -1;
		}
	}
	return nb_packets;
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

	gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
	ret = gnutls_global_init();
	if (ret != 0) {
		SET_ERROR(err, GNUTLS_ERROR, ret);
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
	gnutls_global_deinit();
}

/**
 * Create the operating system packet and send it to nuauth.
 * Packet is in format ::nuv2_authfield.
 *
 * \param session Pointer to client session
 * \param err Pointer to a nuclient_error_t: which contains the error
 */
int send_os(nuauth_session_t * session, nuclient_error_t * err)
{
	/* announce our OS */
	struct utsname info;
	struct nu_authfield osfield;
	char *oses;
	char *enc_oses;
	char *pointer;
	char *buf;
	unsigned stringlen;
	unsigned actuallen;
	int osfield_length;
	int ret;

	/* read OS informations */
	uname(&info);

	/* encode OS informations in base64 */
	stringlen = strlen(info.sysname) + 1
	    + strlen(info.release) + 1 + strlen(info.version) + 1;
#ifdef LINUX
	oses = alloca(stringlen);
#else
	oses = calloc(stringlen, sizeof(char));
#endif
	enc_oses = calloc(4 * stringlen, sizeof(char));
	(void) secure_snprintf(oses, stringlen,
			       "%s;%s;%s",
			       info.sysname, info.release, info.version);
	if (sasl_encode64
	    (oses, strlen(oses), enc_oses, 4 * stringlen,
	     &actuallen) == SASL_BUFOVER) {
		enc_oses = realloc(enc_oses, actuallen);
		sasl_encode64(oses, strlen(oses), enc_oses, actuallen,
			      &actuallen);
	}
#ifndef LINUX
	free(oses);
#endif

	/* build packet header */
	osfield.type = OS_FIELD;
	osfield.option = OS_SRV;
	osfield.length = sizeof(osfield) + actuallen;

	/* add packet body */
#ifdef LINUX
	buf = alloca(osfield.length);
#else
	buf = calloc(osfield.length, sizeof(char));
#endif
	osfield_length = osfield.length;
	osfield.length = htons(osfield.length);
	pointer = buf;
	memcpy(buf, &osfield, sizeof osfield);
	pointer += sizeof osfield;
	memcpy(pointer, enc_oses, actuallen);
	free(enc_oses);

	/* Send OS field over network */
	ret = gnutls_record_send(session->tls, buf, osfield_length);
	if (ret < 0) {
		if (session->verbose)
			printf("Error sending tls data: %s",
			       gnutls_strerror(ret));
		SET_ERROR(err, GNUTLS_ERROR, ret);
		return 0;
	}

	/* wait for message of server about mode */
	ret = gnutls_record_recv(session->tls, buf, osfield_length);
	if (ret <= 0) {
		errno = EACCES;
		SET_ERROR(err, GNUTLS_ERROR, ret);
#ifndef LINUX
		free(buf);
#endif
		return 0;
	}
#ifndef LINUX
	free(buf);
#endif

	if (buf[0] == SRV_TYPE) {
		session->server_mode = buf[1];
	} else {
		session->server_mode = SRV_TYPE_POLL;
	}
	return 1;
}

void nu_client_set_username(nuauth_session_t *session,
			    const char *username)
{
	char *utf8username = nu_client_to_utf8(username, nu_locale_charset);
	session->username = secure_str_copy(utf8username);
	free(utf8username);
}

void nu_client_set_password(nuauth_session_t *session,
				    const char *password)
{
	char *utf8pass = nu_client_to_utf8(password, nu_locale_charset);
	session->password = secure_str_copy(utf8pass);
	free(utf8pass);
}

	void nu_client_set_debug(nuauth_session_t * session, unsigned char enabled);

/**
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
	char *home = getenv("HOME");
	int ok;
	int ret;

	session->tls_password = tls_password;

	/* compute patch keyfile */
	if (keyfile == NULL && home != NULL) {
		ok = secure_snprintf(keystring, sizeof(keystring),
				     "%s/.nufw/key.pem", home);
		if (ok)
			keyfile = keystring;
	}

	/* test if key file exists */
	if (keyfile != NULL && access(keyfile, R_OK) != 0) {
		keyfile = NULL;
#if REQUEST_CERT
		SET_ERROR(err, INTERNAL_ERROR, FILE_ACCESS_ERR);
		errno = EBADF;
		return 0;
#endif
	}

	if (certfile == NULL && home != NULL) {
		ok = secure_snprintf(certstring, sizeof(certstring),
				     "%s/.nufw/cert.pem", home);
		if (ok)
			certfile = certstring;
	}
	/* test if cert exists */
	if (certfile != NULL && access(certfile, R_OK) != 0) {
		certfile = NULL;
#if REQUEST_CERT
		SET_ERROR(err, INTERNAL_ERROR, FILE_ACCESS_ERR);
		errno = EBADF;
		return 0;
#endif
	}
	if (cafile == NULL && home != NULL) {
		ok = secure_snprintf(castring, sizeof(castring),
				     "%s/.nufw/cacert.pem", home);
		if (ok)
			cafile = castring;
	}
	/* test if cert exists */
	if (cafile != NULL && access(cafile, R_OK) != 0) {
		cafile = NULL;
#if REQUEST_CERT
		SET_ERROR(err, INTERNAL_ERROR, FILE_ACCESS_ERR);
		errno = EBADF;
		return 0;
#endif
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
			return 0;
		}
	}

	/* put the x509 credentials to the current session */
	ret =
	    gnutls_credentials_set(session->tls, GNUTLS_CRD_CERTIFICATE,
				   session->cred);
	if (ret < 0) {
		SET_ERROR(err, GNUTLS_ERROR, ret);
		return 0;
	}
	session->need_set_cred = 0;
	return 1;
}

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
 * Initialize SASL: create an client, set properties
 * and then call mysasl_negotiate()
 *
 * \param session Pointer to client session
 * \param err Pointer to a nuclient_error_t: which contains the error
 */
int init_sasl(nuauth_session_t * session, nuclient_error_t * err)
{
	int ret;
	sasl_conn_t *conn;
	sasl_ssf_t extssf = 0;

	/* SASL time */
	sasl_callback_t callbacks[] = {
		{SASL_CB_USER, &nu_get_userdatas, session},
		{SASL_CB_AUTHNAME, &nu_get_userdatas, session},
		{SASL_CB_PASS, &nu_get_usersecret, session},
		{SASL_CB_LIST_END, NULL, NULL}
	};

	/*
	 * gnutls_record_send(session->tls,PROTO_STRING " " PROTO_VERSION,
	 strlen(PROTO_STRING " " PROTO_VERSION));
	 */

	ret =
	    gnutls_record_send(session->tls, "PROTO 4", strlen("PROTO 4"));
	if (ret < 0) {
		SET_ERROR(err, GNUTLS_ERROR, ret);
		return 0;
	}

	/* set external properties here
	   sasl_setprop(conn, SASL_SSF_EXTERNAL, &extprops); */
	/* set username taken from console */

	/* client new connection */
	ret =
	    sasl_client_new("nuauth", "", NULL, NULL, callbacks, 0, &conn);
	if (ret != SASL_OK) {
		if (session->verbose)
			printf("Failed allocating connection state");
		errno = EAGAIN;
		SET_ERROR(err, SASL_ERROR, ret);
		return 0;
	}

	if (! session->username){
		if (session->username_callback){
			session->username = session->username_callback();
		} else {
			if (session->verbose)
				printf("Can't call username callback\n");
		}
	}

	sasl_setprop(conn, SASL_SSF_EXTERNAL, &extssf);
	ret = sasl_setprop(conn, SASL_AUTH_EXTERNAL, session->username);
	if (ret != SASL_OK) {
		errno = EACCES;
		SET_ERROR(err, SASL_ERROR, ret);
		return 0;
	}


	/* set required security properties here
	   sasl_setprop(conn, SASL_SEC_PROPS, &secprops); */

	ret = mysasl_negotiate(session, conn, err);
	if (ret != SASL_OK) {
		errno = EACCES;
		/*        SET_ERROR(err, SASL_ERROR, ret); */
		return 0;
	}
	sasl_dispose(&conn);

	return 1;
}

void nu_client_set_source(nuauth_session_t *session, struct sockaddr_storage *addr)
{
	session->has_src_addr = 1;
	session->src_addr = *addr;
}

/**
 * Create a socket to nuauth, and try to connect. The function also set
 * SIGPIPE handler: ignore these signals.
 *
 * \param session Pointer to client session
 * \param hostname String containing hostname of nuauth server (default: #NUAUTH_IP)
 * \param service Port number (or string) on which nuauth server is listening (default: #USERPCKT_SERVICE)
 * \param err Pointer to a nuclient_error_t: which contains the error
 */
int init_socket(nuauth_session_t * session,
		const char *hostname, const char *service,
		nuclient_error_t *err)
{
	int option_value;
	struct sigaction no_action;
	int ecode;
	struct addrinfo *res;
	struct addrinfo hints = {
		0,
		PF_UNSPEC,
		SOCK_STREAM,
		0,
		0,
		NULL,
		NULL,
		NULL
	};

	/* get address informations */
	ecode = getaddrinfo(hostname, service, &hints, &res);
	if (ecode != 0) {
		if (session->verbose) {
			fprintf(stderr,
				"Fail to create host address: %s\n",
				gai_strerror(ecode));
			fprintf(stderr, "(host=\"%s\", service=\"%s\")\n",
				hostname, service);
		}
		SET_ERROR(err, INTERNAL_ERROR, DNS_RESOLUTION_ERR);
		return 0;
	}
	if (session->has_src_addr && session->src_addr.ss_family != res->ai_family)
	{
		struct sockaddr_in *src4 = (struct sockaddr_in *)&session->src_addr;
		struct sockaddr_in6 *src6 = (struct sockaddr_in6 *)&session->src_addr;
		if (res->ai_family == AF_INET
		    && session->src_addr.ss_family == AF_INET6
		    && memcmp(&src6->sin6_addr, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12) == 0)
		{
			struct in_addr addr;
			addr.s_addr = src6->sin6_addr.s6_addr32[3];
			src4->sin_family = AF_INET;
			src4->sin_addr = addr;
		} else if (res->ai_family == AF_INET6 && session->src_addr.ss_family == AF_INET) {
			struct in_addr addr;
			addr.s_addr = src4->sin_addr.s_addr;
			src6->sin6_addr.s6_addr32[0] = 0;
			src6->sin6_addr.s6_addr32[0] = 0;
			src6->sin6_addr.s6_addr32[2] = 0xffff0000;
			src6->sin6_addr.s6_addr32[3] = addr.s_addr;
		} else {
			if (session->verbose) {
				fprintf(stderr,
						"Unable to set source address: host (%s) is not IPv6!",
						hostname);
			}
			SET_ERROR(err, INTERNAL_ERROR, BINDING_ERR);
			return 0;
		}
	}

	/* ignore SIGPIPE */
	no_action.sa_handler = SIG_IGN;
	sigemptyset(&(no_action.sa_mask));
	no_action.sa_flags = 0;
	(void) sigaction(SIGPIPE, &no_action, NULL);

	/* create socket to nuauth */
	session->socket =
	    socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (session->socket <= 0) {
		errno = EADDRNOTAVAIL;
		freeaddrinfo(res);
		SET_ERROR(err, INTERNAL_ERROR, CANT_CONNECT_ERR);
		return 0;
	}
	option_value = 1;
	setsockopt(session->socket,
		   SOL_SOCKET,
		   SO_KEEPALIVE, &option_value, sizeof(option_value));

	if (session->has_src_addr)
	{
		int result = bind(session->socket,
				  (struct sockaddr*)&session->src_addr, sizeof(session->src_addr));
		if (result != 0)
		{
			SET_ERROR(err, INTERNAL_ERROR, BINDING_ERR);
			return 0;
		}
	}

	/* connect to nuauth */
	if (connect(session->socket, res->ai_addr, res->ai_addrlen) == -1) {
		errno = ENOTCONN;
		SET_ERROR(err, INTERNAL_ERROR, CANT_CONNECT_ERR);
		freeaddrinfo(res);
		return 0;
	}
	freeaddrinfo(res);
	return 1;
}

int get_first_x509_cert_from_tls_session(gnutls_session session,
					  gnutls_x509_crt * cert)
{
	const gnutls_datum *cert_list;
	unsigned int cert_list_size = 0;

	if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509)
		return SASL_BADPARAM;

	cert_list = gnutls_certificate_get_peers(session, &cert_list_size);

	if (cert_list_size > 0) {
		/* we only print information about the first certificate. */
		gnutls_x509_crt_init(cert);
		gnutls_x509_crt_import(*cert, &cert_list[0],
				       GNUTLS_X509_FMT_DER);
	} else {
		return SASL_BADPARAM;
	}
	return SASL_OK;
}


int certificate_check(nuauth_session_t *session)
{
	time_t expiration_time, activation_time;
	gnutls_x509_crt cert;

	if (get_first_x509_cert_from_tls_session(session->tls, &cert)
			!= SASL_OK) {
		return SASL_BADPARAM;
	}

	expiration_time = gnutls_x509_crt_get_expiration_time(cert);
	activation_time = gnutls_x509_crt_get_activation_time(cert);

	/* verify date */
	if (expiration_time < time(NULL)) {
		gnutls_x509_crt_deinit(cert);
		return SASL_EXPIRED;
	}

	if (activation_time > time(NULL)) {
		gnutls_x509_crt_deinit(cert);
		return SASL_DISABLED;
	}

	if (session->nuauth_cert_dn) {
		size_t size;
		char dn[512];
		size = sizeof(dn);
		gnutls_x509_crt_get_dn(cert, dn, &size);
		if (session->verbose) {
			printf("Certificate DN is: %s\n",dn);
		}
		if (strcmp(dn, session->nuauth_cert_dn)) {
			gnutls_x509_crt_deinit(cert);
			return SASL_DISABLED;
		}
	}

	return SASL_OK;
}

/**
 * Do the TLS handshake and check server certificate
 */
int tls_handshake(nuauth_session_t * session, nuclient_error_t * err)
{
	int ret;
	unsigned int status;

	gnutls_transport_set_ptr(session->tls,
				 (gnutls_transport_ptr) session->socket);

	/* Perform the TLS handshake */
	ret = 0;
	do {
		ret = gnutls_handshake(session->tls);
	} while (ret < 0 && !gnutls_error_is_fatal(ret));

	if (ret < 0) {
		gnutls_perror(ret);
		errno = ECONNRESET;
		SET_ERROR(err, GNUTLS_ERROR, ret);
		return 0;
	}

	/* certificate verification */
	if ( session->need_ca_verif )
	{
		ret = gnutls_certificate_verify_peers2(session->tls, &status);
		if (ret < 0) {
			if (session->verbose) {
				printf("Certificate authority verification failed: %s\n",
				       gnutls_strerror(ret));
			}
			SET_ERROR(err, GNUTLS_ERROR, ret);
			return 0;
		}
		if (status != 0) {
			if (session->verbose) {
				printf("Certificate authority verification failed: ");
				if( status & GNUTLS_CERT_INVALID )
					printf("CERT_INVALID ");
				if( status & GNUTLS_CERT_REVOKED )
					printf("CERT_REVOKED ");
				if( status & GNUTLS_CERT_SIGNER_NOT_FOUND )
					printf("CERT_SIGNER_NOT_FOUND ");
				if( status & GNUTLS_CERT_SIGNER_NOT_CA )
					printf("CERT_SIGNER_NOT_CA ");
				printf("\n");
			}
			SET_ERROR(err, GNUTLS_ERROR, ret);
			return 0;
		}
	}

	ret = certificate_check(session);
	if (ret != SASL_OK) {
		if (session->verbose) {
			printf("Certificate check  failed: %s\n",
			       gnutls_strerror(ret));
		}
		SET_ERROR(err, GNUTLS_ERROR, ret);
		return 0;
	}

	if (session->verbose)
		printf("Server Certificate OK\n");
	return 1;
}

/**
 * Make a copy in a string in a secure memory buffer, ie. buffer never moved
 * to swap (hard drive). Use secure_str_free() to free the memory when you
 * don't need the string anymore.
 *
 * If USE_GCRYPT_MALLOC_SECURE compilation option in not set,
 * strdup() is used.
 *
 * \return Copy of the string, or NULL on error.
 */
static char *secure_str_copy(const char *orig)
{
#ifdef USE_GCRYPT_MALLOC_SECURE
	size_t len = strlen(orig);
	char *new = gcry_calloc_secure(len + 1, sizeof(char));
	if (new != NULL) {
		SECURE_STRNCPY(new, orig, len + 1);
	}
	return new;
#else
	return strdup(orig);
#endif
}

int nu_client_reset_tls(nuauth_session_t *session)
{
	int ret;
	session->need_set_cred = 1;

	/* Initialize TLS session */
	ret = gnutls_init(&session->tls, GNUTLS_CLIENT);
	if (ret != 0) {
		return 0;
	}

	ret = gnutls_set_default_priority(session->tls);
	if (ret < 0) {
		return 0;
	}

	ret =
	    gnutls_certificate_type_set_priority(session->tls,
						 cert_type_priority);
	if (ret < 0) {
		return 0;
	}
	return 1;
}
/**
 * \ingroup nuclientAPI
 * \brief Init connection to nuauth server
 *
 * \param diffie_hellman If equals to 1, use Diffie Hellman for key exchange
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
nuauth_session_t *_nu_client_new(unsigned char diffie_hellman, nuclient_error_t * err)
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
	session->diffie_hellman = diffie_hellman;
	session->count_msg_cond = -1;
	session->auth_by_default = 1;
	session->packet_seq = 0;
	session->checkthread = NULL_THREAD;
	session->recvthread = NULL_THREAD;
	session->tls = NULL;
	session->ct = NULL;
	session->tls_password = NULL;
	session->debug_mode = 0;
	session->verbose = 1;
	session->timestamp_last_sent = time(NULL);
	session->need_set_cred = 1;
	session->need_ca_verif = 0;

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

	/* X509 stuff */
	ret = gnutls_certificate_allocate_credentials(&(session->cred));
	if (ret != 0) {
		SET_ERROR(err, GNUTLS_ERROR, ret);
		nu_exit_clean(session);
		return NULL;
	}

	if (session->diffie_hellman) {
		/* allocate diffie hellman parameters */
		ret = gnutls_dh_params_init(&session->dh_params);
		if (ret < 0) {
			SET_ERROR(err, GNUTLS_ERROR, ret);
			nu_exit_clean(session);
			return NULL;
		}

		/* Generate Diffie Hellman parameters - for use with DHE
		 * kx algorithms. These should be discarded and regenerated
		 * once a day, once a week or once a month. Depending on the
		 * security requirements.
		 */
		ret =
		    gnutls_dh_params_generate2(session->dh_params,
					       DH_BITS);
		if (ret < 0) {
			SET_ERROR(err, GNUTLS_ERROR, ret);
			nu_exit_clean(session);
			return NULL;
		}

		gnutls_certificate_set_dh_params(session->cred,
						 session->dh_params);
	}

	if (!nu_client_reset_tls(session))
	{
		SET_ERROR(err, GNUTLS_ERROR, ret);
		nu_exit_clean(session);
	}
	return session;
}

/**
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

	session = _nu_client_new(diffie_hellman, err);

	session->username_callback = username_callback;
	session->passwd_callback = passwd_callback;

	return session;
}

/**
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

	session = _nu_client_new(diffie_hellman, err);

	session->username = secure_str_copy(username);
	session->password = secure_str_copy(password);
	if (session->username == NULL || session->password == NULL) {
		SET_ERROR(err, INTERNAL_ERROR, MEMORY_ERR);
		return NULL;
	}

	return session;
}



/**
 * Reset a session: close the connection and reset attributes. So the session
 * can be used as nu_client_connect() input.
 */
void nu_client_reset(nuauth_session_t * session)
{
	/* close TLS conneciton */
	ask_session_end(session);

	/* delete old TLS session and create a new TLS session */
	gnutls_deinit(session->tls);
	gnutls_init(&session->tls, GNUTLS_CLIENT);
	gnutls_set_default_priority(session->tls);
	gnutls_certificate_type_set_priority(session->tls,
					     cert_type_priority);
	session->need_set_cred = 1;

	/* close socket */
	if (session->socket > 0) {
		shutdown(session->socket, SHUT_WR);
		close(session->socket);
	}

	/* reset fields */
	session->connected = 0;
	session->count_msg_cond = -1;
	session->timestamp_last_sent = time(NULL);
	session->socket = -1;
	session->checkthread = 0;
	session->recvthread = 0;
}

/**
 * Try to connect to nuauth server:
 *    - init_socket(): create socket to server ;
 *    - tls_handshake(): TLS handshake ;
 *    - init_sasl(): authentification with SASL ;
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
 * Enable or disabled verbose mode
 *
 * \param session Pointer to client session
 * \param enabled Enable verbose mode if different than zero (1), disable otherwise
 */
void nu_client_set_verbose(nuauth_session_t * session, unsigned char enabled)
{
	session->verbose = enabled;
}

void ask_session_end(nuauth_session_t * session)
{
	pthread_t self_thread = pthread_self();
	/* we kill thread thus lock will be lost if another thread reach this point */

	/* sanity checks */
	if (session == NULL) {
		return;
	}
	if (session->connected == 0) {
		return;
	}

	pthread_mutex_lock(&(session->mutex));
	session->connected = 0;
	gnutls_bye(session->tls, GNUTLS_SHUT_WR);
	if (session->recvthread != NULL_THREAD
	    && !pthread_equal(session->recvthread, self_thread)) {
		/* destroy thread */
		pthread_cancel(session->recvthread);
		pthread_join(session->recvthread, NULL);
	}
	if (session->server_mode == SRV_TYPE_PUSH) {
		if (session->checkthread != NULL_THREAD
		    && !pthread_equal(session->checkthread, self_thread)) {
			pthread_cancel(session->checkthread);
			pthread_join(session->checkthread, NULL);
		}
	}
	pthread_mutex_unlock(&(session->mutex));
	if (pthread_equal(session->recvthread, self_thread) ||
	    ((session->server_mode == SRV_TYPE_PUSH)
	     && pthread_equal(session->checkthread, self_thread))
	    ) {
		pthread_exit(NULL);
	}
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
	case GNUTLS_ERROR:
		return gnutls_strerror(err->error);
		break;
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
 * Get version of nuclient library (eg. "2.1.1-3")
 *
 * \return Nuclient version string
 */
const char *nu_get_version()
{
	return NUCLIENT_VERSION;
}

/**
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

/**
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


/** @} */

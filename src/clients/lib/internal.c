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

#include "nufw_source.h"
#include "nuclient.h"
#include <sasl/saslutil.h>
#include <stdarg.h>		/* va_list, va_start, ... */
#include <gnutls/x509.h>
#include <langinfo.h>
#include <proto.h>
#include "client.h"
#include "security.h"
#include "internal.h"
#include <sys/utsname.h>


/**
 * \ingroup libnuclient
 * @{
 */

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
						     bucket) == -1) {
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

/**
 * SASL callback used to get password
 *
 * \return SASL_OK if ok, EXIT_FAILURE on error
 */
static int nu_get_usersecret(sasl_conn_t * conn __attribute__ ((unused)),
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

	ret =
	    gnutls_record_send(session->tls, "PROTO 4", strlen("PROTO 4"));
	if (ret < 0) {
		SET_ERROR(err, GNUTLS_ERROR, ret);
		return 0;
	}

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
		/* set username taken from console */
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


	ret = mysasl_negotiate(session, conn, err);
	if (ret != SASL_OK) {
		errno = EACCES;
		/*        SET_ERROR(err, SASL_ERROR, ret); */
		return 0;
	}
	sasl_dispose(&conn);

	return 1;
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
		if (status) {
			if (session->verbose) {
				printf("Certificate authority verification failed:");
				if( status & GNUTLS_CERT_INVALID )
					printf(" invalid");
				if( status & GNUTLS_CERT_REVOKED )
					printf(", revoked");
				if( status & GNUTLS_CERT_SIGNER_NOT_FOUND )
					printf(", signer not found");
				if( status & GNUTLS_CERT_SIGNER_NOT_CA )
					printf(", signer not a CA");
				printf("\n");
			}
			SET_ERROR(err, GNUTLS_ERROR, GNUTLS_E_CERTIFICATE_ERROR);
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
char *secure_str_copy(const char *orig)
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


/** @} */

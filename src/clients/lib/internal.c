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
#include "libnuclient.h"
#include "sending.h"
#include "tcptable.h"
#include <sasl/saslutil.h>
#include <stdarg.h>		/* va_list, va_start, ... */
#include <langinfo.h>
#include <proto.h>
#include "security.h"
#include "internal.h"
#include <sys/utsname.h>

#include <nussl.h>
#include <nubase.h>

char* nu_locale_charset;

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


static int samp_send(nuauth_session_t* session, const char *buffer,
		     unsigned length, nuclient_error_t * err)
{
	char *buf;
	unsigned len, alloclen;
	int result;

	/* prefix ("C: ") + base64 length + 1 nul byte */
	alloclen = 3 + ((length+2)/3)*4 + 1;
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

	result = nussl_write(session->nussl, buf, len + 3);
	if (result < 0) {
		SET_ERROR(err, NUSSL_ERR, result);
		return 0;
	}

	return 1;
}


/* XXX: Move this fuction into nussl */
static unsigned samp_recv(nuauth_session_t* session, char *buf, int bufsize,
			  nuclient_error_t * err)
{
	unsigned len;
	int result;
	int tls_len;

	tls_len = nussl_read(session->nussl, buf, bufsize);
	if (tls_len <= 0) {
		SET_ERROR(err, NUSSL_ERR, tls_len);
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



int mysasl_negotiate(nuauth_session_t * session, sasl_conn_t * conn,
		     nuclient_error_t * err)
{
	char buf[8192];
	const char *data;
	const char *chosenmech;
	unsigned len;
	int result;
	/* gnutls_session session = session->tls; */

	memset(buf, 0, sizeof buf);
	/* get the capability list */
	len = samp_recv(session, buf, 8192, err);
	if (len == 0) {
		return SASL_FAIL;
	}

	result = sasl_client_start(conn,
				   buf, NULL, &data, &len, &chosenmech);

	if (session->verbose) {
		printf("Using mechanism %s\n", chosenmech);
	}

	if (result != SASL_OK && result != SASL_CONTINUE) {
		if (session->verbose) {
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
		if (session->verbose) {
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
			if (session->verbose)
				printf("Performing SASL negotiation\n");
			SET_ERROR(err, SASL_ERROR, result);
		}
		if (data && len) {
			if (session->verbose)
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

	len = samp_recv(session, buf, 42, err);
	if (buf[0] != 'Y') {
		result = SASL_BADAUTH;
		SET_ERROR(err, SASL_ERROR, SASL_BADAUTH);
	}

	if (result != SASL_OK) {
		if (session->verbose)
			puts("Authentication failed...");
		return SASL_FAIL;
	} else {
		if (session->verbose)
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
	ret = nussl_write(session->nussl, buf, osfield_length);
	if (ret < 0) {
		if (session->verbose)
			printf("Error sending tls data: ...");
		SET_ERROR(err, NUSSL_ERR, ret);
		return 0;
	}

	/* wait for message of server about mode */
	ret = nussl_read(session->nussl, buf, osfield_length);
	if (ret <= 0) {
		errno = EACCES;
		SET_ERROR(err, NUSSL_ERR, ret);
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

	ret = nussl_write(session->nussl, "PROTO 5", strlen("PROTO 5"));
	if (ret < 0) {
		SET_ERROR(err, NUSSL_ERR, ret);
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
	/* sanity checks */
	if (session == NULL) {
		return;
	}
	if(session->nussl) {
		nussl_session_destroy(session->nussl);
		session->nussl = NULL;
	}
}


/** @} */

/*
 ** Copyright(C) 2005-2009 INL
 **		 2010 EdenWall Technologies
 ** Written by Eric Leblond <regit@inl.fr>
 ** Modified by Pierre-Louis Bonicoli <bonicoli@edenwall.com>
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
 **
 ** In addition, as a special exception, the copyright holders give
 ** permission to link the code of portions of this program with the
 ** Cyrus SASL library under certain conditions as described in each
 ** individual source file, and distribute linked combinations
 ** including the two.
 ** You must obey the GNU General Public License in all respects
 ** for all of the code used other than Cyrus SASL.  If you modify
 ** file(s) with this exception, you may extend this exception to your
 ** version of the file(s), but you are not obligated to do so.  If you
 ** do not wish to do so, delete this exception statement from your
 ** version.  If you delete this exception statement from all source
 ** files in the program, then also delete it here.
 **
 ** This product includes software developed by Computing Services
 ** at Carnegie Mellon University (http://www.cmu.edu/computing/).
 **
 */


/**
 * \addtogroup TLSUser
 * @{
 */

/** \file sasl.c
 *  \brief Manage clients authentication.
 *
 * This file contains functions used for sasl negotiation. The more important of the is mysasl_negotiate().
 */



#include <auth_srv.h>
#include <sasl/saslutil.h>
#include <ev.h>
#include <fcntl.h>
#include "security.h"

#include <nubase.h>

gchar *mech_string_internal;
gchar *mech_string_external;


/* sasl init function */
void *sasl_gthread_mutex_init(void)
{
	GMutex *lock = g_mutex_new();
	if (!lock)
		return NULL;
	return lock;
}

int sasl_gthread_mutex_lock(void *lock)
{
	g_mutex_lock(lock);
	return 0;
}

int sasl_gthread_mutex_unlock(void *lock)
{
	g_mutex_unlock(lock);
	return 0;
}

void sasl_gthread_mutex_free(void *lock)
{
	g_mutex_free(lock);
}

/* where using private datas to avoid over allocating */
static int external_get_opt(void *context, const char *plugin_name,
			    const char *option,
			    const char **result, unsigned *len)
{
	if (!strcmp(option, "mech_list")) {
		*result = mech_string_external;
		return SASL_OK;
	}
	return SASL_FAIL;
}

static int internal_get_opt(void *context, const char *plugin_name,
			    const char *option,
			    const char **result, unsigned *len)
{
	if (!strcmp(option, "mech_list")) {
		*result = mech_string_internal;
		return SASL_OK;
	}
	return SASL_FAIL;
}

static int userdb_checkpass(sasl_conn_t * conn,
			    void *context,
			    const char *user,
			    const char *pass,
			    unsigned passlen, struct propctx *propctx)
{
	char *dec_user = NULL;
	int ret;

	/*
	 * call module to get password
	 *       and additional properties
	 */

	/* pass can not be null */
	if (pass == NULL || passlen == 0) {
		log_message(INFO, DEBUG_AREA_AUTH,
			    "Password sent by user %s is NULL", user);
		return SASL_BADAUTH;
	}

	/* convert username from utf-8 to locale */
	if (nuauthconf->uses_utf8) {
		size_t bwritten;
		dec_user = g_locale_from_utf8(user,
					      -1, NULL, &bwritten, NULL);
		if (!dec_user) {
			log_message(SERIOUS_WARNING, DEBUG_AREA_AUTH,
				    "Can not convert username at %s:%d",
				    __FILE__, __LINE__);

			/* return to fallback */
			sasl_seterror(conn, 0,
				      "Can not convert username to locale" );
			return SASL_NOUSER;
		}
	} else {
		dec_user = (char *) user;
	}


	ret = modules_user_check(dec_user, pass, passlen, (user_session_t *)context);
	if (ret == SASL_OK) {
		/* we're done */
		if (nuauthconf->uses_utf8)
			g_free(dec_user);
		return SASL_OK;
	}
	if (nuauthconf->uses_utf8)
		g_free(dec_user);
	/* return to fallback */
	log_message(INFO, DEBUG_AREA_AUTH, "Bad auth from user at %s:%d",
		    __FILE__, __LINE__);

	sasl_seterror(conn, 0, "Bad auth from user");
	return ret;
}


/**
 * called in tls_user_init()
 */
void my_sasl_init()
{
	int ret;

	sasl_set_mutex(sasl_gthread_mutex_init,
		       sasl_gthread_mutex_lock,
		       sasl_gthread_mutex_unlock, sasl_gthread_mutex_free);
	/* initialize SASL */
	ret = sasl_server_init(NULL, "nuauth");
	if (ret != SASL_OK) {
		log_message(CRITICAL, DEBUG_AREA_AUTH,
			    "Fail to init SASL library!");
		exit(EXIT_FAILURE);
	}

	mech_string_internal = g_strdup("plain");
	mech_string_external = g_strdup("external");

}

static int samp_send(nussl_session* nussl, const char *buffer,
		     unsigned length)
{
	char *buf;
	unsigned len, alloclen;
	int result;

	/* prefix ("S: ") + base64 length + 1 nul byte */
	alloclen = 3 + ((length+2)/3)*4 + 1;
	buf = g_new(char, alloclen);
	result = sasl_encode64(buffer, length, buf + 3, alloclen - 3, &len);
	if (result != SASL_OK) {
		g_free(buf);
		log_message(WARNING, DEBUG_AREA_AUTH, "Encoding data in base64 failed");
		return result;
	}
	memcpy(buf, "S: ", 3);

	result = nussl_write(nussl, buf, len + 3);
	if (result < 0)
		log_message(WARNING, DEBUG_AREA_AUTH, "nussl_write() failed: %s", nussl_get_error(nussl));

	g_free(buf);
	return result;
}

static unsigned samp_recv(nussl_session* nussl, sasl_conn_t * conn, char *buf,
			       int bufsize)
{
	unsigned int len;
	int result;

	result = nussl_read(nussl, buf, bufsize);
	if (result < 0) {
		log_message(WARNING, DEBUG_AREA_AUTH, "nussl_read() failed: %s", nussl_get_error(nussl));
		return 0;
	}
	len = (unsigned int)result;

	result = sasl_decode64(buf + 3, (unsigned) strlen(buf + 3), buf,
			       bufsize, &len);
	if (result != SASL_OK) {
		log_message(WARNING, DEBUG_AREA_AUTH, "Unable to decode base64 data: %s",
			    sasl_errdetail(conn));
		return 0;
	}
	buf[len] = '\0';
	return len;
}


#define MAX_TRY 2
nu_error_t negotiate_proto_version(user_session_t *c_session)
{
	int i = 0;
	int n = 0;

	while ((c_session->proto_version > PROTO_VERSION) && (i < MAX_TRY)) {
		char data[10];

		n = snprintf(data, 10, "%s %d", PROTO_STRING, PROTO_VERSION);
		if (n <= 0) {
			return NU_EXIT_ERROR;
		}
		n = nussl_write(c_session->nussl, data, strlen(data));
		if (n < 0) {
			return NU_EXIT_ERROR;
		}
		n = nussl_read(c_session->nussl, data, sizeof(data));
		if (n<0) {
			return NU_EXIT_ERROR;
		}
		if (((int) strlen(PROTO_STRING) + 2) <= n 
				&& strncmp(data, PROTO_STRING,
					strlen(PROTO_STRING)) ==
				0) {
			data[n] = 0;
			c_session->proto_version =
				atoi((char *) data +
						strlen(PROTO_STRING));
		} else {
			return NU_EXIT_ERROR;
		}
		i++;
	}
	if (c_session->proto_version <= PROTO_VERSION) {
		n = nussl_write(c_session->nussl, "OK", strlen("OK"));
		if (n < 0) {
			return NU_EXIT_ERROR;
		}
		return NU_EXIT_OK;
	} else {
		nussl_write(c_session->nussl, "NOK", strlen("NOK"));
		return NU_EXIT_ERROR;
	}
	return NU_EXIT_ERROR;
}

static void sock_activity_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	user_session_t * c_session = w->data;
	if (revents & EV_ERROR) {
		log_message(INFO, DEBUG_AREA_AUTH,
				"Error received when waiting protocol");
		ev_io_stop(loop, w);
		ev_unloop(loop, EVUNLOOP_ONE);
		c_session->proto_version = PROTO_VERSION_NONE;
		return;
	}
#if 0
	if (NUSSL_ISINTR(nussl_errno)) {
		log_message(CRITICAL, DEBUG_AREA_MAIN | DEBUG_AREA_AUTH,
				"Warning: tls user select() failed: signal was catched.");
		return;
	}
#endif
	if (revents & EV_WRITE) {
		log_message(VERBOSE_DEBUG, DEBUG_AREA_AUTH,
				"Write event when waiting protocol information");
	}
	if (revents & EV_READ) {
		char buffer[20];
		int ret;
		ev_io_stop(loop, w);
		ev_unloop(loop, EVUNLOOP_ONE);
		memset(buffer, 0, sizeof(buffer));

		log_message(VERBOSE_DEBUG, DEBUG_AREA_AUTH,
				"Getting protocol information");
		ret = nussl_read(c_session->nussl,
				buffer,
				sizeof(buffer) - 1);

		if (ret <= 0) {
			log_message(VERBOSE_DEBUG, DEBUG_AREA_AUTH,
					"nussl_read() failed: %s", nussl_get_error(c_session->nussl));
			c_session->proto_version = PROTO_VERSION_NONE;
			return;
		}
		if (((int) strlen(PROTO_STRING) + 2) <= ret
				&& strncmp(buffer, PROTO_STRING,
					strlen(PROTO_STRING)) ==
				0) {
			buffer[ret] = 0;
			c_session->proto_version =
				atoi((char *) buffer +
						strlen(PROTO_STRING));

			log_message(VERBOSE_DEBUG,
					DEBUG_AREA_AUTH,
					"Protocol information: %d",
					c_session->
					proto_version);
			if (c_session->proto_version >= PROTO_VERSION_V24) {
				int ret = negotiate_proto_version(c_session);
				if (ret != NU_EXIT_OK) {
					log_message(INFO, DEBUG_AREA_AUTH,
							"Unable to negotiate proto");
					c_session->proto_version = PROTO_VERSION_NONE;
				}
				return;
			}
			/* sanity check on know protocol */
			switch (c_session->proto_version) {
				case PROTO_VERSION_V22:
				case PROTO_VERSION_V22_1:
				case PROTO_VERSION_V24:
					break;
				default:
					log_message(INFO,
							DEBUG_AREA_AUTH,
							"Bad protocol, announced %d",
							c_session->proto_version
							);
					c_session->proto_version = PROTO_VERSION_NONE;
					return;
			}
			return;
		} else {
			log_message(INFO, DEBUG_AREA_AUTH,
					"Error bad proto string");
			c_session->proto_version = PROTO_VERSION_NONE;
			return;
		}
	}
}

static void sock_timeout_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	user_session_t *c_session = w->data;

	debug_log_message(DEBUG, DEBUG_AREA_AUTH,
			"Timeout when waiting protocol announce");
	if (c_session->proto_version != PROTO_VERSION_NONE) {
		return;
	}
	ev_io_stop(loop, w->data);
	ev_unloop(loop, EVUNLOOP_ONE);
	log_message(VERBOSE_DEBUG, DEBUG_AREA_AUTH,
					  "Falling back to v3 protocol");
	c_session->proto_version = PROTO_VERSION_V20;
}



/**
 *  fetch protocol version (or guess)
 *
 *  - start a select waiting for protocol announce from client
 *  - if there is nothing it is PROTO_V20 else get datas and fetch PROTO
 *
 * \param a ::user_session_t
 * \return a ::nu_error_t set to NU_EXIT_OK if there is no problem
 */

nu_error_t get_proto_info(user_session_t * c_session)
{
	struct ev_loop *loop;
	ev_io sock_watcher;
	ev_timer timer;

	c_session->proto_version = PROTO_VERSION_NONE;
	loop = ev_loop_new(0);
	ev_io_init(&sock_watcher, sock_activity_cb, c_session->socket, EV_READ);
	sock_watcher.data = c_session;
	ev_io_start(loop, &sock_watcher);
	ev_timer_init(&timer, sock_timeout_cb, 1.0 * nuauthconf->proto_wait_delay, 0.);
	timer.data = c_session;
	ev_timer_start(loop, &timer);

	ev_loop(loop, 0);

	ev_loop_destroy(loop);

	if (c_session->proto_version == PROTO_VERSION_NONE) {
		return NU_EXIT_ERROR;
	}
	return NU_EXIT_OK;
}


/**
 * do the sasl negotiation.
 *
 * \param c_session A ::user_session_t
 * \param conn A ::sasl_conn_t
 * \return -1 if it fails
 */
static int mysasl_negotiate(user_session_t * c_session, sasl_conn_t * conn)
{
	char buf[SASL_BUF_SIZE];
	const char *data = NULL;
	int tls_len = 0;
	unsigned sasl_len = 0;
	int count;
#if 0
	gnutls_session session = *(c_session->tls);
#endif
	ssize_t record_send;
	unsigned len = tls_len;
	int result, auth_result;
	result =
	    sasl_listmech(conn, NULL, NULL, ",", NULL, &data, &sasl_len,
			  &count);
	if (result != SASL_OK) {
		log_message(WARNING, DEBUG_AREA_AUTH,
			    "error generating mechanism list");
		return result;
	}
	log_message(VERBOSE_DEBUG, DEBUG_AREA_AUTH,
			  "%d mechanisms : %s (length: %d)", count, data,
			  sasl_len);
	fcntl(c_session->socket,F_SETFL,(fcntl(c_session->socket,F_GETFL)&~O_NONBLOCK));
	/* send capability list to client */
	record_send = samp_send(c_session->nussl, data, sasl_len);
	tls_len = sasl_len;
#if 0
	if ((record_send == GNUTLS_E_INTERRUPTED)
	    || (record_send == GNUTLS_E_AGAIN)) {
		debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_AUTH,
				  "sasl nego: need to resend packet");
		record_send = samp_send(c_session->nussl, data, tls_len);
	}
#endif
	if (record_send < 0) {
		return SASL_FAIL;
	}
	debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_AUTH,
			  "Now we know record_send >= 0");

	memset(buf, 0, sizeof(buf));
	tls_len = samp_recv(c_session->nussl, conn, buf, sizeof(buf));
	if (tls_len <= 0) {
		if (tls_len == 0) {
			log_message(INFO, DEBUG_AREA_AUTH,
				    "client didn't choose mechanism");
			if (samp_send(c_session->nussl, "N", 1) <= 0)	/* send NO to client */
				return SASL_FAIL;
			return SASL_BADPARAM;
		} else {
			log_message(INFO, DEBUG_AREA_AUTH,
				    "sasl nego : tls crash");
			return SASL_FAIL;
		}
	}
	log_message(VERBOSE_DEBUG, DEBUG_AREA_AUTH,
			  "client chose mechanism %s", buf);

	if (strlen(buf) < (size_t) tls_len) {
		/* Hmm, there's an initial response here */
		data = buf + strlen(buf) + 1;
		len = tls_len - strlen(buf) - 1;
	} else {
		data = NULL;
		len = 0;
	}
	auth_result = sasl_server_start(conn,
				   buf,
				   data, len, &data, (unsigned *) &len);

	if (auth_result != SASL_OK && auth_result != SASL_CONTINUE) {
		char *tempname = NULL;
		log_message(INFO, DEBUG_AREA_AUTH, "Error starting SASL negotiation: %s (%d)",
			  sasl_errdetail(conn),
			  auth_result);
		result =
		    sasl_getprop(conn, SASL_AUTHUSER,
				 (const void **) &(tempname));
		if (result != SASL_OK) {
			g_warning("get user failed: %s", sasl_errdetail(conn));
			return result;
		}
		if (tempname == NULL)
		{
			g_warning("sasl_getprop(SASL_AUTHUSER): username is NULL!");
			return SASL_BADPARAM;
		}
		c_session->user_name = g_strdup(tempname);
		return auth_result;
	}

	while (auth_result == SASL_CONTINUE) {
		if (data) {
			samp_send(c_session->nussl, data, len);
		} else {
			log_message(WARNING, DEBUG_AREA_AUTH,
				    "No data to send--something's wrong");
		}
		debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_AUTH,
				  "Waiting for client reply...");

		memset(buf, 0, sizeof(buf));
		len = samp_recv(c_session->nussl, conn, buf, sizeof(buf));
		data = NULL;
		auth_result = sasl_server_step(conn, buf, len, &data, &len);
	}

	if (auth_result != SASL_OK) {
		log_message(VERBOSE_DEBUG, DEBUG_AREA_AUTH,
				  "incorrect authentication");
		if (c_session->proto_version >= PROTO_VERSION_V22_1) {
			samp_send(c_session->nussl, "N", 1);
		}
	} else {
		log_message(VERBOSE_DEBUG, DEBUG_AREA_AUTH,
				  "correct authentication");
		if (c_session->proto_version >= PROTO_VERSION_V22_1) {
			samp_send(c_session->nussl, "Y", 1);
		}
	}

	if (c_session->user_name) {
		if (auth_result != SASL_OK) {
			return auth_result;
		}
	}

	if (c_session->auth_type != AUTH_TYPE_EXTERNAL) {
		char *tempname = NULL;
		result =
		    sasl_getprop(conn, SASL_AUTHUSER,
				 (const void **) &(tempname));
		if (result != SASL_OK) {
			g_warning("get user failed: %s", sasl_errdetail(conn));
			return result;
		}
		if (tempname == NULL)
		{
			g_warning("sasl_getprop(SASL_AUTHUSER): username is NULL!");
			return SASL_BADPARAM;
		}
		c_session->user_name = g_strdup(tempname);

		if (auth_result != SASL_OK) {
			return auth_result;
		}
		/* in case no call to user_checkdb has been done we need to fill the group */

		c_session->groups =
		    modules_get_user_groups(c_session->user_name);
		if (c_session->groups == NULL) {
			log_message(INFO, DEBUG_AREA_AUTH,
					  "error when searching user groups for %s",
					  c_session->user_name);
			return SASL_BADAUTH;
		}
		c_session->user_id =
		    modules_get_user_id(c_session->user_name);
		if (c_session->user_id == 0) {
			log_message(INFO, DEBUG_AREA_AUTH,
					"Couldn't get user ID for \"%s\"!",
					c_session->user_name);
			return SASL_BADAUTH;
		}
	}
#if 0
	if (nussl_write(c_session->nussl, "O", 1) < 0)	/* send YES to client */
		return SASL_FAIL;
#endif

	fcntl(c_session->socket,F_SETFL,(fcntl(c_session->socket,F_GETFL)|O_NONBLOCK));
	/* negotiation complete */
	return SASL_OK;
}

/**
 * do the sasl negotiation, protocol v3
 *
 * return -1 if it fails
 */
static int mysasl_negotiate_v3(user_session_t * c_session,
			       sasl_conn_t * conn)
{
	char buf[8192];
	char chosenmech[128];
	const char *data = NULL;
	int tls_len = 0;
	unsigned sasl_len = 0;
	int r = SASL_FAIL;
	int count;
	int ret = 0;
#if 0
	gnutls_session session = *(c_session->tls);
#endif
	ssize_t record_send;

	r = sasl_listmech(conn, NULL, "(", ",", ")", &data, &sasl_len,
			  &count);
	if (r != SASL_OK) {
		log_message(WARNING, DEBUG_AREA_AUTH,
			    "proto v3: generating mechanism list");
		return r;
	}
	log_message(VERBOSE_DEBUG, DEBUG_AREA_AUTH, "proto v3: %d mechanisms : %s",
			  count, data);
	tls_len = sasl_len;
	/* send capability list to client */
	record_send = nussl_write(c_session->nussl, (char*)data, tls_len);
#if 0
	if ((record_send == GNUTLS_E_INTERRUPTED)
	    || (record_send == GNUTLS_E_AGAIN)) {
		debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_AUTH,
				  "proto v3: sasl nego : need to resend packet");
		record_send = nussl_write(c_session->nussl, data, tls_len);
	}
#endif
	if (record_send < 0) {
		return SASL_FAIL;
	}
	debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_AUTH,
			  "proto v3: Now we know record_send >= 0");

	memset(chosenmech, 0, sizeof chosenmech);
	tls_len = nussl_read(c_session->nussl, chosenmech, sizeof chosenmech);
	if (tls_len <= 0) {
		if (tls_len == 0) {
			log_message(INFO, DEBUG_AREA_AUTH,
				    "proto v3: client didn't choose mechanism");
			if (nussl_write(c_session->nussl, "N", 1) < 0)	/* send NO to client */
				return SASL_FAIL;
			return SASL_BADPARAM;
		} else {
			log_message(INFO, DEBUG_AREA_AUTH,
				    "proto v3: sasl nego : tls crash");
			return SASL_FAIL;
		}
	}
	log_message(VERBOSE_DEBUG, DEBUG_AREA_AUTH,
			  "proto v3: client chose mechanism %s", chosenmech);

	memset(buf, 0, sizeof buf);
	tls_len = nussl_read(c_session->nussl, buf, sizeof(buf));
	if (tls_len != 1) {
		if (tls_len <= 0) {
			log_message(VERBOSE_DEBUG, DEBUG_AREA_AUTH,
					  "nussl_read() error: %s", nussl_get_error(c_session->nussl));
			return SASL_FAIL;
		}
		log_message(DEBUG, DEBUG_AREA_AUTH,
				  "proto v3: didn't receive first-sent parameter correctly");
		if (nussl_write(c_session->nussl, "N", 1) < 0)	/* send NO to client */
		{
			log_message(VERBOSE_DEBUG, DEBUG_AREA_AUTH,
					  "nussl_write() error: %s", nussl_get_error(c_session->nussl));
			return SASL_FAIL;
		}
		return SASL_BADPARAM;
	}

	if (buf[0] == 'Y') {
		/* receive initial response (if any) */


		memset(buf, 0, sizeof(buf));
		tls_len = nussl_read(c_session->nussl, buf, sizeof(buf));
		if (tls_len <= 0) {
			log_message(VERBOSE_DEBUG, DEBUG_AREA_AUTH,
					  "nussl_read() error: %s", nussl_get_error(c_session->nussl));
			return SASL_FAIL;
		}
		/* start libsasl negotiation */
		r = sasl_server_start(conn, chosenmech, buf, tls_len,
				      &data, &sasl_len);
	} else {
		log_message(DEBUG, DEBUG_AREA_AUTH, "proto v3: start with no msg");
		r = sasl_server_start(conn, chosenmech, NULL, 0, &data,
				      &sasl_len);
	}

	if (r != SASL_OK && r != SASL_CONTINUE) {
		gchar *user_name = NULL;

		log_message(INFO, DEBUG_AREA_AUTH, "proto v3: sasl negotiation error: %d",
			    r);
		ret =
		    sasl_getprop(conn, SASL_AUTHUSER,
				 (const void **) &(user_name));
		if (ret == SASL_OK) {
			c_session->user_name = g_strdup(user_name);
		} else {
			c_session->user_name = NULL;
		}

		if (nussl_write(c_session->nussl, "N", 1) < 0)	/* send NO to client */
		{
			log_message(VERBOSE_DEBUG, DEBUG_AREA_AUTH,
					  "nussl_read() error: %s", nussl_get_error(c_session->nussl));
			return SASL_FAIL;
		}
		return SASL_BADPARAM;
	}

	while (r == SASL_CONTINUE) {

		if (nussl_write(c_session->nussl, "C", 1) < 0)	/* send CONTINUE to client */
			return SASL_FAIL;

		if (data) {
			if (nussl_write(c_session->nussl, (char*)data, tls_len) < 0)
				return SASL_FAIL;
		} else {
			if (nussl_write(c_session->nussl, "", 0) < 0)
				return SASL_FAIL;
		}


		memset(buf, 0, sizeof buf);
		tls_len = nussl_read(c_session->nussl, buf, sizeof buf);
		if (tls_len < 0) {
#ifdef DEBUG_ENABLE
			if (!tls_len) {
				log_message(VERBOSE_DEBUG, DEBUG_AREA_USER | DEBUG_AREA_AUTH,
					    "proto v3: Client disconnected during sasl negotiation");
			} else {
				log_message(VERBOSE_DEBUG, DEBUG_AREA_USER | DEBUG_AREA_AUTH,
					    "proto v3: TLS error during sasl negotiation");
			}
#endif
			return SASL_FAIL;
		}

		r = sasl_server_step(conn, buf, tls_len, &data, &sasl_len);
		if (r != SASL_OK && r != SASL_CONTINUE) {
#ifdef DEBUG_ENABLE
			log_message(VERBOSE_DEBUG, DEBUG_AREA_AUTH,
				    "proto v3: error performing SASL negotiation: %s",
				    sasl_errdetail(conn));
#endif
			if (nussl_write(c_session->nussl, "N", 1) < 0)	/* send NO to client */
				return SASL_FAIL;
			return SASL_BADPARAM;
		}
	}			/* while continue */


	if (r != SASL_OK) {
		log_message(VERBOSE_DEBUG, DEBUG_AREA_AUTH,
				  "proto v3: incorrect authentication");
		/* try to get username */
		if (c_session->user_name == NULL) {
			char *tempname = NULL;
			ret =
				sasl_getprop(conn, SASL_AUTHUSER,
						(const void **) &(tempname));
			if (ret != SASL_OK) {
				g_warning("proto v3: get user failed");
				return ret;
			} else {
				c_session->user_name = g_strdup(tempname);
			}
		}
		if (nussl_write(c_session->nussl, "N", 1) < 0)	/* send NO to client */
			return SASL_FAIL;
		return SASL_BADAUTH;
	}


	if (c_session->user_name)
		c_session->auth_type = AUTH_TYPE_EXTERNAL;

	if (c_session->auth_type != AUTH_TYPE_EXTERNAL) {
		char *tempname = NULL;
		ret =
		    sasl_getprop(conn, SASL_AUTHUSER,
				 (const void **) &(tempname));
		if (ret != SASL_OK) {
			g_warning("proto v3: get user failed");
			return ret;
		} else {
			c_session->user_name = g_strdup(tempname);
		}

		/* in case no call to user_checkdb has been done we need to fill the group */

		c_session->groups =
		    modules_get_user_groups(c_session->user_name);
		if (c_session->groups == NULL) {
			log_message(DEBUG, DEBUG_AREA_USER | DEBUG_AREA_AUTH,
					  "proto v3: Couldn't get user groups");
			if (nussl_write(c_session->nussl, "N", 1) < 0)	/* send NO to client */
				return SASL_FAIL;
			return SASL_BADAUTH;
		}
		c_session->user_id =
		    modules_get_user_id(c_session->user_name);
		if (c_session->user_id == 0) {
			log_message(INFO, DEBUG_AREA_USER | DEBUG_AREA_AUTH,
				    "proto v3: Couldn't get user ID!");
		}
	}

	if (nussl_write(c_session->nussl, "O", 1) < 0)	/* send YES to client */
		return SASL_FAIL;

	/* negotiation complete */
	return SASL_OK;
}



/**
 * realize user negotiation from after TLS to the end.
 */

int sasl_user_check(user_session_t * c_session)
{
	sasl_conn_t *conn = NULL;
	sasl_security_properties_t secprops;
	char iplocalport[INET6_ADDRSTRLEN +20];
	char ipremoteport[INET6_ADDRSTRLEN +20];
	int len;
	int ret;
	sasl_callback_t internal_callbacks[] = {
		{SASL_CB_GETOPT, &internal_get_opt, c_session},
		{SASL_CB_SERVER_USERDB_CHECKPASS, &userdb_checkpass, c_session},
		{SASL_CB_LIST_END, NULL, NULL}
	};
	sasl_callback_t external_callbacks[] = {
		{SASL_CB_GETOPT, &external_get_opt, c_session},
		{SASL_CB_SERVER_USERDB_CHECKPASS, &userdb_checkpass, c_session},
		{SASL_CB_LIST_END, NULL, NULL}
	};
	sasl_callback_t real_sasl_callbacks[] = {
		{SASL_CB_SERVER_USERDB_CHECKPASS, &userdb_checkpass, c_session},
		{SASL_CB_LIST_END, NULL, NULL}
	};


	sasl_callback_t *callbacks;

	if (c_session->user_name) {
		c_session->auth_type = AUTH_TYPE_EXTERNAL;
		c_session->auth_quality = AUTHQ_SSL;
		callbacks = external_callbacks;
	} else {
		callbacks = internal_callbacks;
		c_session->auth_type = AUTH_TYPE_INTERNAL;
		c_session->auth_quality = AUTHQ_SASL;
		if (!nuauthconf->nuauth_uses_fake_sasl) {
			callbacks = real_sasl_callbacks;
		}
	}

	/* format "ip;port" */
	format_ipv6(&c_session->addr, ipremoteport, INET6_ADDRSTRLEN, NULL);
	len = strlen(ipremoteport);
	secure_snprintf(ipremoteport+len, sizeof(ipremoteport)-len,
		";%hu", c_session->sport);

	/* format "ip;port" */
	format_ipv6(&c_session->server_addr, iplocalport, INET6_ADDRSTRLEN, NULL);
	len = strlen(iplocalport);
	secure_snprintf(iplocalport+len, sizeof(iplocalport)-len,
		";%s", nuauthconf->userpckt_port);



	debug_log_message(VERBOSE_DEBUG, DEBUG_AREA_AUTH,
			  "Starting SASL server: service=%s, hostname=%s, realm=%s, iplocal=%s, ipremote=%s",
			  nuauthconf->krb5_service,
			  nuauthconf->krb5_hostname,
			  nuauthconf->krb5_realm,
			  iplocalport, ipremoteport
			 );
	ret = sasl_server_new(nuauthconf->krb5_service,
			nuauthconf->krb5_hostname,
			nuauthconf->krb5_realm,
			iplocalport, ipremoteport,
			callbacks, 0, &conn);
	if (ret != SASL_OK) {
		g_warning
		    ("allocating connection state - failure at sasl_server_new()");
		return ret;
	}

	secprops.min_ssf = 0;
	secprops.max_ssf = UINT_MAX;
	secprops.property_names = NULL;
	secprops.property_values = NULL;
	secprops.security_flags = SASL_SEC_NOANONYMOUS;	/* as appropriate */
	secprops.maxbufsize = 65536;
	sasl_setprop(conn, SASL_SEC_PROPS, &secprops);

	if (c_session->auth_type == AUTH_TYPE_EXTERNAL) {
		sasl_ssf_t extssf = 0;

#ifdef DEBUG_ENABLE
		log_message(VERBOSE_DEBUG, DEBUG_AREA_AUTH,
			    "setting params for external");
		log_message(VERBOSE_DEBUG, DEBUG_AREA_AUTH,
			    "TLS gives user %s, trying EXTERNAL",
			    c_session->user_name);
#endif
		ret =
		    sasl_setprop(conn, SASL_AUTH_EXTERNAL,
				 c_session->user_name);
		if (ret != SASL_OK) {
			sasl_dispose(&conn);
			log_message(INFO, DEBUG_AREA_AUTH,
				    "Error setting external auth");
			return ret;
		}
		ret = sasl_setprop(conn, SASL_SSF_EXTERNAL, &extssf);
		if (ret != SASL_OK) {
			sasl_dispose(&conn);
			log_message(INFO, DEBUG_AREA_AUTH,
				    "Error setting external SSF");
			return ret;
		}
	}

	ret = get_proto_info(c_session);
	if (ret != NU_EXIT_OK) {
		sasl_dispose(&conn);
		log_message(INFO, DEBUG_AREA_AUTH, "Could not fetch proto info");
		return SASL_BADPARAM;
	}

	switch (c_session->proto_version) {
	case PROTO_VERSION_V22:
	case PROTO_VERSION_V22_1:
	case PROTO_VERSION_V24:
		ret = mysasl_negotiate(c_session, conn);
		break;
	case PROTO_VERSION_V20:
		ret = mysasl_negotiate_v3(c_session, conn);
		break;
	default:
		log_message(WARNING, DEBUG_AREA_AUTH, "Unknown protocol");
		ret = SASL_BADPARAM;
	}

	sasl_dispose(&conn);

	if (ret != SASL_OK) {
		nuauth_auth_error_t err;
		const char *message;
		if (ret == SASL_BADAUTH || ret == SASL_NOUSER) {
			err = AUTH_ERROR_CREDENTIALS;
			message =
			    "Invalid credentials (username or password)";
		} else {
			err = AUTH_ERROR_INTERRUPTED;
			message =
			    "Authentication process interrupted";
		}
		modules_auth_error_log(c_session, err, message);
		return ret;
	}

	/* sasl connection is not used anymore */
	return SASL_OK;
}

/**
 * @}
 */

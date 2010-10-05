/*
 ** Copyright (C) 2007-2009 INL
 ** Written by S.Tricaud <stricaud@inl.fr>
 **            L.Defert <ldefert@inl.fr>
 **            Pierre Chifflier <chifflier@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** NuSSL: OpenSSL / GnuTLS layer based on libneon
 */


/*
   HTTP session handling
   Copyright (C) 1999-2007, Joe Orton <joe@manyfish.co.uk>
   Portions are:
   Copyright (C) 1999-2000 Tommi Komulainen <Tommi.Komulainen@iki.fi>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
   MA 02111-1307, USA

   In addition, as a special exception, INL
   gives permission to link the code of its release of NuSSL with the
   OpenSSL project's "OpenSSL" library (or with modified versions of it
   that use the same license as the "OpenSSL" library), and distribute
   the linked executables.  You must obey the GNU General Public License
   in all respects for all of the code used other than "OpenSSL".  If you
   modify this file, you may extend this exception to your version of the
   file, but you are not obligated to do so.  If you do not wish to do
   so, delete this exception statement from your version.
*/

/** \defgroup NuSSL NuSSL Library
 * \brief This is a library used in NuFW to be independant from a specific TLS/SLL implementation.
 *
 * @{
 */

/**
 * \file nussl_session.c
 * \brief nussl session handling
 */

#include <config.h>


#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>

#include "nussl_privssl.h"
#include "nussl_session.h"
#include "nussl_alloc.h"
#include "nussl_utils.h"
#include "nussl_internal.h"
#include "nussl_string.h"
#include "nussl_dates.h"
#include "nussl_socket.h"

#include "nussl_private.h"

#ifdef NUSSL_HAVE_TS_SSL
# include <pthread.h>
#endif

/* pre-declration list */
int nussl_session_get_fd(nussl_session * sess);

extern int nussl_ssl_set_ca_file(nussl_session *sess, const char *cafile);

#if 0
/* Destroy a a list of hooks. */
static void destroy_hooks(struct hook *hooks)
{
	struct hook *nexthk;

	while (hooks) {
		nexthk = hooks->next;
		nussl_free(hooks);
		hooks = nexthk;
	}
}
#endif

void nussl_session_destroy(nussl_session * sess)
{

	NUSSL_DEBUG(NUSSL_DBG_HTTP, "nussl_session_destroy called.\n");

	if (!sess)
		return;

	/* Close the connection; note that the notifier callback could
	 * still be invoked here. */
	nussl_close_connection(sess);

	nussl_free(sess->server.hostname);
	if (sess->server.address)
		nussl_addr_destroy(sess->server.address);

	if (sess->ssl_context)
		nussl_ssl_context_destroy(sess->ssl_context);

	if (sess->peer_cert)
		nussl_ssl_cert_free(sess->peer_cert);

	if (sess->my_cert)
		nussl_ssl_clicert_free(sess->my_cert);

	nussl_free(sess);

}

/* Stores the hostname/port in *sess, setting up the "hostport"
 * segment correctly. */
void nussl_set_hostinfo(nussl_session * sess, const char *hostname,
			unsigned int port)
{

	if (!sess)
		return;

	if (sess->server.hostname)
		nussl_free(sess->server.hostname);
	sess->server.hostname = nussl_strdup(hostname);
	sess->server.port = port;

}

/* Set list of allowed ciphers for TLS negotiation */
void nussl_session_set_ciphers(nussl_session * sess, const char *cipher_list)
{
	if (!sess)
		return;

	if (!sess->ssl_context)
		return;

	sess->ssl_context->ciphers = nussl_strdup(cipher_list);
}

nussl_session *nussl_session_create(int mode)
{

	nussl_session *sess = nussl_calloc(sizeof *sess);

/*    NUSSL_DEBUG(NUSSL_DBG_HTTP, "session to ://%s:%d begins.\n",
	     hostname, port); */

	if (!sess)
		return NULL;

	strcpy(sess->error, "Unknown error.");

	sess->ssl_context = nussl_ssl_context_create(mode);
	sess->flags[NUSSL_SESSFLAG_SSLv2] = 1;
	sess->flags[NUSSL_SESSFLAG_TLS_SNI] = 1;

	/* Set flags which default to on: */
	sess->flags[NUSSL_SESSFLAG_PERSIST] = 1;

	/* Set default read timeout */
	sess->rdtimeout = SOCKET_READ_TIMEOUT;

	/* check certificates by default */
	sess->check_peer_cert = 1;

	sess->mode = mode;

	return sess;
}

/* Server function */
nussl_session *nussl_session_create_with_fd(int server_fd, int verify)
{
	nussl_session *srv_sess;
	srv_sess = nussl_session_create(NUSSL_SSL_CTX_SERVER);
	if (!srv_sess) {
		return NULL;
	}

	srv_sess->socket = nussl_sock_create_with_fd(server_fd);
	/* verify: one of NUSSL_CERT_IGNORE, NUSSL_CERT_REQUEST or NUSSL_CERT_REQUIRE */
	srv_sess->ssl_context->verify = verify;

	return srv_sess;
}

/* Server function */
nussl_session *nussl_session_accept(nussl_session * srv_sess)
{
	nussl_session *client_sess;

	if (!srv_sess)
		return NULL;

	client_sess = nussl_session_create(NUSSL_SSL_CTX_SERVER);

	if (!client_sess) {
		nussl_set_error(srv_sess, _("Not enough memory"));
		return NULL;
	}

	if (srv_sess->ssl_context->verify)
		client_sess->check_peer_cert = 1;

	if (srv_sess->ssl_context->ciphers != NULL)
		nussl_session_set_ciphers(client_sess, srv_sess->ssl_context->ciphers);

	client_sess->socket = nussl_sock_create();

	/* TDOD: make nussl_sock_accept return a real error.. */
	if (nussl_sock_accept(client_sess->socket, nussl_sock_fd(srv_sess->socket)) != 0) {
		nussl_set_error(srv_sess,
				"Error during nussl_session_accept()\n");
		nussl_session_destroy(client_sess);
		return NULL;
	}

	return client_sess;
}

int nussl_session_handshake(nussl_session * client_sess, nussl_session * srv_sess)
{
	int fd;

	if (nussl_sock_accept_ssl(client_sess->socket, srv_sess->ssl_context)) {
		/* nussl_sock_accept_ssl already sets an error */
		nussl_set_error(srv_sess, "%s",
				nussl_sock_error(client_sess->socket));
		return -1;
	}
	// Post handshake needed to retrieve the peers certificate
	if (nussl__ssl_post_handshake(client_sess) != NUSSL_OK) {
		/* nussl__ssl_post_handshake already sets an error */
		nussl_set_error(srv_sess, "%s",
				nussl_get_error(client_sess));
		return -1;
	}

	if (client_sess->rdtimeout > 0) {
		// Set non-blocking mode
		NUSSL_DEBUG(NUSSL_DBG_SSL, "Setting non-blocking mode\n");
		fd = nussl_session_get_fd(client_sess);
		fcntl(fd,F_SETFL,(fcntl(fd,F_GETFL)|O_NONBLOCK));
	}

	return 0;
}

int nussl_session_get_fd(nussl_session * sess)
{
	if (!sess)
		return -1;

	return nussl_sock_fd(sess->socket);
}

int nussl_session_get_cipher(nussl_session * sess, char *buf, size_t bufsz)
{
	char *cipher = NULL;

	if (!sess)
		return -1;

	cipher = nussl_sock_cipher(sess->socket);
	if (!cipher)
		return -1;

	strncpy(buf, cipher, bufsz);
	nussl_free(cipher);

	return 0;
}

int nussl_session_set_dh_bits(nussl_session * sess, unsigned int dh_bits)
{
	if (!sess)
		return NUSSL_ERROR;

	return nussl_ssl_context_set_dh_bits(sess->ssl_context, dh_bits);
}

int nussl_session_set_dh_file(nussl_session * sess, const char *file)
{
	if (!sess)
		return NUSSL_ERROR;

	return nussl_ssl_context_set_dh_file(sess->ssl_context, file);
}

void nussl_set_addrlist(nussl_session * sess,
			const nussl_inet_addr ** addrs, size_t n)
{
	if (!sess)
		return;

	sess->addrlist = addrs;
	sess->numaddrs = n;

}

void nussl_set_error(nussl_session * sess, const char *format, ...)
{
	va_list params;

	if (!sess)
		return;

	va_start(params, format);
	nussl_vsnprintf(sess->error, sizeof sess->error, format, params);
	va_end(params);
}

void nussl_set_session_flag(nussl_session * sess, nussl_session_flag flag,
			    int value)
{
	if (!sess)
		return;

	if (flag < NUSSL_SESSFLAG_LAST) {
		sess->flags[flag] = value;
		if (flag == NUSSL_SESSFLAG_SSLv2 && sess->ssl_context) {
			nussl_ssl_context_set_flag(sess->ssl_context,
						   NUSSL_SSL_CTX_SSLv2,
						   value);
		}
	}
}

int nussl_get_session_flag(nussl_session * sess, nussl_session_flag flag)
{
	if (!sess)
		return -1;

	if (flag < NUSSL_SESSFLAG_LAST) {
		int sess_flag = sess->flags[flag];

		return sess_flag;
	}
	return -1;
}

/* static void progress_notifier(void *userdata, nussl_session_status status, */
/*                               const nussl_session_status_info *info) */
/* { */
/*     nussl_session *sess = userdata; */

/*     if (status == nussl_status_sending || status == nussl_status_recving) { */
/*         sess->progress_cb(sess->progress_ud, info->sr.progress, info->sr.total);     */
/*     } */
/* } */

/* void nussl_set_progress(nussl_session *sess, nussl_progress progress, void *userdata) */
/* { */
/*     sess->progress_cb = progress; */
/*     sess->progress_ud = userdata; */
/*     nussl_set_notifier(sess, progress_notifier, sess); */
/* } */

/* void nussl_set_notifier(nussl_session *sess, */
/* 		     nussl_notify_status status, void *userdata) */
/* { */
/*     sess->notify_cb = status; */
/*     sess->notify_ud = userdata; */
/* } */

void nussl_set_read_timeout(nussl_session * sess, int timeout)
{
	if (!sess)
		return;

	sess->rdtimeout = timeout;

	if (sess->socket)
		nussl_sock_read_timeout(sess->socket, timeout);

}

void nussl_set_connect_timeout(nussl_session * sess, int timeout)
{
	if (!sess)
		return;

	sess->cotimeout = timeout;

	if (sess->socket)
		nussl_sock_connect_timeout(sess->socket, timeout);

}

const char *nussl_get_error(nussl_session * sess)
{
	char *ret;

	if (!sess)
		return NULL;

	ret = nussl_strclean(sess->error);

	return ret;
}

void nussl_close_connection(nussl_session * sess)
{
	if (!sess)
		return;

	if (sess->socket) {
		NUSSL_DEBUG(NUSSL_DBG_SOCKET, "Closing connection.\n");
		nussl_sock_close(sess->socket);
		sess->socket = NULL;
		NUSSL_DEBUG(NUSSL_DBG_SOCKET, "Connection closed.\n");
	} else {
		NUSSL_DEBUG(NUSSL_DBG_SOCKET,
			    "(Not closing closed connection!).\n");
	}
}

void nussl_ssl_disable_certificate_check(nussl_session * sess, int is_disabled)
{
	if (!sess)
		return;

	sess->check_peer_cert = !is_disabled;
}

#if 0
void nussl_ssl_set_verify(nussl_session * sess, nussl_ssl_verify_fn fn,
			  void *userdata)
{

	sess->ssl_verify_fn = fn;
	sess->ssl_verify_ud = userdata;

}

void nussl_ssl_provide_clicert(nussl_session * sess,
			       nussl_ssl_provide_fn fn, void *userdata)
{

	sess->ssl_provide_fn = fn;
	sess->ssl_provide_ud = userdata;

}
#endif

int nussl_ssl_trust_cert_file(nussl_session * sess, const char *cert_file)
{
	int ret;

	if (!sess)
		return NUSSL_ERROR;

	ret = nussl_ssl_set_ca_file(sess, cert_file);

	if (ret == NUSSL_OK)
		sess->check_peer_cert = 1;


	return ret;
}

int nussl_ssl_trust_dir(nussl_session * sess, const char *dir)
{
	int ret;

	if (!sess)
		return NUSSL_ERROR;

	ret = nussl_ssl_context_trustdir(sess->ssl_context, dir);

	if (ret == NUSSL_OK)
		sess->check_peer_cert = 1;


	return ret;
}

void nussl_ssl_cert_validity(const nussl_ssl_certificate * cert,
			     char *from, char *until)
{
	time_t tf, tu;
	char *date;

	if (!cert)
		return;

	nussl_ssl_cert_validity_time(cert, &tf, &tu);

	if (from) {
		if (tf != (time_t) - 1) {
			date = nussl_rfc1123_date(tf);
			nussl_strnzcpy(from, date, NUSSL_SSL_VDATELEN);
			nussl_free(date);
		} else {
			nussl_strnzcpy(from, _("[invalid date]"),
				       NUSSL_SSL_VDATELEN);
		}
	}

	if (until) {
		if (tu != (time_t) - 1) {
			date = nussl_rfc1123_date(tu);
			nussl_strnzcpy(until, date, NUSSL_SSL_VDATELEN);
			nussl_free(date);
		} else {
			nussl_strnzcpy(until, _("[invalid date]"),
				       NUSSL_SSL_VDATELEN);
		}
	}

}

void nussl__ssl_set_verify_err(nussl_session * sess, int failures)
{
	static const struct {
		int bit;
		const char *str;
	} reasons[] = {
		{
		NUSSL_SSL_NOTYETVALID, N_("certificate is not yet valid")},
		{
		NUSSL_SSL_EXPIRED, N_("certificate has expired")}, {
		NUSSL_SSL_IDMISMATCH,
			    N_
			    ("certificate issued for a different hostname")},
		{
		NUSSL_SSL_UNTRUSTED, N_("issuer is not trusted")}, {
		NUSSL_SSL_INVALID,
			    N_("certificate is not a valid certificate")},
		{
		NUSSL_SSL_REVOKED, N_("certificate is revoked")}, {
		NUSSL_SSL_SIGNER_NOT_FOUND, N_("signer not found")}, {
		NUSSL_SSL_SIGNER_NOT_CA, N_("signer not a CA")}, {
		0, NULL}
	};
	int n, flag = 0;

	strcpy(sess->error, _("Peer certificate verification failed: "));

	for (n = 0; reasons[n].bit; n++) {
		if (failures & reasons[n].bit) {
			if (flag)
				strncat(sess->error, ", ",
					sizeof sess->error);
			strncat(sess->error, _(reasons[n].str),
				sizeof sess->error);
			flag = 1;
		}
	}
}

#if 0
typedef void (*void_fn) (void);

#define ADD_HOOK(hooks, fn, ud) add_hook(&(hooks), NULL, (void_fn)(fn), (ud))

static void add_hook(struct hook **hooks, const char *id, void_fn fn,
		     void *ud)
{
	struct hook *hk = nussl_malloc(sizeof(struct hook)), *pos;

	if (*hooks != NULL) {
		for (pos = *hooks; pos->next != NULL; pos = pos->next)
			/* nullop */ ;
		pos->next = hk;
	} else {
		*hooks = hk;
	}

	hk->id = id;
	hk->fn = fn;
	hk->userdata = ud;
	hk->next = NULL;
}
#endif

/* void nussl_hook_create_request(nussl_session *sess,  */
/* 			    nussl_create_request_fn fn, void *userdata) */
/* { */
/*     ADD_HOOK(sess->create_req_hooks, fn, userdata); */
/* } */

/* void nussl_hook_pre_send(nussl_session *sess, nussl_pre_send_fn fn, void *userdata) */
/* { */
/*     ADD_HOOK(sess->pre_send_hooks, fn, userdata); */
/* } */

/* void nussl_hook_post_send(nussl_session *sess, nussl_post_send_fn fn, void *userdata) */
/* { */
/*     ADD_HOOK(sess->post_send_hooks, fn, userdata); */
/* } */

/* void nussl_hook_post_headers(nussl_session *sess, nussl_post_headers_fn fn,  */
/*                           void *userdata) */
/* { */
/*     ADD_HOOK(sess->post_headers_hooks, fn, userdata); */
/* } */

/* void nussl_hook_destroy_request(nussl_session *sess, */
/* 			     nussl_destroy_req_fn fn, void *userdata) */
/* { */
/*     ADD_HOOK(sess->destroy_req_hooks, fn, userdata);     */
/* } */

/* void nussl_hook_destroy_session(nussl_session *sess, */
/* 			     nussl_destroy_sess_fn fn, void *userdata) */
/* { */
/*     ADD_HOOK(sess->destroy_sess_hooks, fn, userdata); */
/* } */

/*
static void remove_hook(struct hook **hooks, void_fn fn, void *ud)
{
    struct hook **p = hooks;

    while (*p) {
        if ((*p)->fn == fn && (*p)->userdata == ud) {
            struct hook *next = (*p)->next;
            nussl_free(*p);
            (*p) = next;
            break;
        }
        p = &(*p)->next;
    }
}

#define REMOVE_HOOK(hooks, fn, ud) remove_hook(&hooks, (void_fn)fn, ud)
*/
/* void nussl_unhook_create_request(nussl_session *sess,  */
/*                               nussl_create_request_fn fn, void *userdata) */
/* { */
/*     REMOVE_HOOK(sess->create_req_hooks, fn, userdata); */
/* } */

/* void nussl_unhook_pre_send(nussl_session *sess, nussl_pre_send_fn fn, void *userdata) */
/* { */
/*     REMOVE_HOOK(sess->pre_send_hooks, fn, userdata); */
/* } */

/* void nussl_unhook_post_headers(nussl_session *sess, nussl_post_headers_fn fn,  */
/* 			    void *userdata) */
/* { */
/*     REMOVE_HOOK(sess->post_headers_hooks, fn, userdata); */
/* } */

/* void nussl_unhook_post_send(nussl_session *sess, nussl_post_send_fn fn, void *userdata) */
/* { */
/*     REMOVE_HOOK(sess->post_send_hooks, fn, userdata); */
/* } */

/* void nussl_unhook_destroy_request(nussl_session *sess, */
/*                                nussl_destroy_req_fn fn, void *userdata) */
/* { */
/*     REMOVE_HOOK(sess->destroy_req_hooks, fn, userdata);     */
/* } */
/*
void nussl_unhook_destroy_session(nussl_session *sess,
                               nussl_destroy_sess_fn fn, void *userdata)
{
    REMOVE_HOOK(sess->destroy_sess_hooks, fn, userdata);
}
*/

int nussl_write(nussl_session * session, const char *buffer, size_t count)
{
	int ret;

	if (!session)
		return NUSSL_ERROR;

	ret = nussl_sock_fullwrite(session->socket, buffer, count);
	if (ret < 0)
		nussl_set_error(session, "%s",
				nussl_sock_error(session->socket));

	return ret;
}

ssize_t nussl_read_available(nussl_session * session)
{
	return nussl_sock_read_available(session->socket);
}

ssize_t nussl_read(nussl_session * session, char *buffer, size_t count)
{
	int ret;

	if (!session)
		return NUSSL_ERROR;

	ret = nussl_sock_read(session->socket, buffer, count);
	if (ret < 0)
		nussl_set_error(session, "%s",
				nussl_sock_error(session->socket));

	return ret;
}

int nussl_ssl_set_keypair(nussl_session * session, const char *cert_file,
			  const char *key_file)
{
	nussl_ssl_client_cert *cert;
	int ret;
	struct stat key_stat;

	if (!session)
		return NUSSL_ERROR;

	/* Try opening the keys */
	if (stat(key_file, &key_stat) != 0) {
		nussl_set_error(session,
				_("Unable to open private key %s: %s"),
				key_file, strerror(errno));
		return NUSSL_ERROR;
	}


	if (check_key_perms(key_file) != NUSSL_OK) {
		nussl_set_error(session,
				_("Permissions on private key %s are not restrictive enough, file should not be readable or writable by others."),
				key_file);
		return NUSSL_ERROR;
	}

	cert = nussl_ssl_import_keypair(cert_file, key_file);
	if (cert == NULL) {
		nussl_set_error(session,
				_
				("Unable to load private key or certificate file"));
		return NUSSL_ERROR;
	}

	ret = nussl_ssl_set_clicert(session, cert);
	return ret;
}

int nussl_ssl_set_pkcs12_keypair(nussl_session * session,
				 const char *pkcs12_file,
				 const char *password)
{
	struct stat key_stat;
	int ret = NUSSL_OK;
	nussl_ssl_client_cert *cert;

	if (!session)
		return NUSSL_ERROR;

	/* Try opening the keys */
	if (stat(pkcs12_file, &key_stat) != 0) {
		nussl_set_error(session,
				_("Unable to open private key %s: %s"),
				pkcs12_file, strerror(errno));
		return NUSSL_ERROR;
	}


	if (check_key_perms(pkcs12_file) != NUSSL_OK) {
		nussl_set_error(session,
				_("Permissions on private key %s are not restrictive enough, file should not be readable or writable by others."),
				pkcs12_file);
		return NUSSL_ERROR;
	}

	cert = nussl_ssl_clicert_read(pkcs12_file);

	if (cert == NULL) {
		nussl_set_error(session,
				_
				("Unable to load PKCS12 certificate file"));
		return NUSSL_ERROR;
	}

	if (nussl_ssl_clicert_encrypted(cert)) {
		if (password) {
			if (nussl_ssl_clicert_decrypt(cert, password) != 0) {
				nussl_set_error(session,
						_
						("Bad password to decrypt the PKCS key"));
				return NUSSL_ERROR;
			}
		} else {
			nussl_set_error(session,
					_
					("PKCS12 file is encrypted, please supply a password"));
			return NUSSL_ERROR;
		}
	} else {
		if (password)
			fprintf(stderr,
				"Warning, the key is not encrypted, but a password was supplied\n");
	}

	ret = nussl_ssl_set_clicert(session, cert);
	return ret;
}

int nussl_session_getpeer(nussl_session * sess, struct sockaddr *addr,
			  socklen_t * addrlen)
{
	int fd;
	int ret;

	if (!sess)
		return NUSSL_ERROR;

	fd = nussl_session_get_fd(sess);
	memset(addr, 0, *addrlen);
	ret = getpeername(fd, addr, addrlen);

	if (ret == -1) {
		nussl_set_error(sess, "%s", strerror(errno));
		return NUSSL_ERROR;
	}

	return NUSSL_OK;
}

void *nussl_get_socket(nussl_session * sess)
{
	if (!sess)
		return NULL;

	return nussl__sock_sslsock(sess->socket);
}

int nussl_init()
{
	return nussl_sock_init();
}

/** @} */

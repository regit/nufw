/*
 ** Copyright (C) 2007 INL
 ** Written by S.Tricaud <stricaud@inl.fr>
 **            L.Defert <ldefert@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** $Id$
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
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
   MA 02111-1307, USA

*/

#include <config.h>
#include <pthread.h>
#include "nussl_config.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "nussl_session.h"
#include "nussl_alloc.h"
#include "nussl_utils.h"
#include "nussl_internal.h"
#include "nussl_string.h"
#include "nussl_dates.h"
#include "nussl_socket.h"

#include "nussl_private.h"

#define UGLY_DEBUG() printf("%s %s:%i\n", __FUNCTION__, __FILE__, __LINE__)

#if 0
/* Destroy a a list of hooks. */
static void destroy_hooks(struct hook *hooks)
{
    struct hook *nexthk;

    UGLY_DEBUG();
    while (hooks) {
	nexthk = hooks->next;
	nussl_free(hooks);
	hooks = nexthk;
    }
}
#endif

void nussl_session_destroy(nussl_session *sess)
{

    UGLY_DEBUG();
    NUSSL_DEBUG(NUSSL_DBG_HTTP, "nussl_session_destroy called.\n");

    /* Close the connection; note that the notifier callback could
     * still be invoked here. */
    if (sess->connected) {
	nussl_close_connection(sess);
    }

    nussl_free(sess->server.hostname);
    if (sess->server.address) nussl_addr_destroy(sess->server.address);

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
void nussl_set_hostinfo(nussl_session* sess, const char *hostname, unsigned int port)
{

    UGLY_DEBUG();
    if(sess->server.hostname)
    	nussl_free(sess->server.hostname);
    sess->server.hostname = nussl_strdup(hostname);
    sess->server.port = port;

}

nussl_session *nussl_session_create()
{

    nussl_session *sess = nussl_calloc(sizeof *sess);
    UGLY_DEBUG();

/*    NUSSL_DEBUG(NUSSL_DBG_HTTP, "session to ://%s:%d begins.\n",
	     hostname, port); */

    if (!sess)
    	return NULL;

    strcpy(sess->error, "Unknown error.");

    sess->ssl_context = nussl_ssl_context_create(0);
    sess->ssl_context->crl_refresh_counter = 0;
    sess->ssl_context->crl_refresh = 0;
    sess->flags[NUSSL_SESSFLAG_SSLv2] = 1;
    sess->flags[NUSSL_SESSFLAG_TLS_SNI] = 1;

    /* Set flags which default to on: */
    sess->flags[NUSSL_SESSFLAG_PERSIST] = 1;

    /* Set default read timeout */
    sess->rdtimeout = SOCKET_READ_TIMEOUT;

    return sess;
}

/* Server function */
nussl_session *nussl_session_create_with_fd(int server_fd, int verify)
{
	nussl_session *srv_sess;
	srv_sess = nussl_session_create();
	if ( !srv_sess ) {
		return NULL;
	}

	srv_sess->socket = nussl_sock_create_with_fd(server_fd);
	srv_sess->ssl_context = nussl_ssl_context_create(0);
	/* verify: one of NUSSL_CERT_IGNORE, NUSSL_CERT_REQUEST or NUSSL_CERT_REQUIRE */
	srv_sess->ssl_context->verify = verify;

	return srv_sess;
}

/* Server function */
nussl_session* nussl_session_accept(nussl_session *srv_sess)
{
	nussl_session* client_sess = nussl_session_create();

	if (!client_sess) {
		return NULL;
	}

	if (srv_sess->ssl_context->verify)
		client_sess->check_peer_cert = 1;

	client_sess->socket = nussl_sock_create();

	if (nussl_sock_accept(client_sess->socket, nussl_sock_fd(srv_sess->socket)) != 0) {
		printf("Error during accept()\n");
		nussl_session_destroy(client_sess);
		return NULL;
	}

	if(nussl_sock_accept_ssl(client_sess->socket, srv_sess->ssl_context))
	{
		printf("Error during accept_ssl()\n");
		nussl_session_destroy(client_sess);
		return NULL;
	}

	// Post handshake needed to retrieve the peers certificate
	if(nussl__ssl_post_handshake(client_sess) != NUSSL_OK)
	{
		printf("Negotiation failed\n");
		printf("%s\n", nussl_get_error(client_sess));
		nussl_session_destroy(client_sess);
		return NULL;
	}

	return client_sess;
}

void nussl_set_crl_refresh(nussl_session *sess, int refresh)
{

    sess->ssl_context->crl_refresh = refresh;

}

void nussl_crl_refresh_counter_inc(nussl_session *sess)
{

    sess->ssl_context->crl_refresh_counter++;

}

int nussl_session_get_fd(nussl_session *sess)
{
	return nussl_sock_fd(sess->socket);
}

void nussl_set_addrlist(nussl_session *sess, const nussl_inet_addr **addrs, size_t n)
{

    UGLY_DEBUG();
    sess->addrlist = addrs;
    sess->numaddrs = n;

}

void nussl_set_error(nussl_session *sess, const char *format, ...)
{
    va_list params;

    va_start(params, format);
    nussl_vsnprintf(sess->error, sizeof sess->error, format, params);
    va_end(params);
}

void nussl_set_session_flag(nussl_session *sess, nussl_session_flag flag, int value)
{
    UGLY_DEBUG();
    if (flag < NUSSL_SESSFLAG_LAST) {
        sess->flags[flag] = value;
        if (flag == NUSSL_SESSFLAG_SSLv2 && sess->ssl_context) {
            nussl_ssl_context_set_flag(sess->ssl_context, NUSSL_SSL_CTX_SSLv2, value);
        }
    }
}

int nussl_get_session_flag(nussl_session *sess, nussl_session_flag flag)
{
    UGLY_DEBUG();
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

void nussl_set_read_timeout(nussl_session *sess, int timeout)
{

    UGLY_DEBUG();
    sess->rdtimeout = timeout;

}

void nussl_set_connect_timeout(nussl_session *sess, int timeout)
{

    UGLY_DEBUG();
    sess->cotimeout = timeout;

}

const char *nussl_get_error(nussl_session *sess)
{
    char* ret;

    UGLY_DEBUG();
    ret = nussl_strclean(sess->error);

    return ret;
}

void nussl_close_connection(nussl_session *sess)
{

    UGLY_DEBUG();
    if (sess->connected) {
	NUSSL_DEBUG(NUSSL_DBG_SOCKET, "Closing connection.\n");
	nussl_sock_close(sess->socket);
	sess->socket = NULL;
	NUSSL_DEBUG(NUSSL_DBG_SOCKET, "Connection closed.\n");
    } else {
	NUSSL_DEBUG(NUSSL_DBG_SOCKET, "(Not closing closed connection!).\n");
    }
    sess->connected = 0;

}

#if 0
void nussl_ssl_set_verify(nussl_session *sess, nussl_ssl_verify_fn fn, void *userdata)
{

    UGLY_DEBUG();
    sess->ssl_verify_fn = fn;
    sess->ssl_verify_ud = userdata;

}

void nussl_ssl_provide_clicert(nussl_session *sess,
			  nussl_ssl_provide_fn fn, void *userdata)
{

    UGLY_DEBUG();
    sess->ssl_provide_fn = fn;
    sess->ssl_provide_ud = userdata;

}
#endif

int nussl_ssl_trust_cert_file(nussl_session *sess, const char *cert_file)
{
    int ret;


    UGLY_DEBUG();
    nussl_ssl_certificate* ca = nussl_ssl_cert_read(cert_file);
    if(ca == NULL)
    {
    	nussl_set_error(sess, _("Unable to load trust certificate"));

	return NUSSL_ERROR;
    }

    ret = nussl_ssl_context_trustcert(sess->ssl_context, ca);

    if (ret == NUSSL_OK)
        sess->check_peer_cert = 1;


    return ret;
}

void nussl_ssl_cert_validity(const nussl_ssl_certificate *cert, char *from, char *until)
{
    time_t tf, tu;
    char *date;


    UGLY_DEBUG();
    nussl_ssl_cert_validity_time(cert, &tf, &tu);

    if (from) {
        if (tf != (time_t) -1) {
            date = nussl_rfc1123_date(tf);
            nussl_strnzcpy(from, date, NUSSL_SSL_VDATELEN);
            nussl_free(date);
        }
        else {
            nussl_strnzcpy(from, _("[invalid date]"), NUSSL_SSL_VDATELEN);
        }
    }

    if (until) {
        if (tu != (time_t) -1) {
            date = nussl_rfc1123_date(tu);
            nussl_strnzcpy(until, date, NUSSL_SSL_VDATELEN);
            nussl_free(date);
        }
        else {
            nussl_strnzcpy(until, _("[invalid date]"), NUSSL_SSL_VDATELEN);
        }
    }

}

void nussl__ssl_set_verify_err(nussl_session *sess, int failures)
{
    static const struct {
	int bit;
	const char *str;
    } reasons[] = {
	{ NUSSL_SSL_NOTYETVALID, N_("certificate is not yet valid") },
	{ NUSSL_SSL_EXPIRED, N_("certificate has expired") },
	{ NUSSL_SSL_IDMISMATCH, N_("certificate issued for a different hostname") },
	{ NUSSL_SSL_UNTRUSTED, N_("issuer is not trusted") },
	{ 0, NULL }
    };
    int n, flag = 0;

    UGLY_DEBUG();
    strcpy(sess->error, _("Server certificate verification failed: "));

    for (n = 0; reasons[n].bit; n++) {
	if (failures & reasons[n].bit) {
	    if (flag) strncat(sess->error, ", ", sizeof sess->error);
	    strncat(sess->error, _(reasons[n].str), sizeof sess->error);
	    flag = 1;
	}
    }
}

typedef void (*void_fn)(void);

#if 0
#define ADD_HOOK(hooks, fn, ud) add_hook(&(hooks), NULL, (void_fn)(fn), (ud))

static void add_hook(struct hook **hooks, const char *id, void_fn fn, void *ud)
{
    struct hook *hk = nussl_malloc(sizeof (struct hook)), *pos;

    if (*hooks != NULL) {
	for (pos = *hooks; pos->next != NULL; pos = pos->next)
	    /* nullop */;
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

int nussl_write(nussl_session *session, char *buffer, size_t count)
{
	int ret;

	UGLY_DEBUG();
	ret = nussl_sock_fullwrite(session->socket, buffer, count);
	if (ret < 0)
		nussl_set_error(session, nussl_sock_error(session->socket));


	return ret;
}


ssize_t nussl_read(nussl_session *session, char *buffer, size_t count)
{
	int ret;

	ret = nussl_sock_read(session->socket, buffer, count);
	if (ret < 0)
		nussl_set_error(session, nussl_sock_error(session->socket));

	return ret;
}

int nussl_ssl_set_keypair(nussl_session *session, const char* cert_file, const char* key_file)
{
	nussl_ssl_client_cert* cert;
	int ret;


	UGLY_DEBUG();

	if (check_key_perms(key_file)!= NUSSL_OK)
	{
		nussl_set_error(session, _("Permissions on private key %s are not restrictive enough, it should be readable only by its owner."), key_file);

		return NUSSL_ERROR;
	}

	cert = nussl_ssl_import_keypair(cert_file, key_file);
	if (cert == NULL)
	{
		nussl_set_error(session, _("Unable to load private key or certificate file"));

		return NUSSL_ERROR;
	}

	ret = nussl_ssl_set_clicert(session, cert);

	return ret;
}

int nussl_ssl_set_pkcs12_keypair(nussl_session *session, const char* pkcs12_file, const char* password)
{
	int ret = NUSSL_OK;


	UGLY_DEBUG();

	if (check_key_perms(pkcs12_file)!= NUSSL_OK)
	{
		nussl_set_error(session, _("Permissions of key %s are too open."), pkcs12_file);
		return NUSSL_ERROR;
	}

	nussl_ssl_client_cert* cert = nussl_ssl_clicert_read(pkcs12_file);

	if (cert == NULL)
	{
		nussl_set_error(session, _("Unable to load PKCS12 certificate file"));
		return NUSSL_ERROR;
	}

	if (nussl_ssl_clicert_encrypted(cert))
	{
		if (password)
		{
			if (nussl_ssl_clicert_decrypt(cert, password) != 0)
			{
				nussl_set_error(session, _("Bad password to decrypt the PKCS key"));
				return NUSSL_ERROR;
			}
		}
		else
		{
			nussl_set_error(session, _("PKCS12 file is encrypted, please supply a password"));
			return NUSSL_ERROR;
		}
	}
	else
	{
		if (password)
			fprintf(stderr, "Warning, the key is not encrypted, but a password was supplied\n");
	}

	ret = nussl_ssl_set_clicert(session, cert);


	return ret;
}

int nussl_session_getpeer(nussl_session *sess, struct sockaddr *addr, socklen_t *addrlen)
{

	int fd = nussl_session_get_fd(sess);
	int ret = getpeername(fd, addr, addrlen);

	if ( ret != 0 ) {
		nussl_set_error(sess, strerror(ret));
		return NUSSL_ERROR;
	}

	return NUSSL_OK;
}

int nussl_init()
{
	int ret;

	ret = nussl_sock_init();

	return ret;
}

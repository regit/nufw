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

/* Destroy a a list of hooks. */
static void destroy_hooks(struct hook *hooks)
{
    struct hook *nexthk;

    while (hooks) {
	nexthk = hooks->next;
	ne_free(hooks);
	hooks = nexthk;
    }
}

void ne_session_destroy(ne_session *sess) 
{
    NE_DEBUG(NE_DBG_HTTP, "ne_session_destroy called.\n");

    /* Close the connection; note that the notifier callback could
     * still be invoked here. */
    if (sess->connected) {
	ne_close_connection(sess);
    }
    
    ne_free(sess->server.hostname);
    if (sess->server.address) ne_addr_destroy(sess->server.address);

#ifdef NE_HAVE_SSL
    if (sess->ssl_context)
        ne_ssl_context_destroy(sess->ssl_context);

    if (sess->server_cert)
        ne_ssl_cert_free(sess->server_cert);
    
    if (sess->client_cert)
        ne_ssl_clicert_free(sess->client_cert);
#endif

    ne_free(sess);
}

/* Stores the hostname/port in *info, setting up the "hostport"
 * segment correctly. */
static void
set_hostinfo(struct host_info *info, const char *hostname, unsigned int port)
{
    info->hostname = ne_strdup(hostname);
    info->port = port;
}

ne_session *ne_session_create(const char *hostname, unsigned int port)
{
    ne_session *sess = ne_calloc(sizeof *sess);

    NE_DEBUG(NE_DBG_HTTP, "session to ://%s:%d begins.\n",
	     hostname, port);

    strcpy(sess->error, "Unknown error.");

    /* set the hostname/port */
    set_hostinfo(&sess->server, hostname, port);

#ifdef NE_HAVE_SSL
    sess->ssl_context = ne_ssl_context_create(0);
    sess->flags[NE_SESSFLAG_SSLv2] = 1;
    sess->flags[NE_SESSFLAG_TLS_SNI] = 1;
#endif

    /* Set flags which default to on: */
    sess->flags[NE_SESSFLAG_PERSIST] = 1;

    return sess;
}

/* void ne_session_proxy(ne_session *sess, const char *hostname, */
/* 		      unsigned int port) */
/* { */
/*     sess->use_proxy = 1; */
/*     if (sess->proxy.hostname) ne_free(sess->proxy.hostname); */
/*     set_hostinfo(&sess->proxy, hostname, port); */
/* } */

void ne_set_addrlist(ne_session *sess, const ne_inet_addr **addrs, size_t n)
{
    sess->addrlist = addrs;
    sess->numaddrs = n;
}

void ne_set_error(ne_session *sess, const char *format, ...)
{
    va_list params;

    va_start(params, format);
    ne_vsnprintf(sess->error, sizeof sess->error, format, params);
    va_end(params);
}

void ne_set_session_flag(ne_session *sess, ne_session_flag flag, int value)
{
    if (flag < NE_SESSFLAG_LAST) {
        sess->flags[flag] = value;
#ifdef NE_HAVE_SSL
        if (flag == NE_SESSFLAG_SSLv2 && sess->ssl_context) {
            ne_ssl_context_set_flag(sess->ssl_context, NE_SSL_CTX_SSLv2, value);
        }
#endif
    }
}

int ne_get_session_flag(ne_session *sess, ne_session_flag flag)
{
    if (flag < NE_SESSFLAG_LAST) {
        return sess->flags[flag];
    }
    return -1;
}

/* static void progress_notifier(void *userdata, ne_session_status status, */
/*                               const ne_session_status_info *info) */
/* { */
/*     ne_session *sess = userdata; */

/*     if (status == ne_status_sending || status == ne_status_recving) { */
/*         sess->progress_cb(sess->progress_ud, info->sr.progress, info->sr.total);     */
/*     } */
/* } */

/* void ne_set_progress(ne_session *sess, ne_progress progress, void *userdata) */
/* { */
/*     sess->progress_cb = progress; */
/*     sess->progress_ud = userdata; */
/*     ne_set_notifier(sess, progress_notifier, sess); */
/* } */

/* void ne_set_notifier(ne_session *sess, */
/* 		     ne_notify_status status, void *userdata) */
/* { */
/*     sess->notify_cb = status; */
/*     sess->notify_ud = userdata; */
/* } */

void ne_set_read_timeout(ne_session *sess, int timeout)
{
    sess->rdtimeout = timeout;
}

void ne_set_connect_timeout(ne_session *sess, int timeout)
{
    sess->cotimeout = timeout;
}

const char *ne_get_error(ne_session *sess)
{
    return ne_strclean(sess->error);
}

void ne_close_connection(ne_session *sess)
{
    if (sess->connected) {
	NE_DEBUG(NE_DBG_SOCKET, "Closing connection.\n");
	ne_sock_close(sess->socket);
	sess->socket = NULL;
	NE_DEBUG(NE_DBG_SOCKET, "Connection closed.\n");
    } else {
	NE_DEBUG(NE_DBG_SOCKET, "(Not closing closed connection!).\n");
    }
    sess->connected = 0;
}

void ne_ssl_set_verify(ne_session *sess, ne_ssl_verify_fn fn, void *userdata)
{
    sess->ssl_verify_fn = fn;
    sess->ssl_verify_ud = userdata;
}

void ne_ssl_provide_clicert(ne_session *sess, 
			  ne_ssl_provide_fn fn, void *userdata)
{
    sess->ssl_provide_fn = fn;
    sess->ssl_provide_ud = userdata;
}

void ne_ssl_trust_cert(ne_session *sess, const ne_ssl_certificate *cert)
{
#ifdef NE_HAVE_SSL
    if (sess->ssl_context) {
        ne_ssl_context_trustcert(sess->ssl_context, cert);
    }
#endif
}

void ne_ssl_cert_validity(const ne_ssl_certificate *cert, char *from, char *until)
{
    time_t tf, tu;
    char *date;

    ne_ssl_cert_validity_time(cert, &tf, &tu);
    
    if (from) {
        if (tf != (time_t) -1) {
            date = ne_rfc1123_date(tf);
            ne_strnzcpy(from, date, NE_SSL_VDATELEN);
            ne_free(date);
        }
        else {
            ne_strnzcpy(from, _("[invalid date]"), NE_SSL_VDATELEN);
        }
    }
        
    if (until) {
        if (tu != (time_t) -1) {
            date = ne_rfc1123_date(tu);
            ne_strnzcpy(until, date, NE_SSL_VDATELEN);
            ne_free(date);
        }
        else {
            ne_strnzcpy(until, _("[invalid date]"), NE_SSL_VDATELEN);
        }
    }
}

#ifdef NE_HAVE_SSL
void ne__ssl_set_verify_err(ne_session *sess, int failures)
{
    static const struct {
	int bit;
	const char *str;
    } reasons[] = {
	{ NE_SSL_NOTYETVALID, N_("certificate is not yet valid") },
	{ NE_SSL_EXPIRED, N_("certificate has expired") },
	{ NE_SSL_IDMISMATCH, N_("certificate issued for a different hostname") },
	{ NE_SSL_UNTRUSTED, N_("issuer is not trusted") },
	{ 0, NULL }
    };
    int n, flag = 0;

    strcpy(sess->error, _("Server certificate verification failed: "));

    for (n = 0; reasons[n].bit; n++) {
	if (failures & reasons[n].bit) {
	    if (flag) strncat(sess->error, ", ", sizeof sess->error);
	    strncat(sess->error, _(reasons[n].str), sizeof sess->error);
	    flag = 1;
	}
    }
}
#endif

typedef void (*void_fn)(void);

#define ADD_HOOK(hooks, fn, ud) add_hook(&(hooks), NULL, (void_fn)(fn), (ud))

static void add_hook(struct hook **hooks, const char *id, void_fn fn, void *ud)
{
    struct hook *hk = ne_malloc(sizeof (struct hook)), *pos;

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

/* void ne_hook_create_request(ne_session *sess,  */
/* 			    ne_create_request_fn fn, void *userdata) */
/* { */
/*     ADD_HOOK(sess->create_req_hooks, fn, userdata); */
/* } */

/* void ne_hook_pre_send(ne_session *sess, ne_pre_send_fn fn, void *userdata) */
/* { */
/*     ADD_HOOK(sess->pre_send_hooks, fn, userdata); */
/* } */

/* void ne_hook_post_send(ne_session *sess, ne_post_send_fn fn, void *userdata) */
/* { */
/*     ADD_HOOK(sess->post_send_hooks, fn, userdata); */
/* } */

/* void ne_hook_post_headers(ne_session *sess, ne_post_headers_fn fn,  */
/*                           void *userdata) */
/* { */
/*     ADD_HOOK(sess->post_headers_hooks, fn, userdata); */
/* } */

/* void ne_hook_destroy_request(ne_session *sess, */
/* 			     ne_destroy_req_fn fn, void *userdata) */
/* { */
/*     ADD_HOOK(sess->destroy_req_hooks, fn, userdata);     */
/* } */

/* void ne_hook_destroy_session(ne_session *sess, */
/* 			     ne_destroy_sess_fn fn, void *userdata) */
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
            ne_free(*p);
            (*p) = next;
            break;
        }
        p = &(*p)->next;
    }
}

#define REMOVE_HOOK(hooks, fn, ud) remove_hook(&hooks, (void_fn)fn, ud)
*/
/* void ne_unhook_create_request(ne_session *sess,  */
/*                               ne_create_request_fn fn, void *userdata) */
/* { */
/*     REMOVE_HOOK(sess->create_req_hooks, fn, userdata); */
/* } */

/* void ne_unhook_pre_send(ne_session *sess, ne_pre_send_fn fn, void *userdata) */
/* { */
/*     REMOVE_HOOK(sess->pre_send_hooks, fn, userdata); */
/* } */

/* void ne_unhook_post_headers(ne_session *sess, ne_post_headers_fn fn,  */
/* 			    void *userdata) */
/* { */
/*     REMOVE_HOOK(sess->post_headers_hooks, fn, userdata); */
/* } */

/* void ne_unhook_post_send(ne_session *sess, ne_post_send_fn fn, void *userdata) */
/* { */
/*     REMOVE_HOOK(sess->post_send_hooks, fn, userdata); */
/* } */

/* void ne_unhook_destroy_request(ne_session *sess, */
/*                                ne_destroy_req_fn fn, void *userdata) */
/* { */
/*     REMOVE_HOOK(sess->destroy_req_hooks, fn, userdata);     */
/* } */
/*
void ne_unhook_destroy_session(ne_session *sess,
                               ne_destroy_sess_fn fn, void *userdata)
{
    REMOVE_HOOK(sess->destroy_sess_hooks, fn, userdata);
}
*/

int ne_write(ne_session *session, char *buffer, size_t count)
{
	return ne_sock_fullwrite(session->socket, buffer, count);
}


ssize_t ne_read(ne_session *session, char *buffer, size_t count)
{
	return ne_sock_fullread(session->socket, buffer, count);
}





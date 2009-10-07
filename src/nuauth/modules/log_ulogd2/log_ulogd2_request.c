/*
 ** Copyright(C) 2008-2009 INL
 ** Written by  Pierre Chifflier <chifflier@inl.fr>
 **
 ** $Id$
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
 */

#include <auth_srv.h>
#include <string.h>
#include <errno.h>

#include <inttypes.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "log_ulogd2.h"

#define UNIX_PATH_MAX	108

#include "security.h"

/**
 * \ingroup Ulogd2Module
 *
 * @{ */

struct ulogd2_request * ulogd2_request_new(void)
{
	struct ulogd2_request *req;

	req = g_new0(struct ulogd2_request, 1);
	req->payload = NULL;
	req->payload_len = 0;

	req->options = g_new0(struct ulogd2_option, 1);

	req->options->opt = -1;
	req->options->value = NULL;
	req->options->length = 0;
	INIT_LLIST_HEAD( &req->options->list );

	return req;
}

void ulogd2_request_set_payload(struct ulogd2_request *req, unsigned char *payload, unsigned int payload_len)
{
	req->payload = payload;
	req->payload_len = payload_len;
}

void ulogd2_request_add_option(struct ulogd2_request *req, unsigned int opt, void *value, unsigned int length)
{
	struct ulogd2_option *option = NULL;

	option = g_new0(struct ulogd2_option, 1);

	option->opt = opt;
	option->value = value;
	option->length = length;
	INIT_LLIST_HEAD( &option->list );

	llist_add(&option->list, &req->options->list);
}

#define  INC_RET(value) do { ret += value; if (ret >= bufsz) return -1; } while(0)

ssize_t ulogd2_request_format(struct ulogd2_request *req, unsigned char*buf, unsigned int bufsz)
{
	struct ulogd2_option *opt, *optbkp;
	ssize_t ret=0;

	/* skip space to store total length (stored later) */
	INC_RET(sizeof(u_int16_t));

	/* payload length + payload */
	*(u_int16_t*)(buf + ret) = htons(req->payload_len);
	INC_RET(sizeof(u_int16_t));

	memcpy(buf+ret, req->payload, req->payload_len);
	INC_RET(req->payload_len);

	/* Options, in KLV (Key Length Value) format */
	llist_for_each_entry_safe(opt, optbkp, &req->options->list, list) {
		/* Key ID */
		*(u_int16_t*)(buf + ret) = htons(opt->opt);
		INC_RET(sizeof(u_int16_t));
		/* Length */
		/* always write a \0 after option data, hence the +1 */
		*(u_int16_t*)(buf + ret) = htons(opt->length + 1);
		INC_RET(sizeof(u_int16_t));
		/* Value */
		memcpy(buf+ret, opt->value, opt->length);
		INC_RET(opt->length);
		buf[ret] = '\0';
		ret++;
	}

	/* finally, set options length */
	*(u_int16_t*)buf = htons(ret);

	return ret;
}

void ulogd2_request_free(struct ulogd2_request *req)
{
	if (req->options) {
		struct ulogd2_option *opt, *optbkp;
		llist_for_each_entry_safe(opt, optbkp, &req->options->list, list) {
			g_free(opt);
		}
		//while (!llist_empty(&req->options->list)) {
		//	opt = llist_entry(&req->options->list, struct ulogd2_option, list);
		//	llist_del(&req->options->list);
		//}
		g_free(req->options);
	}
	g_free(req);
}

/** @} */

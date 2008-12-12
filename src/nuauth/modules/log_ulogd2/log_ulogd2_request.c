/*
 ** Copyright(C) 2008 INL
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
 * \ingroup NuauthModules
 * \defgroup LoggingNuauthModules Logging modules
 */

/**
 * \ingroup LoggingNuauthModules
 * \defgroup Ulogd2Module Ulogd2 logging module
 *
 * @{ */

struct ulogd2_request * ulogd2_request_new(void)
{
	struct ulogd2_request *req;

	req = malloc(sizeof(struct ulogd2_request));
	req->payload = NULL;
	req->payload_len = 0;

	req->options = malloc(sizeof(struct ulogd2_option));

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

	option = malloc(sizeof(struct ulogd2_option));

	option->opt = opt;
	option->value = value;
	option->length = length;
	INIT_LLIST_HEAD( &option->list );

	llist_add(&option->list, &req->options->list);
}

ssize_t ulogd2_request_format(struct ulogd2_request *req, unsigned char*buf, unsigned int bufsz)
{
	struct ulogd2_option *opt, *optbkp;
	ssize_t ret=0;

	/* skip space to store total length (stored later) */
	ret += sizeof(u_int16_t);

	/* payload length + payload */
	*(u_int16_t*)(buf + ret) = htons(req->payload_len);
	ret += sizeof(u_int16_t);

	memcpy(buf+ret, req->payload, req->payload_len);
	ret += req->payload_len;

	/* Options, in KLV (Key Length Value) format */
	llist_for_each_entry_safe(opt, optbkp, &req->options->list, list) {
		/* TODO remove this, debug */
		fprintf(stderr, "Option: %d, value: '%s', length %d\n",
			opt->opt,
			(char*)opt->value,
			opt->length);

		/* Key ID */
		*(u_int16_t*)(buf + ret) = htons(opt->opt);
		ret += sizeof(u_int16_t);
		/* Length */
		/* always write a \0 after option data, hence the +1 */
		*(u_int16_t*)(buf + ret) = htons(opt->length + 1);
		ret += sizeof(u_int16_t);
		/* Value */
		memcpy(buf+ret, opt->value, opt->length);
		ret += opt->length;
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
			free(opt);
		}
		//while (!llist_empty(&req->options->list)) {
		//	opt = llist_entry(&req->options->list, struct ulogd2_option, list);
		//	llist_del(&req->options->list);
		//}
		free(req->options);
	}
	free(req);
}

/** @} */

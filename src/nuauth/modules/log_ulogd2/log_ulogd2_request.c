/*
 ** Copyright(C) 2008-2010 INL
 ** Written by  Pierre Chifflier <chifflier@inl.fr>
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

#include <netinet/in.h>
#include <netinet/ip.h>

#include "log_ulogd2.h"

#include "security.h"

/**
 * \ingroup Ulogd2Module
 *
 * @{ */

/***** Keep this in sync with ulogd2 **********/
struct ulogd_unixsock_packet_t {
	uint32_t marker;
	uint16_t total_size;
	uint32_t version:4,
		 reserved:28;
	uint16_t payload_length;
} __attribute__((packed));

struct ulogd_unixsock_option_t  {
	uint32_t option_id;
	uint32_t option_length;
	char     option_value[0];
} __attribute__((packed));

#define USOCK_ALIGNTO 8
#define USOCK_ALIGN(len) ( ((len)+USOCK_ALIGNTO-1) & ~(USOCK_ALIGNTO-1) )
/***** end of sync **********/

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
	size_t ret=0;
	int padded_length;
	struct ulogd_unixsock_packet_t pkt;

	if (bufsz < sizeof(struct ulogd_unixsock_packet_t))
		return -1;

	pkt.marker = htonl(ULOGD_SOCKET_MARK);
	pkt.total_size = 0; /* stored later */
	pkt.version = 0;
	pkt.reserved = 0;
	pkt.payload_length = htons(req->payload_len);

	memcpy(buf, &pkt, sizeof(pkt));
	INC_RET(sizeof(pkt));

	memcpy(buf+ret, req->payload, req->payload_len);
	padded_length = USOCK_ALIGN(req->payload_len);
	INC_RET(padded_length);

	/* Options, in KLV (Key Length Value) format */
	llist_for_each_entry_safe(opt, optbkp, &req->options->list, list) {
		/* Key ID */
		*(u_int32_t*)(buf + ret) = htonl(opt->opt);
		INC_RET(sizeof(u_int32_t));
		/* Length */
		/* always write a \0 after option data, hence the +1 */
		*(u_int32_t*)(buf + ret) = htonl(opt->length + 1);
		INC_RET(sizeof(u_int32_t));
		/* Value */
		memcpy(buf+ret, opt->value, opt->length);
		buf[ret + opt->length] = '\0';
		padded_length = USOCK_ALIGN(opt->length + 1);
		INC_RET(padded_length);
	}

	/* finally, set options length */
	*(u_int16_t*)(buf + sizeof(u_int32_t)) = htons(ret - sizeof(u_int32_t));

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

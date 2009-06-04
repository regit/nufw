/*
 ** Copyright 2005-2009 - INL
 ** Written by Eric Leblond <regit@inl.fr>
 **            Vincent Deffontaines <vincent@inl.fr>
 ** INL http://www.inl.fr/
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

#include "libnuclient.h"
#include <sasl/saslutil.h>
#include <proto.h>
#include <nussl.h>

#include "sending.h"
#include "proc.h"

/**
 * \addtogroup libnuclient
 * @{
 */

#if DEBUG_ENABLE
int count;
#endif

int send_hello_pckt(nuauth_session_t * session)
{
	struct nu_header header;

	/* fill struct */
	header.proto = PROTO_VERSION;
	header.msg_type = USER_HELLO;
	header.option = 0;
	header.length = htons(sizeof(struct nu_header));

#if XXX
	/*  send it */
	if (session->tls) {
		if (gnutls_record_send
		    (session->tls, &header,
		     sizeof(struct nu_header)) <= 0) {
#if DEBUG_ENABLE
			printf("write failed at %s:%d\n", __FILE__,
			       __LINE__);
#endif
			return 0;
		}
	}
#else
	if (nussl_write(session->nussl, (char*)&header, sizeof(struct nu_header)) < 0)
	{
#if DEBUG_ENABLE
		printf("write failed at %s:%d\n", __FILE__,
		       __LINE__);
#endif
		return 0;
	}
#endif

	return 1;
}


/**
 * Send connections to nuauth: between 1 and #CONN_MAX connections
 * in a big packet of format:
 *   [ nu_header + nu_authfield_ipv6 * N ]
 */
int send_user_pckt(nuauth_session_t * session, conn_t * carray[CONN_MAX])
{
	char data[PACKET_SIZE];
	char *pointer;
	unsigned int item;
	struct nu_header *header;
	struct nu_authreq *authreq;
	struct nu_authfield_ipv6 *authfield;
	struct nu_authfield_app *appfield;
	struct nu_authfield_app *sigfield;
	unsigned len;
	const char *appname;
	const char *appsig;
	char *app_ptr;

	session->timestamp_last_sent = time(NULL);
	memset(data, 0, sizeof data);

	header = (struct nu_header *) data;
	header->proto = PROTO_VERSION;
	header->msg_type = USER_REQUEST;
	header->option = 0;
	header->length = sizeof(struct nu_header);
	pointer = (char *) (header + 1);

	for (item = 0; ((item < CONN_MAX) && carray[item] != NULL); item++) {
#if DEBUG
		printf("adding one authreq\n");
#endif
#ifdef LINUX
		/* get application name from inode */
		appname = prg_cache_get(carray[item]->inode);
#else
		appname = "UNKNOWN";
#endif
		header->length +=
		    sizeof(struct nu_authreq) +
		    sizeof(struct nu_authfield_ipv6);

		authreq = (struct nu_authreq *) pointer;
		authreq->packet_seq = session->packet_seq++;
		authreq->packet_length =
		    sizeof(struct nu_authreq) +
		    sizeof(struct nu_authfield_ipv6);

		authfield = (struct nu_authfield_ipv6 *) (authreq + 1);
		authfield->type = IPV6_FIELD;
		authfield->option = 0;
		authfield->src = carray[item]->ip_src;
		authfield->dst = carray[item]->ip_dst;
		authfield->proto = carray[item]->protocol;
		authfield->flags = 0;
		authfield->FUSE = 0;
#ifdef _I386__ENDIAN_H_
#ifdef __DARWIN_LITTLE_ENDIAN
		authfield->sport = carray[item]->port_src;
		authfield->dport = carray[item]->port_dst;
#else
		authfield->sport = htons(carray[item]->port_src);
		authfield->dport = htons(carray[item]->port_dst);
#endif				/* DARWIN LITTLE ENDIAN */
#else
		authfield->sport = htons(carray[item]->port_src);
		authfield->dport = htons(carray[item]->port_dst);
#endif				/* I386 ENDIAN */

		/* application field  */
		appfield = (struct nu_authfield_app *) (authfield + 1);
		appfield->type = APP_FIELD;
		appfield->option = APP_TYPE_NAME;
		app_ptr = (char *) (appfield + 1);
		sasl_encode64(appname, strlen(appname), app_ptr,
			      PROGNAME_BASE64_WIDTH, &len);
		appfield->length = sizeof(struct nu_authfield_app) + len;
		authreq->packet_length += appfield->length;

		/* glue piece together on data if packet is not too long */
		header->length += appfield->length;

		appsig = prg_cache_getsig(carray[item]->inode);
		sigfield = (struct nu_authfield_app *) ((char*)appfield + appfield->length);
		sigfield->type = HASH_FIELD;
		sigfield->option = 0;
		app_ptr = (char *) (sigfield + 1);
		memcpy(app_ptr, appsig, strlen(appsig));
		sigfield->length = sizeof(struct nu_authfield_app) + strlen(appsig);

		authreq->packet_length += sigfield->length;

		/* glue piece together on data if packet is not too long */
		header->length += sigfield->length;

		assert(header->length < PACKET_SIZE);

		pointer += authreq->packet_length;

		sigfield->length = htons(sigfield->length);

		appfield->length = htons(appfield->length);

		authreq->packet_length = htons(authreq->packet_length);
		authfield->length =
		    htons(sizeof(struct nu_authfield_ipv6));
	}
	header->length = htons(header->length);
	if (session->debug_mode) {
		log_printf(DEBUG_LEVEL_INFO, "[+] Send %u new connection(s) to nuauth\n", item);
	}

	/* and send it */
#if XXX
	if (session->tls) {
		if (gnutls_record_send
		    (session->tls, data, pointer - data) <= 0) {
			log_printf(DEBUG_LEVEL_CRITICAL, "write failed\n");
			return 0;
		}
	}
#else
	if (nussl_write(session->nussl, (char*)data, pointer - data) < 0)
	{
		log_printf(DEBUG_LEVEL_CRITICAL, "write failed\n");
		return 0;
	}
#endif
	return 1;
}

/** @} */

/*
 ** Copyright (C) 2005-2006 INL
 ** Written by Eric Leblond <regit@inl.fr>
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

/** \file nufw/conntrack.c
 *  \brief Connection tracking
 *
 * Connection tracking function if NuFW is compiled with \#HAVE_LIBCONNTRACK.
 */

#define DEBUG_CONNTRACK

#include "nufw.h"
#include "ipv6.h"
#ifdef HAVE_LIBCONNTRACK

#include <nubase.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>

#ifdef HAVE_NEW_NFCT_API
#  define MSG_DESTROY NFCT_T_DESTROY
#  define MSG_UPDATE NFCT_T_UPDATE
#else
#  define MSG_DESTROY NFCT_MSG_DESTROY
#  define MSG_UPDATE NFCT_MSG_UPDATE
#endif

void fill_message(struct nuv4_conntrack_message_t *message,
#ifdef HAVE_NEW_NFCT_API
		  struct nf_conntrack *conn)
#else
		  struct nfct_conntrack *conn)
#endif
{
#ifdef DEBUG_CONNTRACK
	char ascii[INET6_ADDRSTRLEN];
#endif

#ifdef HAVE_NEW_NFCT_API
	message->ip_protocol = nfct_get_attr_u8(conn, ATTR_ORIG_L4PROTO);

	if (nfct_get_attr_u8(conn, ATTR_ORIG_L3PROTO) == AF_INET) {
		uint32_to_ipv6(nfct_get_attr_u32(conn, ATTR_ORIG_IPV4_SRC),
			&message->ip_src);
		uint32_to_ipv6(nfct_get_attr_u32(conn, ATTR_ORIG_IPV4_DST),
			&message->ip_dst);
	} else {
		memcpy(&message->ip_src,
		       nfct_get_attr(conn, ATTR_ORIG_IPV6_SRC),
		       sizeof(message->ip_src));
		memcpy(&message->ip_dst,
		       nfct_get_attr(conn, ATTR_ORIG_IPV6_DST),
		       sizeof(message->ip_dst));
	}

	switch (message->ip_protocol) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		message->src_port =
		    nfct_get_attr_u16(conn, ATTR_ORIG_PORT_SRC);
		message->dest_port =
		    nfct_get_attr_u16(conn, ATTR_ORIG_PORT_DST);
		break;
	default:
		message->src_port = 0;
		message->dest_port = 0;
		break;
	}

	message->mark = nfct_get_attr_u32(conn, ATTR_MARK);

	message->packets_in =
	    nfct_get_attr_u32(conn, ATTR_ORIG_COUNTER_PACKETS);
	message->bytes_in =
	    nfct_get_attr_u32(conn, ATTR_ORIG_COUNTER_BYTES);

	message->packets_out =
	    nfct_get_attr_u32(conn, ATTR_REPL_COUNTER_PACKETS);
	message->bytes_out =
	    nfct_get_attr_u32(conn, ATTR_REPL_COUNTER_BYTES);
#else
	message->ip_protocol = conn->tuple[0].protonum;

	if (conn->tuple[0].l3protonum == AF_INET) {
		uint32_to_ipv6(conn->tuple[0].src.v4,
				&message->ip_src);

		uint32_to_ipv6(conn->tuple[0].dst.v4,
				&message->ip_dst);
	} else {
		memcpy(&message->ip_src, &conn->tuple[0].src.v6,
		       sizeof(message->ip_src));
		memcpy(&message->ip_dst, &conn->tuple[0].dst.v6,
		       sizeof(message->ip_dst));
	}

	switch (message->ip_protocol) {
	case IPPROTO_TCP:
		message->src_port = conn->tuple[0].l4src.tcp.port;
		message->dest_port = conn->tuple[0].l4dst.tcp.port;
		break;
	case IPPROTO_UDP:
		message->src_port = conn->tuple[0].l4src.udp.port;
		message->dest_port = conn->tuple[0].l4dst.udp.port;
		break;
	default:
		message->src_port = 0;
		message->dest_port = 0;
		break;
	}

	message->mark = conn->mark;

	message->packets_in = conn->counters[1].packets;
	message->bytes_in = conn->counters[1].bytes;

	message->packets_out = conn->counters[0].packets;
	message->bytes_out = conn->counters[0].bytes;
#endif

#ifdef DEBUG_CONNTRACK
	printf("(*) New conntrack event: ");
	FORMAT_IPV6(&message->ip_src, ascii);
	printf(" src=%s", ascii);
	FORMAT_IPV6(&message->ip_dst, ascii);
	printf(" dst=%s\n", ascii);
#endif
}

/**
 * Send message to TLS tunnel on new netfilter conntrack event.
 *
 * \param arg Pointer to a connection of type ::nfct_conntrack
 * \param type Event type (IPCTNL_MSG_CT_DELETE, IPCTNL_MSG_CT_NEW, ...)
 * \param flags Event flags (no used)
 * \param data (no data, NULL pointer)
 * \return If an error occurs returns -1, else returns 0
 */
#ifdef HAVE_NEW_NFCT_API
int update_handler(enum nf_conntrack_msg_type type,
		   struct nf_conntrack *conn, void *data)
#else
int update_handler(struct nfct_conntrack *conn, unsigned int flags, int type,
		   void *data)
#endif
{
	struct nuv4_conntrack_message_t message;
	int ret;
#ifdef HAVE_NEW_NFCT_API
	int callback_ret = NFCT_CB_CONTINUE;
#else
	int callback_ret = 0;
#endif
	/* switch can be done with a signal */
	if (handle_conntrack_event == 0) {
#ifdef HAVE_NEW_NFCT_API
		return NFCT_CB_STOP;
#else
		return -1;
#endif
	}
	/* if nufw_conntrack_uses_mark is set we should have mark set here
	 * This REQUIRES correct CONNMARK rules and correct kernel */
	if (nufw_conntrack_uses_mark == 1) {
#ifdef HAVE_NEW_NFCT_API
		if (nfct_get_attr_u32(conn, ATTR_MARK) == 0)
			return callback_ret;
#else
		if (conn->mark == 0)
			return callback_ret;
#endif
	}
	message.protocol_version = PROTO_NUFW_VERSION;
	message.msg_length =
	    htons(sizeof(struct nuv4_conntrack_message_t));
	switch (type) {
	case MSG_DESTROY:
		message.msg_type = AUTH_CONN_DESTROY;
		debug_log_printf(DEBUG_AREA_MAIN,
				 DEBUG_LEVEL_VERBOSE_DEBUG,
				 "Destroy event to be send to nuauth.");
		break;
	case MSG_UPDATE:
#ifdef HAVE_NEW_NFCT_API
		if (!(nfct_get_attr_u32(conn, ATTR_STATUS) & IPS_ASSURED)) {
			return callback_ret;
		} else {
			/* We only want to log ESTABLISHED for TCP state */
			if (nfct_get_attr_u8(conn, ATTR_ORIG_L4PROTO)
					== IPPROTO_TCP) {
				if (nfct_get_attr_u8(conn, ATTR_TCP_STATE)
						!= TCP_CONNTRACK_ESTABLISHED) {
					return callback_ret;
				}
			}
		}
#else
		if (!(conn->status & IPS_ASSURED)) {

			return callback_ret;
		}
#endif
		message.msg_type = AUTH_CONN_UPDATE;
		debug_log_printf(DEBUG_AREA_MAIN,
				 DEBUG_LEVEL_VERBOSE_DEBUG,
				 "Update event to be send to nuauth.");
		break;
	default:
		debug_log_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_INFO,
				 "Strange, get message (type %d) not %d or %d",
				 type, MSG_DESTROY, MSG_UPDATE);
		return callback_ret;
	}
	fill_message(&message, conn);

	pthread_mutex_lock(&tls.mutex);
	if (tls.session) {
		debug_log_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
				 "Sending conntrack event to nuauth.");
		ret = gnutls_record_send(*(tls.session),
					 &message,
					 sizeof(struct
						nuv4_conntrack_message_t)
		    );
		if (ret < 0) {
			if (gnutls_error_is_fatal(ret)) {
				/* warn sender thread that it will need to reconnect at next access */
				pthread_cancel(tls.auth_server);
				tls.auth_server_running = 0;
				pthread_mutex_unlock(&tls.mutex);
				return callback_ret;
			}
		}
	}
	pthread_mutex_unlock(&tls.mutex);
	return callback_ret;
}

/**
 * Install netfilter conntrack event handler: update_handler().
 *
 * \return NULL pointer
 */
void *conntrack_event_handler(void *data)
{
	struct nfct_handle *cth;
	int res;

	debug_log_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_VERBOSE_DEBUG,
			 "Starting conntrack thread");
	cth =
	    nfct_open(CONNTRACK,
		      NF_NETLINK_CONNTRACK_DESTROY |
		      NF_NETLINK_CONNTRACK_UPDATE);
	if (!cth)
		log_printf(DEBUG_LEVEL_WARNING,
			   "Not enough memory to open netfilter conntrack");
#ifdef HAVE_NEW_NFCT_API
	nfct_callback_register(cth, NFCT_T_UPDATE | NFCT_T_DESTROY,
			       update_handler, NULL);
	res = nfct_catch(cth);
#else
	nfct_register_callback(cth, update_handler, NULL);
	res = nfct_event_conntrack(cth);
#endif
	nfct_close(cth);
	debug_log_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_VERBOSE_DEBUG,
			 "Conntrack thread has exited");
	return NULL;
}

#endif				/* ifdef HAVE_LIBCONNTRACK */

/*
 ** Copyright (C) 2002-2009 INL
 ** Written by Eric Leblond <eric@regit.org>
 **            Vincent Deffontaines <vincent@gryzor.com>
 ** INL http://www.inl.fr/
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

#include "nufw.h"

#include <nubase.h>

#define CLEANING_DELAY 5

#ifdef HAVE_NFQ_INDEV_NAME
#  include "iface.h"
#endif

/** \file packetsrv.c
 *  \brief Packet server thread
 *
 * packetsrv() is a thread which read packet from netfilter queue. If packet
 * content match to IPv4 TCP/UDP, add it to the packet list (::packets_list)
 * and ask NuAuth an authentication or control using auth_request_send().
 *
 * When using NetFilter queue, treat_packet() is used as callback to parse
 * new packets. Function look_for_tcp_flags() is a tool to check TCP flags
 * in a IPv4 packet.
 */

/**
 * Parse an packet and check if it's TCP in IPv4 packet with TCP flag
 * ACK, FIN or RST set.
 *
 * \param dgram Pointer to data to parse
 * \param datalen Length of the data
 * \return If the TCP if the packet matchs, returns 1. Else, returns 0.
 */
int look_for_tcp_flags(unsigned char *dgram, unsigned int datalen)
{
	struct iphdr *iphdrs = (struct iphdr *) dgram;
	/* check need some data */
	if (datalen < sizeof(struct iphdr) + sizeof(struct tcphdr)) {
		log_area_printf(DEBUG_AREA_PACKET, DEBUG_LEVEL_VERBOSE_DEBUG,
				"Incorrect packet data length");
		return 0;
	}
	/* check IP version */
	if (iphdrs->version == 4) {
		if (iphdrs->protocol == IPPROTO_TCP) {
			struct tcphdr *tcphdrs =
			    (struct tcphdr *) (dgram + 4 * iphdrs->ihl);
			if (tcphdrs->fin || tcphdrs->ack || tcphdrs->rst) {
				RETURN_NO_LOG 1;
			}
		}
	}
	return 0;
}

/**
 * \brief Callback called by NetFilter when a packet with target QUEUE is matched.
 *
 * For TCP packet with flags different than SYN, just send it to NuAuth and
 * accept it.
 *
 * For other packet: First of all, fill a structure ::packet_idl (identifier,
 * timestamp, ...). Try to add the new packet to ::packets_list (fails if the
 * list is full). Ask an authentication to NuAuth using auth_request_send(),
 * If the packet can't be sended, remove it from the list.
 *
 * \return If an error occurs, returns 0, else returns 1.
 */
static int treat_packet(struct nfq_handle *qh, struct nfgenmsg *nfmsg,
			struct nfq_data *nfa, void *data)
{
	packet_idl *current;
	struct queued_pckt q_pckt;
	struct nfqnl_msg_packet_hdr *ph;
	struct timeval timestamp;
	int ret;
#ifdef HAVE_NFQ_INDEV_NAME
	struct nlif_handle *nlif_handle = (struct nlif_handle *) data;
#endif

	debug_log_printf(DEBUG_AREA_PACKET, DEBUG_LEVEL_VERBOSE_DEBUG,
			 "(*) New packet");

	q_pckt.payload_len = nfq_get_payload(nfa, &(q_pckt.payload));
	if (q_pckt.payload_len == -1) {
		log_area_printf(DEBUG_AREA_PACKET, DEBUG_LEVEL_INFO,
				"Unable to get payload");
		return 0;
	}

	q_pckt.mark = nfq_get_nfmark(nfa);

#ifdef HAVE_NFQ_INDEV_NAME
	if (!get_interface_information(nlif_handle, &q_pckt, nfa)) {
		log_area_printf(DEBUG_AREA_PACKET, DEBUG_LEVEL_INFO,
				"Can not get interfaces information for message");
		return 0;
	}
#else
	snprintf(q_pckt.indev, sizeof(q_pckt.indev), "*");
	snprintf(q_pckt.physindev, sizeof(q_pckt.physindev), "*");
	snprintf(q_pckt.outdev, sizeof(q_pckt.outdev), "*");
	snprintf(q_pckt.physoutdev, sizeof(q_pckt.physoutdev), "*");
#endif

	ret = nfq_get_timestamp(nfa, &timestamp);
	if (ret == 0) {
		q_pckt.timestamp = timestamp.tv_sec;
	} else {
		q_pckt.timestamp = time(NULL);
	}

	if (look_for_tcp_flags
	    ((unsigned char *) q_pckt.payload, q_pckt.payload_len)) {
		ph = nfq_get_msg_packet_hdr(nfa);
		if (ph) {
			q_pckt.packet_id = ntohl(ph->packet_id);
			auth_request_send(AUTH_CONTROL, &q_pckt);
			IPQ_SET_VERDICT(q_pckt.packet_id, NF_ACCEPT);
			RETURN_NO_LOG 1;
		} else {
			log_area_printf(DEBUG_AREA_PACKET, DEBUG_LEVEL_VERBOSE_DEBUG,
					"Can not get the packet headers");
			return 0;
		}
	}
	current = calloc(1, sizeof(packet_idl));
	current->nfmark = q_pckt.mark;
	current->timestamp = q_pckt.timestamp ;
	current->id = 0;
	if (current == NULL) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_MESSAGE,
				"Can not allocate packet_id");
		return 0;
	}
#ifdef PERF_DISPLAY_ENABLE
	gettimeofday(&(current->arrival_time), NULL);
#endif
	/* Get unique identifier of packet in queue */
	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		current->id = ntohl(ph->packet_id);
	} else {
		free(current);
		log_area_printf(DEBUG_AREA_PACKET, DEBUG_LEVEL_INFO,
				"Can not get id for message");
		return 0;
	}

	/* Try to add the packet to the list */
	ret = padd(current);
	q_pckt.packet_id = current->id;

	if (ret == 0) {
		/* send an auth request packet */
		if (!auth_request_send(AUTH_REQUEST, &q_pckt)) {
			int sandf = 0;
			/* send failure dropping packet */
			IPQ_SET_VERDICT(q_pckt.packet_id, NF_DROP);
			/* we fail to send the packet so we free packet related to current */
			/* search and destroy packet by packet_id */
			sandf = psearch_and_destroy(q_pckt.packet_id,
						&(q_pckt.mark));

			if (!sandf) {
				log_area_printf(DEBUG_AREA_MAIN,
						DEBUG_LEVEL_WARNING,
						"Packet could not be removed: %u",
						q_pckt.packet_id);
			}
		}
	}
	return 1;
}


/**
 * Open a netlink connection and returns file descriptor
 */
int packetsrv_open(void *data)
{
	log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
			"Opening netfilter queue socket");
	log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
			"[!] Don't forget to load kernel modules nfnetlink and nfnetlink_queue (using modprobe command)");

	/* opening library handle */
	h = nfq_open();
	if (!h) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL,
				"[!] Error during nfq_open()");
		return -1;
	}

	/* unbinding existing nf_queue handler for AF_INET (if any) */
	/* ignoring return, see http://www.spinics.net/lists/netfilter/msg42063.html */
	nfq_unbind_pf(h, AF_INET);

	/* binding nfnetlink_queue as nf_queue handler for AF_INET */
	if (nfq_bind_pf(h, AF_INET) < 0) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL,
				"[!] Error during nfq_bind_pf()");
		return -1;
	}

	if (!nufw_no_ipv6) {
		/* unbinding existing nf_queue handler for AF_INET6 (if any) */
		nfq_unbind_pf(h, AF_INET6);

		/* binding nfnetlink_queue as nf_queue handler for AF_INET6 */
		if (nfq_bind_pf(h, AF_INET6) < 0) {
			log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL,
					"[!] Error during nfq_bind_pf()");
			log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL,
					"Maybe you need to compile NF_NETLINK* kernel options as modules (not built in the kernel!)");
			return -1;
		}
	}

	/* binding this socket to queue number ::nfqueue_num
	 * and install our packet handler */
	hndl = nfq_create_queue(h, nfqueue_num,
			     (nfq_callback *) & treat_packet, data);
	if (!hndl) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL,
				"[!] Error during nfq_create_queue() (queue %d busy ?)",
				nfqueue_num);
		return -1;
	}

	/* setting copy_packet mode */
	if (nfq_set_mode(hndl, NFQNL_COPY_PACKET, 0xffff) < 0) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL,
				"[!] Can't set packet_copy mode");
		return -1;
	}
#ifdef HAVE_NFQ_SET_QUEUE_MAXLEN
	/* setting queue length */
	if (queue_maxlen) {
		if (nfq_set_queue_maxlen(hndl, queue_maxlen) < 0) {
			if (nufw_set_mark) {
				log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL,
						"[!] Can't set queue length, and mark will be set, leaving !");
				exit(EXIT_FAILURE);
			} else {
				log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL,
						"[!] Can't set queue length, continuing anyway");
			}
		}
	}
#endif

	return nfq_fd(h);
}

void packetsrv_close(int smart)
{
	log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_SERIOUS_MESSAGE,
			"Destroy netfilter queue socket");
	if (smart)
		nfq_destroy_queue(hndl);
	nfq_close(h);
}

static void iface_activity_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	struct nlif_handle *nlif_handle = w->data;
	ev_io_stop(loop, w);
	if (revents & EV_ERROR) {
		int if_fd;
		iface_table_close(nlif_handle);

		nlif_handle = iface_table_open();
		if (!nlif_handle)
			exit(EXIT_FAILURE);

		if_fd = nlif_fd(nlif_handle);
		if (if_fd < 0) {
			exit(EXIT_FAILURE);
		}
		ev_io_set(w, if_fd, EV_READ);
	}
	if (revents & EV_READ) {
		iface_treat_message(nlif_handle);
	}
	ev_io_start(loop, w);
}

static void packetsrv_activity_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	if (revents & EV_READ) {
		unsigned char buffer[BUFSIZ];
		int rv;
		int fd = nfq_fd(h);
		/* read one packet */
		rv = recv(fd, buffer, sizeof(buffer), 0);
		if (rv < 0) {
			struct nlif_handle *nlif_handle = (struct nlif_handle *) w->data;
			log_area_printf(DEBUG_AREA_MAIN,
					DEBUG_LEVEL_WARNING,
					"[!] Error of read on netfilter queue socket (code %i)!",
					rv);
			log_area_printf(DEBUG_AREA_MAIN,
					DEBUG_LEVEL_SERIOUS_MESSAGE,
					"Reopen netlink connection.");
			packetsrv_close(0);
#ifdef HAVE_NFQ_INDEV_NAME
			fd = packetsrv_open(nlif_handle);
#else
			fd = packetsrv_open(NULL);
#endif
			if (fd < 0) {
				log_area_printf(DEBUG_AREA_MAIN,
						DEBUG_LEVEL_CRITICAL,
						"[!] FATAL ERROR: Fail to reopen netlink connection!");
				exit(EXIT_FAILURE);
			}
			ev_io_set(w, fd, EV_READ);
			ev_io_start(loop, w);
			return;
		}

		ev_io_stop(loop, &tls.ev_io);
		/* process the packet */
		nfq_handle_packet(h, (char *) buffer, rv);
		pckt_rx++;
		ev_io_start(loop, &tls.ev_io);
	}

	if (revents & EV_ERROR) {
		struct nlif_handle *nlif_handle = (struct nlif_handle *) w->data;
		int fd;
		packetsrv_close(0);
		ev_io_stop(loop, w);
#ifdef HAVE_NFQ_INDEV_NAME
		fd = packetsrv_open(nlif_handle);
#else
		fd = packetsrv_open(NULL);
#endif
		ev_io_set(w, fd, EV_READ);
		ev_io_start(loop, w);
	}
}

static void tls_activity_cb(struct ev_loop *loop, ev_io *w, int revents) {
	ev_io *nfq_watcher = (ev_io *) w->data;
	if (revents & EV_READ) {
		ev_io_stop(loop, w);
		ev_io_stop(loop, nfq_watcher);
		/* FIXME correct function type here */
		authsrv(NULL);
		ev_io_start(loop, nfq_watcher);
		if (tls.session) {
			ev_io_start(loop, w);
		}
	}

	if (revents & EV_ERROR) {
		tls.auth_server_running = 0;
	}
}

int p_pckt_rx;
int p_pckt_tx;

static void cleaning_timer_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	int stat_rx, stat_tx;

	ev_io *nfq_watcher = (ev_io *) w->data;
	ev_io_stop(loop, &tls.ev_io);
	ev_io_stop(loop, nfq_watcher);
	clean_old_packets();
	ev_io_start(loop, nfq_watcher);
	ev_io_start(loop, &tls.ev_io);
#ifdef DEBUG_ENABLE
	/* display stats */
	/* FIXME : modify this function */
	/*
	process_poll(0);
	*/
	stat_rx = pckt_rx - p_pckt_rx;
	p_pckt_rx = pckt_rx;

	stat_tx = pckt_rx - p_pckt_rx;
	p_pckt_rx = pckt_rx;

	log_area_printf(DEBUG_AREA_MAIN | DEBUG_AREA_PACKET,
			DEBUG_LEVEL_DEBUG,
			"Average: rx=%.2f, tx=%.2f",
			(1.0 * stat_rx) / CLEANING_DELAY,
			(1.0 * stat_tx) / CLEANING_DELAY);
#endif
}

/**
 * \brief Packet server thread function.
 *
 * Connect to netfilter to ask a netlink. Read packet
 * on this link. Check if packet useful for NuFW. If yes, add it to packet
 * list and/or send it to NuAuth.
 *
 * When using NetFilter queue, it uses treat_packet() as callback.
 * In ipq mode it uses an internal packet parser and process mechanism.
 *
 * \return NULL
 */
void *packetsrv(void *void_arg)
{
	int fatal_error = 0;
	ev_io iface_watcher;
	ev_io nfq_watcher;
	ev_timer timer;
	struct ev_loop *loop;
	int fd;
#ifdef HAVE_NFQ_INDEV_NAME
	struct nlif_handle *nlif_handle;
	int if_fd;
#endif

#ifdef HAVE_NFQ_INDEV_NAME
	nlif_handle = iface_table_open();

	if (!nlif_handle)
		exit(EXIT_FAILURE);

	if_fd = nlif_fd(nlif_handle);
	if (if_fd < 0) {
		exit(EXIT_FAILURE);
	}

	fd = packetsrv_open((void *) nlif_handle);
#else
	fd = packetsrv_open(NULL);
#endif

	if (fd < 0) {
		exit(EXIT_FAILURE);
	}

	log_area_printf(DEBUG_AREA_MAIN | DEBUG_AREA_PACKET, DEBUG_LEVEL_DEBUG,
			"[+] Packet server started");

	loop = ev_loop_new(0);
	/* add io for nfq */
	ev_io_init(&nfq_watcher , packetsrv_activity_cb, fd, EV_READ);
	nfq_watcher.data = nlif_handle;
	ev_io_start(loop, &nfq_watcher);
#ifdef HAVE_NFQ_INDEV_NAME
	/* add io for iface */
	ev_io_init(&iface_watcher , iface_activity_cb, if_fd, EV_READ);
	iface_watcher.data = nlif_handle;
	ev_io_start(loop, &iface_watcher);
#endif
	ev_io_init(&tls.ev_io, tls_activity_cb,
		   nussl_session_get_fd(tls.session), EV_READ);
	tls.ev_io.data = &nfq_watcher;
	ev_io_start(loop, &tls.ev_io);

	p_pckt_rx = 0;
	p_pckt_tx = 0;
	ev_timer_init(&timer, cleaning_timer_cb, 0, 1.0 * CLEANING_DELAY);
	timer.data = &nfq_watcher;
	ev_timer_start(loop, &timer);

	/* start loop */
	ev_loop(loop, 0);

	ev_loop_destroy(loop);


#ifdef HAVE_NFQ_INDEV_NAME
	iface_table_close(nlif_handle);
#endif

	packetsrv_close(!fatal_error);

	log_area_printf(DEBUG_AREA_MAIN | DEBUG_AREA_PACKET,
			DEBUG_LEVEL_WARNING,
			"[+] Leave packet server thread");
	return NULL;
}

/**
 * Halt TLS threads and close socket
 */
void shutdown_tls()
{
	if (!tls.auth_server_running)
		return;

	log_area_printf(DEBUG_AREA_GW, DEBUG_LEVEL_CRITICAL,
			"tls send failure when sending request");

	close_tls_session();

	/* put auth_server_running to 0 because this is this thread which has
	 * just killed auth_server */
	tls.auth_server_running = 0;
}

/**
 * Send an authentication request to NuAuth. May restart TLS session
 * and/or open TLS connection (if closed).
 *
 * Create the thread authsrv() when opening a new session.
 *
 * Packet maximum size is 512 bytes,
 * and it's structure is ::nufw_to_nuauth_auth_message_t.
 *
 * \param type Type of request (::AUTH_REQUEST, ::AUTH_CONTROL, ...)
 * \param pckt_data A pointer to a queued_pckt:: holding packet information
 * \return If an error occurs returns 0, else return 1.
 */
int auth_request_send(uint8_t type, struct queued_pckt *pckt_data)
{
	unsigned char data[512];
	nuv4_nufw_to_nuauth_auth_message_t *msg_header =
	    (nuv4_nufw_to_nuauth_auth_message_t *) & data;
	unsigned char *msg_content =
	    data + sizeof(nuv4_nufw_to_nuauth_auth_message_t);
	int msg_length;

	/* Drop non-IPv(4|6) packet */
	if ((((struct iphdr *) (pckt_data->payload))->version != 4)
	    && (((struct iphdr *) (pckt_data->payload))->version != 6)) {
		log_area_printf(DEBUG_AREA_PACKET, DEBUG_LEVEL_DEBUG,
				 "Dropping non-IPv4/non-IPv6 packet (version %u)",
				 ((struct iphdr *) (pckt_data->payload))->
				 version);
		return 0;
	}

	/* Truncate packet content if needed */
	if (sizeof(data) <
	    sizeof(nuv4_nufw_to_nuauth_auth_message_t) + pckt_data->payload_len) {
		debug_log_printf(DEBUG_AREA_PACKET, DEBUG_LEVEL_DEBUG,
				 "Very long packet: truncating!");
		pckt_data->payload_len =
		    sizeof(data) -
		    sizeof(nuv4_nufw_to_nuauth_auth_message_t);
	}
	msg_length = sizeof(nuv4_nufw_to_nuauth_auth_message_t) + pckt_data->payload_len;

	/* Fill message header */
	msg_header->protocol_version = PROTO_NUFW_VERSION;
	msg_header->msg_type = type;
	msg_header->msg_length = htons(msg_length);
	msg_header->packet_id = htonl(pckt_data->packet_id);
	msg_header->timestamp = htonl(pckt_data->timestamp);

	/* Add info about interfaces */
	msg_header->mark = pckt_data->mark;
	memcpy(msg_header->indev, pckt_data->indev,
	       IFNAMSIZ * sizeof(char));
	memcpy(msg_header->outdev, pckt_data->outdev,
	       IFNAMSIZ * sizeof(char));
	memcpy(msg_header->physindev, pckt_data->physindev,
	       IFNAMSIZ * sizeof(char));
	memcpy(msg_header->physoutdev, pckt_data->physoutdev,
	       IFNAMSIZ * sizeof(char));

	/* Copy (maybe truncated) packet content */
	memcpy(msg_content, pckt_data->payload, pckt_data->payload_len);

	/* Display message */
	log_area_printf(DEBUG_AREA_PACKET, DEBUG_LEVEL_DEBUG,
			"Sending request for %lu", (long)pckt_data->packet_id);

	/* negotiate TLS connection if needed */
	if (!tls.session) {
		log_area_printf(DEBUG_AREA_GW, DEBUG_LEVEL_INFO,
				"Not connected, trying TLS connection");
		tls_connect();

		if (tls.session) {
			char buf[256];
			buf[0] = '\0';
			nussl_session_get_cipher(tls.session, buf, sizeof(buf));
			log_area_printf(DEBUG_AREA_GW,
					DEBUG_LEVEL_WARNING,
					"[+] TLS connection to nuauth restored (%s:%d), cipher is %s",
					authreq_addr, authreq_port,
					(buf[0] != '\0') ? buf : "none" );

		} else {
			log_area_printf(DEBUG_AREA_GW,
					DEBUG_LEVEL_WARNING,
					"[!] TLS connection to nuauth can NOT be restored (%s:%d)",
					authreq_addr, authreq_port);
			return 0;
		}
	}

	if (nussl_write(tls.session, (char*)data, msg_length) < 0) {
		debug_log_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
				 "Error during nussl_write (auth_request_send).");
		shutdown_tls();
		log_area_printf(DEBUG_AREA_GW,
				DEBUG_LEVEL_WARNING,
				"[!] TLS send failure");
		return 0;
	}
	return 1;
}


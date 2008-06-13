/*
 ** Copyright (C) 2002-2008 INL
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

#ifdef USE_NFQUEUE
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
	pthread_mutex_lock(&packets_list.mutex);
	q_pckt.packet_id = padd(current);
	pthread_mutex_unlock(&packets_list.mutex);

	if (q_pckt.packet_id) {
		/* send an auth request packet */
		if (!auth_request_send(AUTH_REQUEST, &q_pckt)) {
			int sandf = 0;
			/* send failure dropping packet */
			IPQ_SET_VERDICT(q_pckt.packet_id, NF_DROP);
			/* we fail to send the packet so we free packet related to current */
			pthread_mutex_lock(&packets_list.mutex);
			/* search and destroy packet by packet_id */
			sandf =
			    psearch_and_destroy(q_pckt.packet_id,
						&(q_pckt.mark));
			pthread_mutex_unlock(&packets_list.mutex);

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
	struct nfnl_handle *nh;

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

	/* unbinding existing nf_queue handler for AF_INET6 (if any) */
	nfq_unbind_pf(h, AF_INET6);

	/* binding nfnetlink_queue as nf_queue handler for AF_INET6 */
	if (nfq_bind_pf(h, AF_INET6) < 0) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL,
				"[!] Error during nfq_bind_pf()");
		return -1;
	}

	/* binding this socket to queue number ::nfqueue_num
	 * and install our packet handler */
	hndl =
	    nfq_create_queue(h, nfqueue_num,
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

	nh = nfq_nfnlh(h);
	return nfnl_fd(nh);
}

void packetsrv_close(int smart)
{
	log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_SERIOUS_MESSAGE,
			"Destroy netfilter queue socket");
	if (smart)
		nfq_destroy_queue(hndl);
	nfq_close(h);
}

#else				/* USE_NFQUEUE */

/**
 * Process an IP message received from IPQ
 * \return Returns 1 if it's ok, 0 otherwise.
 */
void packetsrv_ipq_process(unsigned char *buffer)
{
	ipq_packet_msg_t *msg_p = NULL;
	packet_idl *current;
	struct queued_pckt q_pckt;
	uint32_t pcktid;

	pckt_rx++;
	/* printf("Working on IP packet\n"); */
	msg_p = ipq_get_packet(buffer);
	q_pckt.packet_id = msg_p->packet_id;
	q_pckt.payload = (char *) msg_p->payload;
	q_pckt.payload_len = msg_p->data_len;
	/* need to parse to see if it's an end connection packet */
	if (look_for_tcp_flags(msg_p->payload, msg_p->data_len)) {
		auth_request_send(AUTH_CONTROL, &q_pckt);
		IPQ_SET_VERDICT(msg_p->packet_id, NF_ACCEPT);
		RETURN_NO_LOG;
	}

	/* Create packet */
	current = calloc(1, sizeof(packet_idl));
	if (current == NULL) {
		/* no more memory: drop packet and exit */
		IPQ_SET_VERDICT(msg_p->packet_id, NF_DROP);
		log_area_printf(DEBUG_AREA_MAIN | DEBUG_AREA_PACKET,
				DEBUG_LEVEL_SERIOUS_WARNING,
				"[+] Can not allocate packet_id (drop packet)");
		return;
	}
	current->id = msg_p->packet_id;
	current->timestamp = msg_p->timestamp_sec;
#ifdef HAVE_LIBIPQ_MARK
	current->nfmark = msg_p->mark;
#endif

	/* Adding packet to list */
	pthread_mutex_lock(&packets_list.mutex);
	pcktid = padd(current);
	pthread_mutex_unlock(&packets_list.mutex);
	if (!pcktid) {
		log_area_printf(DEBUG_AREA_MAIN | DEBUG_AREA_PACKET,
				DEBUG_LEVEL_VERBOSE_DEBUG,
				"Can not add packet to packet list (so already dropped): exit");
		return;
	}

	/* send an auth request packet */
	if (!auth_request_send(AUTH_REQUEST, &q_pckt)) {
		int sandf = 0;
		/* we fail to send the packet so we free packet related to current */
		pthread_mutex_lock(&packets_list.mutex);
		/* search and destroy packet by packet_id */
		sandf =
		    psearch_and_destroy(msg_p->packet_id,
					(uint32_t *) & msg_p->mark);
		pthread_mutex_unlock(&packets_list.mutex);

		if (!sandf) {
			log_area_printf(DEBUG_AREA_MAIN,
					DEBUG_LEVEL_WARNING,
					"Packet could not be removed: %lu",
					msg_p->packet_id);
		}
	}
}
#endif				/* USE_NFQUEUE */

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
	struct nufw_threadargument *thread_arg = void_arg;
	struct nufw_threadtype *this = thread_arg->thread;
	int fatal_error = 0;
#ifdef USE_NFQUEUE
	unsigned char buffer[BUFSIZ];
	struct timeval tv;
	int fd;
#ifdef HAVE_NFQ_INDEV_NAME
	struct nlif_handle *nlif_handle;
	int if_fd;
#endif
	int rv;
	int select_result;
	int max_fd;
	fd_set wk_set;

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

	/* loop until main process ask to stop */
	while (pthread_mutex_trylock(&this->mutex) == 0) {
		pthread_mutex_unlock(&this->mutex);

		/* Set timeout: one second */
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		/* wait new event on socket */
		FD_ZERO(&wk_set);
		FD_SET(fd, &wk_set);
#ifdef HAVE_NFQ_INDEV_NAME
		FD_SET(if_fd, &wk_set);

		if (fd >= if_fd) {
			max_fd = fd + 1;
		} else {
			max_fd = if_fd + 1;
		}
#else
		max_fd = fd + 1;
#endif

		select_result = select(max_fd, &wk_set, NULL, NULL, &tv);
		if (select_result == -1) {
			int err = errno;
			if (err == EINTR) {
				continue;
			}

			if (err == EBADF) {
				struct stat s;
#ifdef HAVE_NFQ_INDEV_NAME
				if ((fstat(if_fd, &s)<0)) {
					iface_table_close(nlif_handle);

					nlif_handle = iface_table_open();
					if (!nlif_handle)
						exit(EXIT_FAILURE);

					if_fd = nlif_fd(nlif_handle);
					if (if_fd < 0) {
						exit(EXIT_FAILURE);
					}
				}
#endif
				if ((fstat(fd, &s)<0)) {
					packetsrv_close(0);
#ifdef HAVE_NFQ_INDEV_NAME
					fd = packetsrv_open(nlif_handle);
#else
					fd = packetsrv_open(NULL);
#endif
				}
				continue;
			}
			log_area_printf(DEBUG_AREA_MAIN,
					DEBUG_LEVEL_CRITICAL,
					"[!] FATAL ERROR: Error of select() in netfilter queue thread (code %i)!",
					err);
			fatal_error = 1;
			break;
		}

		/* catch timeout */
		if (select_result == 0) {
			/* timeout! */
			continue;
		}
#ifdef HAVE_NFQ_INDEV_NAME
		if (FD_ISSET(if_fd, &wk_set)) {
			iface_treat_message(nlif_handle);
			continue;
		}
#endif
		/* read one packet */
		rv = recv(fd, buffer, sizeof(buffer), 0);
		if (rv < 0) {
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
				fatal_error = 1;
				break;
			}
			continue;
		}

		/* process the packet */
		nfq_handle_packet(h, (char *) buffer, rv);
		pckt_rx++;
	}

#ifdef HAVE_NFQ_INDEV_NAME
	iface_table_close(nlif_handle);
#endif


	packetsrv_close(!fatal_error);
#else				/* USE_NFQUEUE */
	unsigned char buffer[BUFSIZ];
	int size;

	log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_MESSAGE,
			"Try to connect to netlink (IPQ)");
	log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_SERIOUS_WARNING,
			"Don't forget to load Linux kernel module ip_queue (using modprobe command)");

	/* init netlink connection */
	hndl = ipq_create_handle(0, PF_INET);
	if (!hndl) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL,
				"[!] FATAL ERROR: Could not create ipq handle!");
		kill(thread_arg->parent_pid, SIGTERM);
		pthread_exit(NULL);
	}

	ipq_set_mode(hndl, IPQ_COPY_PACKET, BUFSIZ);

	log_area_printf(DEBUG_AREA_MAIN | DEBUG_AREA_PACKET, DEBUG_LEVEL_FATAL,
			"[+] Packet server started");

	/* loop until main process ask this thread to stop using its mutex */
	while (pthread_mutex_trylock(&this->mutex) != EBUSY) {
		pthread_mutex_unlock(&this->mutex);

		/* wait netfilter event with a timeout of one second */
		size = ipq_read(hndl, buffer, sizeof(buffer), 1000000);

		/* is timeout recheaded */
		if (size == 0) {
			continue;
		}

		/* Check buffer size */
		if (size == -1) {
			log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
					"BUFSIZ too small (size == %d)",
					size);
			continue;
		}
		if (BUFSIZ <= size) {
			log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
					"BUFSIZ too small (size == %d)",
					size);
			continue;
		}

		/* skip message different than packets */
		if (ipq_message_type(buffer) != IPQM_PACKET) {
			/* if it's an error, display it and stop NuFW !!! */
			if (ipq_message_type(buffer) == NLMSG_ERROR) {
				log_area_printf(DEBUG_AREA_MAIN,
						DEBUG_LEVEL_CRITICAL,
						"[!] FATAL ERROR: libipq error (code %d)!",
						ipq_get_msgerr(buffer));
				fatal_error = 1;
				break;
			}
			continue;
		}

		/* process packet */
		packetsrv_ipq_process(buffer);
	}
	ipq_destroy_handle(hndl);
#endif
	log_area_printf(DEBUG_AREA_MAIN | DEBUG_AREA_PACKET,
			DEBUG_LEVEL_WARNING,
			"[+] Leave packet server thread");
	if (fatal_error) {
		kill(thread_arg->parent_pid, SIGTERM);
	}
	pthread_exit(NULL);
}

/**
 * Halt TLS threads and close socket
 */
void shutdown_tls()
{
	log_area_printf(DEBUG_AREA_GW, DEBUG_LEVEL_CRITICAL,
			"tls send failure when sending request");
	pthread_mutex_lock(&tls.mutex);

	pthread_cancel(tls.auth_server);

	close_tls_session();

	/* put auth_server_running to 1 because this is this thread which has
	 * just killed auth_server */
	tls.auth_server_running = 1;

	pthread_mutex_unlock(&tls.mutex);
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
 * \param pckt_datas A pointer to a queued_pckt:: holding packet information
 * \return If an error occurs returns 0, else return 1.
 */
int auth_request_send(uint8_t type, struct queued_pckt *pckt_datas)
{
	unsigned char datas[512];
	nuv4_nufw_to_nuauth_auth_message_t *msg_header =
	    (nuv4_nufw_to_nuauth_auth_message_t *) & datas;
	unsigned char *msg_content =
	    datas + sizeof(nuv4_nufw_to_nuauth_auth_message_t);
	int msg_length;

	/* Drop non-IPv(4|6) packet */
	if ((((struct iphdr *) (pckt_datas->payload))->version != 4)
	    && (((struct iphdr *) (pckt_datas->payload))->version != 6)) {
		log_area_printf(DEBUG_AREA_PACKET, DEBUG_LEVEL_DEBUG,
				 "Dropping non-IPv4/non-IPv6 packet (version %u)",
				 ((struct iphdr *) (pckt_datas->payload))->
				 version);
		return 0;
	}

	/* Truncate packet content if needed */
	if (sizeof(datas) <
	    sizeof(nuv4_nufw_to_nuauth_auth_message_t) +
	    pckt_datas->payload_len) {
		debug_log_printf(DEBUG_AREA_PACKET, DEBUG_LEVEL_DEBUG,
				 "Very long packet: truncating!");
		pckt_datas->payload_len =
		    sizeof(datas) -
		    sizeof(nuv4_nufw_to_nuauth_auth_message_t);
	}
	msg_length =
	    sizeof(nuv4_nufw_to_nuauth_auth_message_t) +
	    pckt_datas->payload_len;

	/* Fill message header */
	msg_header->protocol_version = PROTO_NUFW_VERSION;
	msg_header->msg_type = type;
	msg_header->msg_length = htons(msg_length);
	msg_header->packet_id = htonl(pckt_datas->packet_id);
	msg_header->timestamp = htonl(pckt_datas->timestamp);

	/* Add info about interfaces */
	msg_header->mark = pckt_datas->mark;
	memcpy(msg_header->indev, pckt_datas->indev,
	       IFNAMSIZ * sizeof(char));
	memcpy(msg_header->outdev, pckt_datas->outdev,
	       IFNAMSIZ * sizeof(char));
	memcpy(msg_header->physindev, pckt_datas->physindev,
	       IFNAMSIZ * sizeof(char));
	memcpy(msg_header->physoutdev, pckt_datas->physoutdev,
	       IFNAMSIZ * sizeof(char));

	/* Copy (maybe truncated) packet content */
	memcpy(msg_content, pckt_datas->payload, pckt_datas->payload_len);

	/* Display message */
	log_area_printf(DEBUG_AREA_PACKET, DEBUG_LEVEL_DEBUG,
			"Sending request for %lu", (long)pckt_datas->packet_id);

	/* cleaning up current session : auth_server has detected a problem */
	pthread_mutex_lock(&tls.mutex);
	if ((tls.auth_server_running == 0) && tls.session != NULL) {
		close_tls_session();
	}

	pthread_mutex_unlock(&tls.mutex);

	/* negotiate TLS connection if needed */
	if (!tls.session) {
		log_area_printf(DEBUG_AREA_GW, DEBUG_LEVEL_INFO,
				"Not connected, trying TLS connection");
		tls.session = tls_connect();

		if (tls.session) {
			pthread_attr_t attr;
			pthread_attr_init(&attr);
			pthread_attr_setdetachstate(&attr,
						    PTHREAD_CREATE_JOINABLE);

			log_area_printf(DEBUG_AREA_GW,
					DEBUG_LEVEL_WARNING,
					"[+] TLS connection to nuauth restored");

			/* create joinable thread for auth server */
			pthread_mutex_init(&tls.auth_server_mutex, NULL);
			if (pthread_create
			    (&tls.auth_server, &attr, authsrv,
			     NULL) == EAGAIN) {
				exit(EXIT_FAILURE);
			}
			tls.auth_server_running = 1;
		} else {
			log_area_printf(DEBUG_AREA_GW,
					DEBUG_LEVEL_WARNING,
					"[!] TLS connection to nuauth can NOT be restored");
			return 0;
		}
	}

	/* send packet */
	pthread_mutex_lock(&tls.mutex);

	if (nussl_write(tls.session, (char*)datas, msg_length) < 0) {
		debug_log_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
				 "Error during nussl_write.");
		shutdown_tls();
		pthread_mutex_unlock(&tls.mutex);
		log_area_printf(DEBUG_AREA_GW,
				DEBUG_LEVEL_WARNING,
				"[!] TLS send failure");
		return 0;
	}
	pthread_mutex_unlock(&tls.mutex);
	return 1;
}


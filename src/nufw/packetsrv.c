/*
 ** Copyright (C) 2002-2005 Eric Leblond <eric@regit.org>
 **		      Vincent Deffontaines <vincent@gryzor.com>
 **                    INL http://www.inl.fr/
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

#include "nufw.h"

/**
 * Parse an packet and check if it's TCP in IPv4 packet with TCP flag
 * ACK, FIN or RST set.
 *
 * \return If the TCP if the packet matchs, returns 1. Else, returns 0.
 */
int look_for_tcp_flags(unsigned char* dgram,int datalen){
	struct iphdr * iphdrs = (struct iphdr *) dgram;
	/* check need some datas */    
	if (datalen < sizeof(struct iphdr) +sizeof(struct tcphdr)){
		return 0;
	}
	/* check IP version */
	if (iphdrs->version == 4){
		if ( iphdrs->protocol == IPPROTO_TCP){
			struct tcphdr * tcphdrs=(struct tcphdr *) (dgram+4*iphdrs->ihl);
			if (tcphdrs->fin || tcphdrs->ack || tcphdrs->rst ){
				return 1;
			}
		}
	}
	return 0;
}

#if USE_NFQUEUE
/**
 * Callback called by NetFilter when a packet with target QUEUE is matched.
 *
 * For TCP packet with flags different than SYN, just send it to NuAuth and
 * accept it.
 * 
 * For other packet: First of all, fill a structure ::packet_idl (identifier,
 * timestamp, ...). Try to add the new packet to ::packets_list (fails if the
 * list is full). Ask an authentification to NuAuth using auth_request_send(),
 * If the packet can't be sended, remove it from the list.
 *
 * \return If an error occurs, returns 0, else returns 1.
 */
static int treat_packet(struct nfq_handle *qh, struct nfgenmsg *nfmsg,
		struct nfq_data *nfa, void *data)
{
	packet_idl * current;
	uint32_t pcktid;
	uint32_t c_mark;
	char *payload;
	int payload_len;
	struct nfqnl_msg_packet_hdr *ph;
	struct timeval timestamp;
	int ret;

	payload_len =  nfq_get_payload(nfa,&payload);
	if (payload_len == -1){
		return 0;
	}

	if (look_for_tcp_flags(payload,payload_len)){
		ph = nfq_get_msg_packet_hdr(nfa);
		if (ph){
			pcktid = ntohl(ph->packet_id);
			auth_request_send(AUTH_CONTROL,
					pcktid,
					payload,payload_len);
			IPQ_SET_VERDICT(pcktid,NF_ACCEPT);
			return 1;
		} else {
			return 0;
		}
	} 
	current=calloc(1,sizeof( packet_idl));
	current->id=0;
	if (current == NULL){
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_MESSAGE,
                "Can not allocate packet_id");
		return 0;
	}

    /* Get unique identifier of packet in queue */
	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph){
		current->id= ntohl(ph->packet_id);
	} else {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_MESSAGE,
                "Can not get id for message");
		free(current);
		return 0;
	}

	current->nfmark=nfq_get_nfmark(nfa);

	ret = nfq_get_timestamp(nfa, &timestamp);
	if (ret == 0){
		current->timestamp=timestamp.tv_sec;
	}else {
        debug_log_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_MESSAGE,
                "Can not get timestamp for message");
		current->timestamp=time(NULL);
	}

	/* Try to add the packet to the list */
	pthread_mutex_lock(&packets_list.mutex);
	pcktid=padd(current);
	pthread_mutex_unlock(&packets_list.mutex);

	if (pcktid){
		/* send an auth request packet */
		if (! auth_request_send(AUTH_REQUEST,pcktid,payload,payload_len)){
			int sandf=0;
			/* we fail to send the packet so we free packet related to current */
			pthread_mutex_lock(&packets_list.mutex);
			/* search and destroy packet by packet_id */
			sandf = psearch_and_destroy (pcktid,&c_mark);
			pthread_mutex_unlock(&packets_list.mutex);

			if (!sandf){
                log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING, \
                        "Packet could not be removed: %u", pcktid);
			}
		}
	}
	return 1;
}
#endif

/**
 * Packet server thread. Connect to netfilter to ask a netlink. Read packet
 * on this link. Check if packet useful for NuFW. If yes, add it to packet 
 * list and/or send it to NuAuth.
 *
 * When using NetFilter queue, use treat_packet() callback.
 * Else, use internal packet parser and process mechanism.
 *
 * \return NULL
 */
void* packetsrv(void *data)
{
	unsigned char buffer[BUFSIZ];
#if USE_NFQUEUE
	int fd;
	int rv;
	struct nfnl_handle *nh;

	h = nfq_open();
	if (!h) {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL, 
                "Error during nfq_open()");
		exit(EXIT_FAILURE);
	}

	if (nfq_unbind_pf(h, AF_INET) < 0) {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL, 
                "Error during nfq_unbind_pf()");
		exit(EXIT_FAILURE);
	}

	if (nfq_bind_pf(h, AF_INET) < 0) {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL, 
                "Error during nfq_bind_pf()");
		exit(EXIT_FAILURE);
	}
        
        
	hndl = nfq_create_queue(h,  nfqueue_num, (nfq_callback *)&treat_packet, NULL);
	if (!hndl) {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL,
                "Error during nfq_create_queue() (queue %d busy ?)",
                nfqueue_num);
		exit(EXIT_FAILURE);
	}

	if (nfq_set_mode(hndl, NFQNL_COPY_PACKET, 0xffff) < 0) {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL,
                "Can't set packet_copy mode");
		exit(EXIT_FAILURE);
	}

	nh = nfq_nfnlh(h);
	fd = nfnl_fd(nh);
#else
	size_t size;
	uint32_t pcktid;
	ipq_packet_msg_t *msg_p = NULL ;
	packet_idl * current;
	/* init netlink connection */
	hndl = ipq_create_handle(0,PF_INET);
	if (hndl)
		ipq_set_mode(hndl, IPQ_COPY_PACKET,BUFSIZ);  
	else {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL,
                "Could not create ipq handle");
	}
#endif
	for (;;){
#if USE_NFQUEUE
		if ((rv = recv(fd, buffer, sizeof(buffer), 0)) && rv >= 0) {
			nfq_handle_packet(h, buffer, rv);
			pckt_rx++ ;
		} else 
			break;
#else
		size = ipq_read(hndl,buffer,sizeof(buffer),0);
		if (size != -1){
			if (size < BUFSIZ ){
				if (ipq_message_type(buffer) == NLMSG_ERROR ){
                    log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_MESSAGE, 
                            "Got error message from libipq: %d",
                            ipq_get_msgerr(buffer));
				} else {
					if ( ipq_message_type (buffer) == IPQM_PACKET ) {
						pckt_rx++ ;
						/* printf("Working on IP packet\n"); */
						msg_p = ipq_get_packet(buffer);
						/* need to parse to see if it's an end connection packet */
						if (look_for_tcp_flags(msg_p->payload,msg_p->data_len)){
							auth_request_send(AUTH_CONTROL,msg_p->packet_id,(char*)msg_p->payload,msg_p->data_len);
							IPQ_SET_VERDICT( msg_p->packet_id,NF_ACCEPT);
						} else {
                            /* Create packet */
							current=calloc(1,sizeof( packet_idl));
							if (current == NULL){
                                log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_MESSAGE,
                                        "Can not allocate packet_id");
								return NULL;
							}
							current->id=msg_p->packet_id;
							current->timestamp=msg_p->timestamp_sec;
#ifdef HAVE_LIBIPQ_MARK
							current->nfmark=msg_p->mark;
#endif

							/* Adding packet to list  */
							pthread_mutex_lock(&packets_list.mutex);
							pcktid=padd(current);
							pthread_mutex_unlock(&packets_list.mutex);

							if (pcktid){
								/* send an auth request packet */
								if (! auth_request_send(AUTH_REQUEST,msg_p->packet_id,(char*)msg_p->payload,msg_p->data_len)){
									int sandf=0;
									/* we fail to send the packet so we free packet related to current */
									pthread_mutex_lock(&packets_list.mutex);
									/* search and destroy packet by packet_id */
									sandf = psearch_and_destroy (msg_p->packet_id,(uint32_t*)&msg_p->mark);
									pthread_mutex_unlock(&packets_list.mutex);

									if (!sandf){
                                        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
                                                "Packet could not be removed: %lu", 
                                                msg_p->packet_id);
									}
								}
							}
						}
					} else {
                        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG, 
                                "Dropping non-IP packet");
						IPQ_SET_VERDICT(msg_p->packet_id, NF_DROP);
					}
				}
			}
		} else {
            log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
                    "BUFSIZ too small (size == %d)", size);
		}
#endif
	}
#if USE_NFQUEUE
#else
	ipq_destroy_handle( hndl );  
#endif
	return NULL;
}   


/**
 * Send an authentication request to NuAuth.
 *
 * \param type Type of request
 * \param packet_id Unique identifier of the packet in netfilter queue
 * \param payload Packet content
 * \param data_len Size of payload (in bytes)
 */
int auth_request_send(uint8_t type,uint32_t packet_id,char* payload,int data_len){
	char datas[512];
	char *pointer;
	int auth_len,total_data_len=512;
	uint8_t version=PROTO_VERSION;
	uint16_t dataslen=data_len+12;
	long timestamp;

	timestamp = time(NULL);

	packet_id=htonl(packet_id);
	dataslen=htons(dataslen);
	timestamp=htonl(timestamp);

	if ( ((struct iphdr *)payload)->version == 4) {
		memset(datas,0,sizeof datas);
		memcpy(datas,&version,sizeof version);
		pointer=datas+sizeof version;
		memcpy(pointer,&type,sizeof type);
		pointer+=sizeof type;
		memcpy(pointer,&dataslen,sizeof dataslen);
		pointer+=sizeof dataslen;
		memcpy(pointer,&packet_id,sizeof packet_id);
		pointer+=sizeof packet_id;
		memcpy(pointer,&timestamp,sizeof timestamp);
		pointer+=sizeof timestamp;
		auth_len=pointer-datas;

		/* memcpy header to datas + offset */
		if (data_len<512-auth_len) {
			memcpy(pointer,payload,data_len);
			total_data_len=data_len+auth_len;
		} else {
            debug_log_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG, 
                    "Very long packet: truncating!");
			memcpy(pointer,payload,511-auth_len);
		}

	} else {
        debug_log_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG, "Dropping non-IP packet");
		return 0;
	}
    debug_log_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG, 
            "Sending request for %u", ntohl(packet_id));
    
    /* cleaning up current session : auth_server has detected a problem */
    pthread_mutex_lock(tls.mutex);
    if ((tls.auth_server_running == 0) && tls.session) {
        int socket_tls = (int)gnutls_transport_get_ptr(*tls.session);
        gnutls_bye(*tls.session,GNUTLS_SHUT_WR);
        gnutls_deinit(*tls.session);
        shutdown(socket_tls,SHUT_RDWR);
        close(socket_tls);
        free(tls.session);
        tls.session = NULL;
    }
    pthread_mutex_unlock(tls.mutex);
    
	/* negotiate TLS connection if needed */
	if (!tls.session){
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_INFO, 
                "Not connected, trying TLS connection");
		tls.session = tls_connect();

		if (tls.session){
            log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
                    "Connection to nuauth restored");
			tls.auth_server_running=1;
            /* create thread for auth server */
            if (pthread_create(&(tls.auth_server),NULL,authsrv,NULL) == EAGAIN){
                exit(EXIT_FAILURE);
            }
#ifdef HAVE_LIBCONNTRACK
            if (handle_conntrack_event){
                if (pthread_create(&(tls.conntrack_event_handler),NULL,conntrack_event_handler,NULL) == EAGAIN){
                    exit(EXIT_FAILURE);
                }
            }
#endif
        } else {
            return 0;
        }
	}
    
	/* send packet */
	if (!gnutls_record_send(*(tls.session),datas,total_data_len)){
		int socket_tls;
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL, "tls send failure when sending request");
        pthread_mutex_lock(tls.mutex);
        pthread_cancel(tls.auth_server);
        pthread_cancel(tls.conntrack_event_handler);
        socket_tls=(int)gnutls_transport_get_ptr(*tls.session);
        gnutls_bye(*tls.session,GNUTLS_SHUT_WR);
		gnutls_deinit(*tls.session);
        shutdown(socket_tls,SHUT_RDWR);
		close(socket_tls);
		free(tls.session);
        tls.session=NULL;
        /* put auth_server_running to 1 because this is this thread which has just killed auth_server */
        tls.auth_server_running=1;
        pthread_mutex_unlock(tls.mutex);
		return 0;
	}
    return 1;
}

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

/* 
 * return offset to next type of headers 
 */
int look_for_flags(char* dgram,int datalen){
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

	if (look_for_flags(payload,payload_len)){
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
		if (DEBUG_OR_NOT(DEBUG_LEVEL_MESSAGE,DEBUG_AREA_MAIN)){
			if (log_engine == LOG_TO_SYSLOG) {
				syslog(SYSLOG_FACILITY(DEBUG_LEVEL_MESSAGE),"Can not allocate packet_id");
			} else {
				printf("[%i] Can not allocate packet_id\n",getpid());
			} 
		}
		return 0;
	}

	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph){
		current->id= ntohl(ph->packet_id);
	} else {
		if (DEBUG_OR_NOT(DEBUG_LEVEL_MESSAGE,DEBUG_AREA_MAIN)){
			if (log_engine == LOG_TO_SYSLOG) {
				syslog(SYSLOG_FACILITY(DEBUG_LEVEL_MESSAGE),"Can not get id for message");
			} else {
				printf("[%i] Can not get id for message\n",getpid());
			} 
		}

		free(current);
		return 0;
	}

	current->nfmark=nfq_get_nfmark(nfa);

	ret = nfq_get_timestamp(nfa, &timestamp);
	if (ret == 0){
		current->timestamp=timestamp.tv_sec;
	}else {
#ifdef DEBUG_ENABLE
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
			if (log_engine == LOG_TO_SYSLOG) {
				syslog(SYSLOG_FACILITY(DEBUG_LEVEL_MESSAGE),"Can not get timestamp for message");
			} else {
				printf("[%i] Can not get timestamp for message\n",getpid());
			} 
		}
#endif
		current->timestamp=time(NULL);
	}

	/* lock packet list mutex */
	pthread_mutex_lock(&packets_list_mutex);
	/* Adding packet to list  */
	pcktid=padd(current);
	/* unlock datas */
	pthread_mutex_unlock(&packets_list_mutex);

	if (pcktid){
		/* send an auth request packet */
		if (! auth_request_send(AUTH_REQUEST,pcktid,payload,payload_len)){
			int sandf=0;
			/* we fail to send the packet so we free packet related to current */
			pthread_mutex_lock(&packets_list_mutex);
			/* search and destroy packet by packet_id */
			sandf = psearch_and_destroy (pcktid,&c_mark);
			pthread_mutex_unlock(&packets_list_mutex);

			if (!sandf){
				if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
					if (log_engine == LOG_TO_SYSLOG) {
						syslog(SYSLOG_FACILITY(DEBUG_LEVEL_WARNING),"Packet could not be removed : %ue",pcktid);
					}else{
						printf("[%i] Packet could not be removed : %u\n",getpid(),pcktid);
					}
				}
			}
		}
	}
	return 1;
}
#endif

void* packetsrv(void *data){
	char buffer[BUFSIZ];
#if USE_NFQUEUE
	int fd;
	int rv;
	struct nfnl_handle *nh;

	h = nfq_open();
	if (!h) {
		if (DEBUG_OR_NOT(DEBUG_LEVEL_CRITICAL,DEBUG_AREA_MAIN)){
			if (log_engine == LOG_TO_SYSLOG){
				syslog(SYSLOG_FACILITY(DEBUG_LEVEL_CRITICAL),"error during nfq_open()");
			}else{
				printf("[%d] error during nfq_open()\n",getpid());
			}
		}
		exit(1);
	}

	if (nfq_unbind_pf(h, AF_INET) < 0) {
		if (DEBUG_OR_NOT(DEBUG_LEVEL_CRITICAL,DEBUG_AREA_MAIN)){
			if (log_engine == LOG_TO_SYSLOG){
				syslog(SYSLOG_FACILITY(DEBUG_LEVEL_CRITICAL),"error during nfq_unbind_pf()");
			}else{
				printf("[%d] error during nfq_unbind_pf()\n",getpid());
			}
		}
		exit(1);
	}

	if (nfq_bind_pf(h, AF_INET) < 0) {
		if (DEBUG_OR_NOT(DEBUG_LEVEL_CRITICAL,DEBUG_AREA_MAIN)){
			if (log_engine == LOG_TO_SYSLOG){
				syslog(SYSLOG_FACILITY(DEBUG_LEVEL_CRITICAL),"error during nfq_bind_pf()");
			}else{
				printf("[%d] error during nfq_bind_pf()\n",getpid());
			}
		}
		exit(1);
	}
        
        
	hndl = nfq_create_queue(h,  nfqueue_num, (nfq_callback *)&treat_packet, NULL);
	if (!hndl) {
		if (DEBUG_OR_NOT(DEBUG_LEVEL_CRITICAL,DEBUG_AREA_MAIN)){
			if (log_engine == LOG_TO_SYSLOG){
				syslog(SYSLOG_FACILITY(DEBUG_LEVEL_CRITICAL),"error during nfq_create_queue() (queue %d busy ?)",nfqueue_num);
			}else{
				printf("[%d] error during nfq_create_queue() (queue %d busy ?)\n",getpid(),nfqueue_num);
			}
		}
		exit(1);
	}

	if (nfq_set_mode(hndl, NFQNL_COPY_PACKET, 0xffff) < 0) {

		if (DEBUG_OR_NOT(DEBUG_LEVEL_CRITICAL,DEBUG_AREA_MAIN)){
			if (log_engine == LOG_TO_SYSLOG){
				syslog(SYSLOG_FACILITY(DEBUG_LEVEL_CRITICAL),"can't set packet_copy mode");
			}else{
				printf("[%d] can't set packet_copy mode\n",getpid());
			}
		}

		exit(1);
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
		if (DEBUG_OR_NOT(DEBUG_LEVEL_CRITICAL,DEBUG_AREA_MAIN)){
			if (log_engine == LOG_TO_SYSLOG){
				syslog(SYSLOG_FACILITY(DEBUG_LEVEL_CRITICAL),"Could not create ipq handle");
			}else{
				printf("[%d] Could not create ipq handle\n",getpid());
			}
		}
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
					if (DEBUG_OR_NOT(DEBUG_LEVEL_MESSAGE,DEBUG_AREA_MAIN)){
						if (log_engine == LOG_TO_SYSLOG) {
							syslog(SYSLOG_FACILITY(DEBUG_LEVEL_MESSAGE),"Got error message from libipq : %d",ipq_get_msgerr(buffer));
						}else {
							printf("[%i] Got error message from libipq : %d\n",getpid(),ipq_get_msgerr(buffer));
						}
					}
				} else {
					if ( ipq_message_type (buffer) == IPQM_PACKET ) {
						pckt_rx++ ;
						/* printf("Working on IP packet\n"); */
						msg_p = ipq_get_packet(buffer);
						/* need to parse to see if it's an end connection packet */
						if (look_for_flags(msg_p->payload,msg_p->data_len)){
							auth_request_send(AUTH_CONTROL,msg_p->packet_id,(char*)msg_p->payload,msg_p->data_len);
							IPQ_SET_VERDICT( msg_p->packet_id,NF_ACCEPT);
						} else {
							current=calloc(1,sizeof( packet_idl));
							if (current == NULL){
								if (DEBUG_OR_NOT(DEBUG_LEVEL_MESSAGE,DEBUG_AREA_MAIN)){
									if (log_engine == LOG_TO_SYSLOG) {
										syslog(SYSLOG_FACILITY(DEBUG_LEVEL_MESSAGE),"Can not allocate packet_id");
									} else {
										printf("[%i] Can not allocate packet_id\n",getpid());
									} 
								}
								return 0;
							}
							current->id=msg_p->packet_id;
#ifdef HAVE_LIBIPQ_MARK
							current->nfmark=msg_p->mark;
#endif
							current->timestamp=msg_p->timestamp_sec;
							/* lock packet list mutex */
							pthread_mutex_lock(&packets_list_mutex);
							/* Adding packet to list  */
							pcktid=padd(current);
							/* unlock datas */
							pthread_mutex_unlock(&packets_list_mutex);

							if (pcktid){
								/* send an auth request packet */
								if (! auth_request_send(AUTH_REQUEST,msg_p->packet_id,(char*)msg_p->payload,msg_p->data_len)){
									int sandf=0;
									/* we fail to send the packet so we free packet related to current */
									pthread_mutex_lock(&packets_list_mutex);
									/* search and destroy packet by packet_id */
									sandf = psearch_and_destroy (msg_p->packet_id,&msg_p->mark);
									pthread_mutex_unlock(&packets_list_mutex);

									if (!sandf){
										if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
											if (log_engine == LOG_TO_SYSLOG) {
												syslog(SYSLOG_FACILITY(DEBUG_LEVEL_WARNING),"Packet could not be removed : %lu",msg_p->packet_id);
											}else{
												printf("[%i] Packet could not be removed : %lu\n",getpid(),msg_p->packet_id);
											}
										}
									}
								}
							}
						}
					} else {
						if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
							if (log_engine == LOG_TO_SYSLOG) {
								syslog(SYSLOG_FACILITY(DEBUG_LEVEL_DEBUG),"Dropping non-IP packet");
							}else {
								printf ("[%i] Dropping non-IP packet\n",getpid());
							}
						}
						IPQ_SET_VERDICT(msg_p->packet_id, NF_DROP);
					}
				}
			}
		} else {
			if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
				if (log_engine == LOG_TO_SYSLOG) {
					syslog(SYSLOG_FACILITY(DEBUG_LEVEL_DEBUG),"BUFSIZ too small, (size == %d)",size);
				}else {
					printf("[%i] BUFSIZ too small, (size == %d)\n",getpid(),size);
				}
			}
		}
#endif
	}
#if USE_NFQUEUE

#else
	ipq_destroy_handle( hndl );  
#endif
	return NULL;
}   

int auth_request_send(uint8_t type,unsigned long packet_id,char* payload,int data_len){
	char datas[512];
	char *pointer;
	int auth_len,total_data_len=512;
	uint8_t version=PROTO_VERSION;
	uint16_t dataslen=data_len+12;
	long timestamp;

	timestamp = time(NULL);

#ifdef WORDS_BIGENDIAN
	packet_id=swap32(packet_id);
	dataslen=swap16(dataslen);
	timestamp=swap32(timestamp);
#endif

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
#ifdef DEBUG_ENABLE
			if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
				if (log_engine == LOG_TO_SYSLOG) {
					syslog(SYSLOG_FACILITY(DEBUG_LEVEL_DEBUG),"Very long packet : truncating !");
				}else {
					printf("[%i] Very long packet : truncating !\n",getpid());
				}
			}
#endif
			memcpy(pointer,payload,511-auth_len);
		}

	} else {
#ifdef DEBUG_ENABLE
		if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
			if (log_engine == LOG_TO_SYSLOG) {
				syslog(SYSLOG_FACILITY(DEBUG_LEVEL_WARNING),"Dropping non-IP packet");
			}else {
				printf ("[%i] Dropping non-IP packet\n",getpid());
			}
		}
#endif
		return 0;
	}


#ifdef DEBUG_ENABLE
	if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN)){
		if (log_engine == LOG_TO_SYSLOG) {
#ifdef WORDS_BIGENDIAN
			syslog(SYSLOG_FACILITY(DEBUG_LEVEL_DEBUG),"Sending request for %lu",swap32(packet_id));
#else
			syslog(SYSLOG_FACILITY(DEBUG_LEVEL_DEBUG),"Sending request for %lu",packet_id);
#endif
		}else {
#ifdef WORDS_BIGENDIAN
			printf("[%i] Sending request for %lu\n",getpid(),swap32(packet_id));
#else
			printf("[%i] Sending request for %lu\n",getpid(),packet_id);
#endif
		}
	}
#endif
        pthread_mutex_lock(tls.mutex);
        /* cleaning up current session : auth_server has detected a problem */
        if (tls.auth_server_running == 0){
            if (tls.session){
                int socket_tls=(int)gnutls_transport_get_ptr(*tls.session);
                gnutls_bye(*tls.session,GNUTLS_SHUT_WR);
                shutdown(socket_tls,SHUT_RDWR);
                tls.session=NULL;
            }
        }
        pthread_mutex_unlock(tls.mutex);
	/* negotiate TLS connection if needed */
	if (!tls.session){
		if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN)){
			if (log_engine == LOG_TO_SYSLOG) {
				syslog(SYSLOG_FACILITY(DEBUG_LEVEL_DEBUG),"Not connected, trying TLS connection");
			}else {
				printf("[%i] Not connected, trying TLS connection\n",getpid());
			}
		}
		tls.session = tls_connect();

		if (tls.session){
			if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
				if (log_engine == LOG_TO_SYSLOG) {
					syslog(SYSLOG_FACILITY(DEBUG_LEVEL_DEBUG),"Connection to nuauth restored");
				}else {
					printf("[%i] Connection to nuauth restored\n",getpid());
				}
			}
			tls.auth_server_running=1;
                        /* create thread for auth server */
                        if (pthread_create(&(tls.auth_server),NULL,authsrv,NULL) == EAGAIN){
                                exit(1);
                        }
		} else {
                        return 0;
                }
	}
	/* send packet */
	if (!gnutls_record_send(*(tls.session),datas,total_data_len)){
		int socket_tls;
		if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
			if (log_engine == LOG_TO_SYSLOG) {
				syslog(SYSLOG_FACILITY(DEBUG_LEVEL_CRITICAL),"tls send failure when sending request");
			}else {
				printf ("[%i] tls send failure when sending request\n",getpid());
			}
                }
                pthread_mutex_lock(tls.mutex);
                pthread_cancel(tls.auth_server);
                gnutls_bye(*tls.session,GNUTLS_SHUT_WR);
                socket_tls=(int)gnutls_transport_get_ptr(*tls.session);
                shutdown(socket_tls,SHUT_RDWR);
                tls.session=NULL;
                /* put auth_server_running to 1 because this is this thread which has just killed auth_server */
                tls.auth_server_running=1;
                pthread_mutex_unlock(tls.mutex);
		return 0;
	}
        return 1;
}

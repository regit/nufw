/*
 ** Copyright (C) 2002-2005, Éric Leblond <eric@regit.org>
 **		       Vincent Deffontaines <vincent@gryzor.com>
 **                      INL http://www.inl.fr/
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

#include "nufw.h"

/** \file nufw/authsrv.c
 *  \brief Process NuAuth packets
 *   
 * authsrv() thread (created by auth_request_send()) wait for new NuAuth packets,
 * and then call auth_packet_to_decision() to process packet.
 */

/**
 * Process NuAuth message of type #AUTH_ANSWER
 */
void auth_process_answer(char *dgram)
{
    uint32_t nfmark;
    int sandf;
    u_int32_t packet_id = ntohl(*(unsigned long *)(dgram+8));

    /* search and destroy packet by packet_id */
    pthread_mutex_lock(&packets_list.mutex);
    sandf=psearch_and_destroy (packet_id,&nfmark);
    pthread_mutex_unlock(&packets_list.mutex);

    if (sandf){
        if ( *(dgram+4) == DECISION_ACCEPT ) {
            /* TODO : test on return */
            debug_log_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
                    "Accepting packet with id=%u", packet_id);
#if HAVE_LIBIPQ_MARK || USE_NFQUEUE
            if (nufw_set_mark) {
                debug_log_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
                        "Marking packet with %d",
                        *(u_int16_t *)(dgram+2));
                /* we put the userid mark at the end of the mark, not changing the 16 first big bits */
                IPQ_SET_VWMARK(packet_id, NF_ACCEPT,((ntohs(*(u_int16_t *)(dgram+2))) & 0xffff ) | (nfmark & 0xffff0000 )); 
            } else {
                IPQ_SET_VERDICT(packet_id, NF_ACCEPT);
            }
#else                      
            IPQ_SET_VERDICT(packet_id, NF_ACCEPT);
#endif /* HAVE_LIBIPQ_MARK || USE_NFQUEUE */

            pckt_tx++;

#ifdef GRYZOR_HACKS
        }else if( *(dgram+4) == NOK_REJ){ 
            /* Packet is rejected, ie. dropped and ICMP signalized */
            log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
                    "Rejecting %lu", packet_id);
            IPQ_SET_VERDICT(packet_id, NF_DROP);
            send_icmp_unreach(dgram);
#endif
        } else {
            debug_log_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
                    "Dropping %u", packet_id);
            IPQ_SET_VERDICT(packet_id, NF_DROP);
        }
    } else {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING, 
                "Packet without a known ID: %u", packet_id);
    }
}    

#ifdef HAVE_LIBCONNTRACK
/**
 * Process NuAuth message of type #AUTH_CONN_DESTROY
 */
void auth_process_conn_destroy(char *dgram)
{
    struct nu_conntrack_message_t* packet_hdr=(struct nu_conntrack_message_t*)dgram;
    struct nfct_tuple orig;
    int id=0;
    orig.src.v4=packet_hdr->ipv4_src;
    orig.dst.v4=packet_hdr->ipv4_dst;
    orig.protonum=packet_hdr->ipv4_protocol;

    switch (packet_hdr->ipv4_protocol){
        case IPPROTO_TCP:
            orig.l4src.tcp.port=packet_hdr->src_port;  
            orig.l4dst.tcp.port=packet_hdr->dest_port;  
            break;
        case IPPROTO_UDP:
            orig.l4src.udp.port=packet_hdr->src_port;  
            orig.l4dst.udp.port=packet_hdr->dest_port;  
            break;
        default:
            return; 
    }
    (void)nfct_delete_conntrack(cth, &orig, 
            NFCT_DIR_ORIGINAL,
            id);
}    

/**
 * Process NuAuth message of type #AUTH_CONN_UPDATE
 */
void auth_process_conn_update(char *dgram)
{
    struct nu_conntrack_message_t* packet_hdr=(struct nu_conntrack_message_t*)dgram;
    struct nfct_conntrack ct;
    ct.tuple[NFCT_DIR_ORIGINAL].src.v4=packet_hdr->ipv4_src;
    ct.tuple[NFCT_DIR_ORIGINAL].dst.v4=packet_hdr->ipv4_dst;
    ct.tuple[NFCT_DIR_ORIGINAL].protonum=packet_hdr->ipv4_protocol;
    ct.timeout=0;

    switch (packet_hdr->ipv4_protocol){
        case IPPROTO_TCP:
            ct.tuple[NFCT_DIR_ORIGINAL].l4src.tcp.port=packet_hdr->src_port;  
            ct.tuple[NFCT_DIR_ORIGINAL].l4dst.tcp.port=packet_hdr->dest_port;  
            break;
        case IPPROTO_UDP:
            ct.tuple[NFCT_DIR_ORIGINAL].l4src.udp.port=packet_hdr->src_port;  
            ct.tuple[NFCT_DIR_ORIGINAL].l4dst.udp.port=packet_hdr->dest_port;  
            break;
        default:
            return; 
    }
#ifdef HAVE_LIBCONNTRACK_FIXEDTIMEOUT
    if (packet_hdr->timeout){
        ct.fixed_timeout=ntohl(packet_hdr->timeout);
    }
#endif
    (void)nfct_update_conntrack(cth, &ct);
}    
#endif /* HAVE_LIBCONNTRACK */

/**
 * Process authentification server (NuAuth) packet answer. Different answers
 * can be:
 *   - Decision answer: packet accepted/rejected
 *   - Connection destroy: ask conntrack to destroy a connection
 *   - Connection update: ask connectrak to set connection timeout to given
 *     value
 */
inline void auth_packet_to_decision(char* dgram)
{
    if (*dgram != PROTO_VERSION)
    {
        debug_log_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG, "Wrong protocol version from authentification server answer.");
        return;
    }

    switch (*(dgram+1)) {
        case AUTH_ANSWER:
            auth_process_answer(dgram);
            break;
#ifdef HAVE_LIBCONNTRACK
        case AUTH_CONN_DESTROY: 
            auth_process_conn_destroy(dgram);
            break;
        case AUTH_CONN_UPDATE: 
            auth_process_conn_update(dgram);
            break;
#else          
        case AUTH_CONN_DESTROY:
            log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
                    "Connection destroy message not supported");
            break;
        case AUTH_CONN_UPDATE:
            log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
                    "Connection update message not supported");
            break;
#endif                             
        default:
            log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG, 
                    "Type %d for packet %lu (not for me)",
                    *(dgram+1),*(unsigned long * )(dgram+4));
            break;
    }
}

/**
 * Thread waiting to authentification server (NuAuth) answer.
 * Call auth_packet_to_decision() on new packet.
 */
void* authsrv(void* data)
{
    int ret;
    char dgram[512];
    int socket = (int)gnutls_transport_get_ptr(*tls.session);
    fd_set wk_set;
    int select_result;
    struct timeval tv;

    log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
            "[+] Start auth server thread");

    while (pthread_mutex_trylock(&tls.auth_server_mutex) == 0)
    {
        pthread_mutex_unlock(&tls.auth_server_mutex);

        /* Set timeout: one second */
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        /* wait new event on socket */
        FD_ZERO(&wk_set);
        FD_SET(socket,&wk_set);
        select_result = select(socket+1,&wk_set,NULL,NULL,&tv);
        if (select_result == -1)
        {
            break;
        }

        /* catch timeout */
        if (select_result == 0) {
            /* timeout! */
            continue;
        }
        
        memset(dgram, 0, sizeof dgram);
        ret= gnutls_record_recv(*tls.session,dgram,sizeof dgram);
        if (ret<0){
            if ( gnutls_error_is_fatal(ret) ){
                break;
            }
        } else {
            auth_packet_to_decision(dgram);
        }
    }
    
    log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
            "[+] Leave auth server thread");
    
    pthread_mutex_lock(&tls.mutex);
    /* warn sender thread that it will need to reconnect at next access */
    tls.auth_server_running=0;
    pthread_mutex_unlock(&tls.mutex);
    pthread_exit(NULL);
}


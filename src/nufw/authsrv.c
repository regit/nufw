/*
 ** Copyright (C) 2002-2006, Éric Leblond <eric@regit.org>
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
void auth_process_answer(char *dgram, int dgram_size)
{
    nuauth_decision_response_t *answer;
    uint32_t nfmark;
    int sandf;
    u_int32_t packet_id;
    u_int16_t user_id;
    int payload_len;

    /* check packet size */
    if (dgram_size < (int)sizeof(nuauth_decision_response_t))
    {
        return;
    }
    answer = (nuauth_decision_response_t *)dgram;

    /* check payload length */
    payload_len = ntohs(answer->payload_len);
    if (dgram_size < (int)(sizeof(nuauth_decision_response_t) + payload_len)
            || ((payload_len != 0) && (payload_len != (20+8)) && (payload_len != (40+8))))
    {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING, 
                "Packet with improper size");
        return;
    }
    
    /* get packet id and user id */
    packet_id = ntohl(answer->packet_id);
    user_id = ntohs(answer->user_id);

    /* search and destroy packet by packet_id */
    pthread_mutex_lock(&packets_list.mutex);
    sandf=psearch_and_destroy (packet_id,&nfmark);
    pthread_mutex_unlock(&packets_list.mutex);
    if (!sandf)
    {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING, 
                "Packet without a known ID: %u", packet_id);
        return;
    }

    switch (answer->decision)
    {
    case DECISION_ACCEPT:
        /* accept packet */
        debug_log_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
                "Accepting packet with id=%u", packet_id);
#if HAVE_LIBIPQ_MARK || USE_NFQUEUE
        if (nufw_set_mark) {
            debug_log_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
                    "Marking packet with %d",
                    user_id);
            /* we put the userid mark at the end of the mark, not changing the 16 first big bits */
            nfmark = (nfmark & 0xffff0000 ) | user_id;
            IPQ_SET_VWMARK(packet_id, NF_ACCEPT, htonl(nfmark)); 
        } else {
            IPQ_SET_VERDICT(packet_id, NF_ACCEPT);
        }
#else                      
        IPQ_SET_VERDICT(packet_id, NF_ACCEPT);
#endif /* HAVE_LIBIPQ_MARK || USE_NFQUEUE */
        pckt_tx++;
        break;

    case DECISION_REJECT:
        /* Packet is rejected, ie. dropped and ICMP signalized */
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
                "Rejecting %lu", packet_id);
        IPQ_SET_VERDICT(packet_id, NF_DROP);
        send_icmp_unreach(dgram + sizeof(nuauth_decision_response_t));
        break;
        
    default:
        /* drop packet */
        debug_log_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
                "Drop packet %u", packet_id);
        IPQ_SET_VERDICT(packet_id, NF_DROP);
    }
}    

#ifdef HAVE_LIBCONNTRACK

/**
 * Check if a IPv6 address is a IPv4 or not.
 *
 * \return 1 for IPv4 and 0 for IPv6
 */
int is_ipv4(struct in6_addr *addr)
{
    if (addr->s6_addr32[2] != 0xffff0000)
        return 0;
    if (addr->s6_addr32[0] != 0 || addr->s6_addr32[1] != 0)
        return 0;
    return 1;
}

int build_nfct_tuple_from_message(struct nfct_tuple* orig,struct nu_conntrack_message_t* packet_hdr)
{
    orig->protonum = packet_hdr->ip_protocol;
    if (is_ipv4(&packet_hdr->ip_src) && is_ipv4(&packet_hdr->ip_dst))
    {
        orig->l3protonum = AF_INET;
        orig->src.v4 = packet_hdr->ip_src.s6_addr32[3];
        orig->dst.v4 = packet_hdr->ip_dst.s6_addr32[3];
    } else {
        orig->l3protonum = AF_INET6;
        memcpy(&orig->src.v6, &packet_hdr->ip_src, sizeof(orig->src.v6));
        memcpy(&orig->dst.v6, &packet_hdr->ip_dst, sizeof(orig->dst.v6));
    }

    switch (packet_hdr->ip_protocol)
    {
        case IPPROTO_TCP:
            orig->l4src.tcp.port=packet_hdr->src_port;  
            orig->l4dst.tcp.port=packet_hdr->dest_port;  
            break;
        case IPPROTO_UDP:
            orig->l4src.udp.port=packet_hdr->src_port;  
            orig->l4dst.udp.port=packet_hdr->dest_port;  
            break;
        default:
            return 0; 
    }
    return 1;

}

/**
 * Process NuAuth message of type #AUTH_CONN_DESTROY
 */
void auth_process_conn_destroy(char *dgram, int dgram_size)
{
    struct nu_conntrack_message_t* packet_hdr;
    struct nfct_tuple orig;
    int id=0;

    /* check packet size */
    if (dgram_size < (int)sizeof(struct nu_conntrack_message_t)) {
        return;
    }
    packet_hdr = (struct nu_conntrack_message_t*)dgram;
    
    if (build_nfct_tuple_from_message(&orig,packet_hdr)){
        debug_log_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_VERBOSE_DEBUG, 
                "Deleting entry from conntrack after NuAuth request");
        (void)nfct_delete_conntrack(cth, &orig, NFCT_DIR_ORIGINAL, id);
    }
}    

/**
 * Process NuAuth message of type #AUTH_CONN_UPDATE
 */
void auth_process_conn_update(char *dgram, int dgram_size)
{
    struct nu_conntrack_message_t* packet_hdr;
    struct nfct_conntrack *ct;
    struct nfct_tuple orig;
    struct nfct_tuple reply;
    union nfct_protoinfo proto;


    /* check packet size */
    if (dgram_size < (int)sizeof(struct nu_conntrack_message_t)) {
        debug_log_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG, 
                "NuAuth sent too small message");
        return;
    }
    packet_hdr = (struct nu_conntrack_message_t*)dgram;
    
    if (build_nfct_tuple_from_message(&orig,packet_hdr)){
        /* generate reply : this is stupid but done by conntrack tool */
        memset(&reply, 0, sizeof(reply));
        reply.l3protonum = orig.l3protonum;
#if 0
        /* we set it to 0 to avoid problem  with NAT */
        memset(&reply.src, 0, sizeof(reply.src));
        memset(&reply.dst, 0, sizeof(reply.dst));

        memset(&reply.l4src, 0, sizeof(reply.l4src));
        memset(&reply.l4dst, 0, sizeof(reply.l4dst));
#endif

        
        proto.tcp.state=3;

#ifdef  HAVE_LIBCONNTRACK_FIXEDTIMEOUT
        ct = nfct_conntrack_alloc(&orig, &reply, 0, 
                &proto,  IPS_ASSURED|IPS_SEEN_REPLY|IPS_FIXED_TIMEOUT  , 0, 0, NULL);
#else
        ct = nfct_conntrack_alloc(&orig, &reply, 0, 
                &proto,  IPS_ASSURED|IPS_SEEN_REPLY, 0, 0, NULL);
#endif
#ifdef HAVE_LIBCONNTRACK_FIXEDTIMEOUT
        if (packet_hdr->timeout)
        {
            debug_log_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_VERBOSE_DEBUG, 
                    "Setting timeout to %d after NuAuth request",ntohl(packet_hdr->timeout));
            ct->timeout = ntohl(packet_hdr->timeout);
        }
#endif /* HAVE_LIBCONNTRACK_FIXEDTIMEOUT */

        if (nfct_update_conntrack(cth, ct) != 0){
            log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
                "Conntrack update was impossible");

        }
        nfct_conntrack_free(ct);
    }
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
inline void auth_packet_to_decision(char* dgram, int dgram_size)
{
    if (dgram_size < 2)
    {
        debug_log_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG, 
                "NuAuth sent too small message");
        return;
    }

    if (dgram[0] != PROTO_VERSION)
    {
        debug_log_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
                "Wrong protocol version from authentification server answer.");
        return;
    }

    switch (dgram[1]) {
        case AUTH_ANSWER:
            auth_process_answer(dgram, dgram_size);
            break;
#ifdef HAVE_LIBCONNTRACK
        case AUTH_CONN_DESTROY: 
            auth_process_conn_destroy(dgram, dgram_size);
            break;
        case AUTH_CONN_UPDATE: 
            auth_process_conn_update(dgram, dgram_size);
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
                    "NuAuth message type %d not for me",
                    dgram[1]);
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
        
        /* memset(dgram, 0, sizeof dgram); */
        pthread_mutex_lock(&tls.mutex);
        ret= gnutls_record_recv(*tls.session,dgram,sizeof dgram);
        pthread_mutex_unlock(&tls.mutex);
        if (ret<0){
            if ( gnutls_error_is_fatal(ret) ){
                break;
            }
        } else {
            auth_packet_to_decision(dgram, ret);
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


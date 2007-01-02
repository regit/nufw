/*
 ** Copyright (C) 2002-2006 Eric Leblond <eric@regit.org>
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

/** \file packetsrv.c
 *  \brief Packet server thread
 *
 * packetsrv() is a thread which read packet from netfilter queue. If packet
 * content match to IPv4 TCP/UDP, add it to the packet list (::packets_list)
 * and ask NuAuth an authentification or control using auth_request_send().
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
int look_for_tcp_flags(unsigned char* dgram, unsigned int datalen){
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

#ifdef USE_NFQUEUE
/**
 * \brief Callback called by NetFilter when a packet with target QUEUE is matched.
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
    struct queued_pckt q_pckt;
    struct nfqnl_msg_packet_hdr *ph;
    struct timeval timestamp;
    int ret;

    debug_log_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_VERBOSE_DEBUG,
            "(*) New packet");

    q_pckt.payload_len =  nfq_get_payload(nfa,&(q_pckt.payload));
    if (q_pckt.payload_len == -1){
        return 0;
    }

    if (look_for_tcp_flags((unsigned char*)q_pckt.payload,q_pckt.payload_len)){
        ph = nfq_get_msg_packet_hdr(nfa);
        if (ph){
            q_pckt.packet_id = ntohl(ph->packet_id);
            auth_request_send(AUTH_CONTROL,&q_pckt);
            IPQ_SET_VERDICT(q_pckt.packet_id,NF_ACCEPT);
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
#ifdef PERF_DISPLAY_ENABLE
    gettimeofday(&(current->arrival_time),NULL);
#endif
    /* Get unique identifier of packet in queue */
    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph){
        current->id= ntohl(ph->packet_id);
    } else {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_INFO,
                "Can not get id for message");
        free(current);
        return 0;
    }

    q_pckt.mark = current->nfmark = nfq_get_nfmark(nfa);

    if (! get_interface_information(&q_pckt, nfa)){
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_INFO,
                "Can not get interfaces information for message");
        free(current);
		return 0;
	}

    ret = nfq_get_timestamp(nfa, &timestamp);
    if (ret == 0){
        q_pckt.timestamp = current->timestamp = timestamp.tv_sec;
    }else {
        q_pckt.timestamp = current->timestamp = time(NULL);
    }

    /* Try to add the packet to the list */
    pthread_mutex_lock(&packets_list.mutex);
    q_pckt.packet_id=padd(current);
    pthread_mutex_unlock(&packets_list.mutex);

    if (q_pckt.packet_id){
        /* send an auth request packet */
        if (! auth_request_send(AUTH_REQUEST,&q_pckt)){
            int sandf=0;
            /* we fail to send the packet so we free packet related to current */
            pthread_mutex_lock(&packets_list.mutex);
            /* search and destroy packet by packet_id */
            sandf = psearch_and_destroy (q_pckt.packet_id,&(q_pckt.mark));
            pthread_mutex_unlock(&packets_list.mutex);

            if (!sandf){
                log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING, \
                        "Packet could not be removed: %u", q_pckt.packet_id);
            }
        }
    }
    return 1;
}

/**
 * Open a netlink connection and returns file descriptor
 */
int packetsrv_open()
{
    struct nfnl_handle *nh;

    log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_SERIOUS_MESSAGE,
            "Open netfilter queue socket");
    log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_SERIOUS_WARNING,
            "Don't forget to load kernel modules nfnetlink and nfnetlink_queue (using modprobe command)");

    /* opening library handle */
    h = nfq_open();
    if (!h) {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL, 
                "[!] Error during nfq_open()");
        return -1;
    }

    /* unbinding existing nf_queue handler for AF_INET (if any) */
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL, 
                "[!] Error during nfq_unbind_pf()");
        return -1;
    }

    /* binding nfnetlink_queue as nf_queue handler for AF_INET */
    if (nfq_bind_pf(h, AF_INET) < 0) {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL, 
                "[!] Error during nfq_bind_pf()");
        return -1;
    }

    /* unbinding existing nf_queue handler for AF_INET6 (if any) */
    if (nfq_unbind_pf(h, AF_INET6) < 0) {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL, 
                "[!] Error during nfq_unbind_pf()");
        return -1;
    }

    /* binding nfnetlink_queue as nf_queue handler for AF_INET6 */
    if (nfq_bind_pf(h, AF_INET6) < 0) {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL, 
                "[!] Error during nfq_bind_pf()");
        return -1;
    }

    /* binding this socket to queue number ::nfqueue_num 
     * and install our packet handler */
    hndl = nfq_create_queue(h,  nfqueue_num, (nfq_callback *)&treat_packet, NULL);
    if (!hndl) {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL,
                "[!] Error during nfq_create_queue() (queue %d busy ?)",
                nfqueue_num);
        return -1;
    }

    /* setting copy_packet mode */
    if (nfq_set_mode(hndl, NFQNL_COPY_PACKET, 0xffff) < 0) {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL,
                "[!] Can't set packet_copy mode");
        return -1;
    }
#ifdef HAVE_NFQ_SET_QUEUE_MAXLEN
    /* setting queue length */
    if (nfq_set_queue_maxlen(hndl, queue_maxlen) < 0) {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL,
                "[!] Can't set queue length");
        return -1;
    }
#endif

    nh = nfq_nfnlh(h);
    return nfnl_fd(nh);
}

void packetsrv_close(int smart)
{
    log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_SERIOUS_MESSAGE,
            "Destroy netfilter queue socket");
    if (smart)
        nfq_destroy_queue(hndl);
    nfq_close(h);
}

#else /* USE_NFQUEUE */

/**
 * Process an IP message received from IPQ
 * \return Returns 1 if it's ok, 0 otherwise.
 */
void packetsrv_ipq_process(unsigned char *buffer)
{
    ipq_packet_msg_t *msg_p = NULL ;
    packet_idl *current;
    struct queued_pckt q_pckt;
    uint32_t pcktid;

    pckt_rx++ ;
    /* printf("Working on IP packet\n"); */
    msg_p = ipq_get_packet(buffer);
    q_pckt.packet_id = msg_p->packet_id;
    q_pckt.payload = (char*)msg_p->payload;
    q_pckt.payload_len = msg_p->data_len;
    /* need to parse to see if it's an end connection packet */
    if (look_for_tcp_flags(msg_p->payload,msg_p->data_len)){
        auth_request_send(AUTH_CONTROL,&q_pckt); 
        IPQ_SET_VERDICT( msg_p->packet_id,NF_ACCEPT);
        return;
    }

    /* Create packet */
    current=calloc(1,sizeof( packet_idl));
    if (current == NULL)
    {
        /* no more memory: drop packet and exit */
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_SERIOUS_WARNING,
                "[+] Can not allocate packet_id (drop packet)");
        IPQ_SET_VERDICT( msg_p->packet_id,NF_DROP);
        return;
    }
    current->id=msg_p->packet_id;
    current->timestamp=msg_p->timestamp_sec;
#ifdef HAVE_LIBIPQ_MARK
    current->nfmark=msg_p->mark;
#endif

    /* Adding packet to list */
    pthread_mutex_lock(&packets_list.mutex);
    pcktid=padd(current);
    pthread_mutex_unlock(&packets_list.mutex);
    if (!pcktid) {
        /* can't add packet to packet list (so already dropped): exit */
        return;
    }

    /* send an auth request packet */
    if (! auth_request_send(AUTH_REQUEST,&q_pckt)){
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
#endif /* USE_NFQUEUE */

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
void* packetsrv(void *void_arg)
{
    struct ThreadArgument *thread_arg  = void_arg;
    struct ThreadType *this = thread_arg->thread;
    int fatal_error = 0;
#ifdef USE_NFQUEUE
    unsigned char buffer[BUFSIZ];
    struct timeval tv;
    int fd;
    int rv;
    int select_result;
    fd_set wk_set;

    fd = packetsrv_open();
    if (fd < 0) 
    {
        exit(EXIT_FAILURE);
    }

    log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
            "[+] Packet server started");

    /* loop until main process ask to stop */
    while (pthread_mutex_trylock(&this->mutex) == 0)
    {
        pthread_mutex_unlock(&this->mutex);

        /* Set timeout: one second */
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        /* wait new event on socket */
        FD_ZERO(&wk_set);
        FD_SET(fd,&wk_set);
        select_result = select(fd+1,&wk_set,NULL,NULL,&tv);
        if (select_result == -1)
        {
	    int err = errno;
	    if (err == EINTR) {
		    continue;
	    }
            log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL, 
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

        /* read one packet */
        rv = recv(fd, buffer, sizeof(buffer), 0);
        if (rv < 0)
        {
            log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING, 
                    "[!] Error of read on netfilter queue socket (code %i)!",
                    rv);
            log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_SERIOUS_MESSAGE, 
                    "Reopen netlink connection.");
            packetsrv_close(0);
            fd = packetsrv_open();
            if (fd < 0)
            {
                log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL, 
                        "[!] FATAL ERROR: Fail to reopen netlink connection!");
                fatal_error = 1;
                break;
            }
            continue;
        }

        /* process the packet */
        nfq_handle_packet(h, (char*)buffer, rv);
        pckt_rx++ ;
    }

    packetsrv_close(!fatal_error);
#else /* USE_NFQUEUE */
    unsigned char buffer[BUFSIZ];
    int size;

    log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_MESSAGE,
            "Try to connect to netlink (IPQ)");
    log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_SERIOUS_WARNING,
            "Don't forget to load Linux kernel module ip_queue (using modprobe command)");

    /* init netlink connection */
    hndl = ipq_create_handle(0,PF_INET);
    if (!hndl)
    {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL,
                "[!] FATAL ERROR: Could not create ipq handle!");
        kill(thread_arg->parent_pid, SIGTERM);
        pthread_exit (NULL);
    }
    
    ipq_set_mode(hndl, IPQ_COPY_PACKET,BUFSIZ);  

    log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_FATAL,
            "[+] Packet server started");

    /* loop until main process ask this thread to stop using its mutex */
    while (pthread_mutex_trylock(&this->mutex) != EBUSY)
    {
        pthread_mutex_unlock(&this->mutex);

        /* wait netfilter event with a timeout of one second */
        size = ipq_read(hndl,buffer,sizeof(buffer), 1000000);

        /* is timeout recheaded */
        if (size == 0) {
            continue;
        }          

        /* Check buffer size */
        if (size == -1)
        {
            log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
                    "BUFSIZ too small (size == %d)", size);
            continue;
        }
        if (BUFSIZ <= size)
        {
            log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
                    "BUFSIZ too small (size == %d)", size);
            continue;
        }

        /* skip message different than packets */
        if (ipq_message_type (buffer) != IPQM_PACKET)
        {
            /* if it's an error, display it and stop NuFW !!! */
            if (ipq_message_type(buffer) == NLMSG_ERROR)
            {
                log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL, 
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
    ipq_destroy_handle( hndl );  
#endif
    log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_WARNING,
            "[+] Leave packet server thread");
    if (fatal_error){
        kill(thread_arg->parent_pid, SIGTERM);
    }
    pthread_exit (NULL);
}   

/**
 * Halt TLS threads and close socket
 */
void shutdown_tls()
{
    log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL, "tls send failure when sending request");
    pthread_mutex_lock(&tls.mutex);

    pthread_cancel(tls.auth_server);

    close_tls_session();

    /* put auth_server_running to 1 because this is this thread which has
     * just killed auth_server */
    tls.auth_server_running=1;

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
int auth_request_send(uint8_t type, struct queued_pckt* pckt_datas)
{
    unsigned char datas[512];
    nuv4_nufw_to_nuauth_auth_message_t *msg_header = (nuv4_nufw_to_nuauth_auth_message_t *)&datas;
    unsigned char *msg_content = datas + sizeof(nuv4_nufw_to_nuauth_auth_message_t);
    int msg_length;

    /* Drop non-IPv(4|6) packet */
    if ((((struct iphdr *)(pckt_datas->payload))->version != 4) && ( ((struct iphdr *)(pckt_datas->payload))->version != 6)) {
        debug_log_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG, 
                "Dropping non-IPv4/non-IPv6 packet (version %u)",
                ((struct iphdr *)(pckt_datas->payload))->version);
        return 0;
    } 

    /* Truncate packet content if needed */
    if (sizeof(datas) < sizeof(nuv4_nufw_to_nuauth_auth_message_t) + pckt_datas->payload_len) {
        debug_log_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG, 
                "Very long packet: truncating!");
        pckt_datas->payload_len = sizeof(datas) - sizeof(nuv4_nufw_to_nuauth_auth_message_t);
    }
    msg_length = sizeof(nuv4_nufw_to_nuauth_auth_message_t) + pckt_datas->payload_len;

    /* Fill message header */
    msg_header->protocol_version = PROTO_VERSION;
    msg_header->msg_type = type;
    msg_header->msg_length = htons(msg_length);
    msg_header->packet_id = htonl(pckt_datas->packet_id);
    msg_header->timestamp = htonl(pckt_datas->timestamp);

    /* Add info about interfaces */
    if (pckt_datas->indev){
        memcpy(msg_header->indev,pckt_datas->indev,IFNAMSIZ*sizeof(char));
    } else {
        memset(msg_header->indev,0,IFNAMSIZ*sizeof(char));
    }

    if (pckt_datas->outdev){
        memcpy(msg_header->outdev,pckt_datas->outdev,IFNAMSIZ*sizeof(char));
    } else {
        memset(msg_header->indev,0,IFNAMSIZ*sizeof(char));
    }

    if (pckt_datas->physindev){
        memcpy(msg_header->physindev,pckt_datas->physindev,IFNAMSIZ*sizeof(char));
    } else {
        memset(msg_header->indev,0,IFNAMSIZ*sizeof(char));
    }

    if (pckt_datas->physoutdev){
        memcpy(msg_header->physoutdev,pckt_datas->physoutdev,IFNAMSIZ*sizeof(char));
    } else {
        memset(msg_header->indev,0,IFNAMSIZ*sizeof(char));
    }


    /* Copy (maybe truncated) packet content */
    memcpy(msg_content, pckt_datas->payload, pckt_datas->payload_len);    

    /* Display message */
    debug_log_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_VERBOSE_DEBUG, 
            "Sending request for %lu", pckt_datas->packet_id);

    /* cleaning up current session : auth_server has detected a problem */
    pthread_mutex_lock(&tls.mutex);
    if ((tls.auth_server_running == 0) && tls.session != NULL) {
        close_tls_session();
    }
    pthread_mutex_unlock(&tls.mutex);

    /* negotiate TLS connection if needed */
    if (!tls.session){
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_INFO,
                "Not connected, trying TLS connection");
        tls.session = tls_connect();

        if (tls.session){
            pthread_attr_t attr;
            pthread_attr_init(&attr);
            pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

            log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_INFO,
                    "Connection to nuauth restored");
            tls.auth_server_running=1;
            
            /* create joinable thread for auth server */
            pthread_mutex_init(&tls.auth_server_mutex, NULL);
            if (pthread_create(&tls.auth_server, &attr, authsrv, NULL) == EAGAIN){
                exit(EXIT_FAILURE);
            }
       } else {
            return 0;
        }
    }

    /* send packet */
    pthread_mutex_lock(&tls.mutex);
    if (!gnutls_record_send(*(tls.session), datas, msg_length)){
        shutdown_tls();
        pthread_mutex_unlock(&tls.mutex);
        return 0;
    }
    pthread_mutex_unlock(&tls.mutex);
    return 1;
}

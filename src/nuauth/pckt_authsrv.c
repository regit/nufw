/*
 ** Copyright(C) 2003-2004 Eric Leblond <regit@inl.fr>
 **                        INL http://www.inl.fr/
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

/** \file pckt_authsrv.c
 *  \brief Functions to parse a packet sent by NuFW 
 * 
 * Function authpckt_decode() parse a packet sent by NuFW. Depends on
 * message type (see ::nufw_message_t), send a message to
 * limited_connections_queue (member of ::nuauthdatas), may log packet
 * (log_user_packet()) and/or create a new connection
 * (of type ::connection_t).
 *
 * This function is called by treat_nufw_request()
 * which is called in the thread tls_nufw_authsrv().
 */

#include <auth_srv.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h> 

#include <errno.h>

/** 
 * Fill IP fields (saddr, daddr and protocol) of the a connection tracking 
 * (::tracking_t) structure.
 * 
 * \param connection Pointer to a connection
 * \param dgram Pointer to packet datas
 * \return Offset to next type of headers, or 0 if the packet is not recognized 
 */
unsigned int get_ip_headers(tracking_t *tracking, unsigned char *dgram, unsigned int dgram_size)
{
    struct iphdr *ip = (struct iphdr *)dgram;

    /* check ip headers minimum size */
    if (dgram_size < sizeof(struct iphdr))
        return 0;

    /* check IP version (should be IPv4) */
    if (ip->version == 4){
        tracking->saddr = ntohl(ip->saddr);
        tracking->daddr = ntohl(ip->daddr);
        tracking->protocol = ip->protocol;
        return 4*ip->ihl;
    }
#ifdef DEBUG_ENABLE
    if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_PACKET)){
        g_message("IP version is %d, ihl : %d", ip->version, ip->ihl);
    }
#endif
    return 0;
}

/** 
 * Fill UDP fields (source and dest) of a connection tracking
 * (::tracking_t) structure.
 * 
 * \param connection Pointer to a connection
 * \param dgram Pointer to packet datas
 * \return If an error occurs return 1, else returns 0
 */
int get_udp_headers(tracking_t *tracking, unsigned char *dgram, unsigned int dgram_size)
{
    struct udphdr *udp = (struct udphdr *)dgram;

    /* check udp headers minimum size */
    if (dgram_size < sizeof(struct udphdr))
        return 1;

    tracking->source = ntohs(udp->source);
    tracking->dest = ntohs(udp->dest);
    tracking->type = 0;
    tracking->code = 0;
    return 0;
}


/**
 * Fill TCP fields (source and dest) of the connection tracking
 * (::tracking_t) structure.
 *
 * \param connection Pointer to a connection
 * \param dgram Pointer to packet datas
 * \return State of the TCP connection (#TCP_STATE_OPEN, 
 *         #TCP_STATE_ESTABLISHED, #TCP_STATE_CLOSE), or #TCP_STATE_UNKNOW
 *         if an error occurs.
 */
tcp_state_t get_tcp_headers(tracking_t *tracking, unsigned char *dgram, unsigned int dgram_size)
{
    struct tcphdr *tcp = (struct tcphdr *)dgram;

    /* check udp headers minimum size */
    if (dgram_size < sizeof(struct tcphdr))
        return TCP_STATE_UNKNOW;

    tracking->source = ntohs(tcp->source);
    tracking->dest = ntohs(tcp->dest);
    tracking->type = 0;
    tracking->code = 0;

    /* test if fin ack or syn */
    /* if fin ack return 0 end of connection */
    if (tcp->fin || tcp->rst )
        return TCP_STATE_CLOSE;

    /* if syn return 1 */
    if (tcp->syn) {
        if (tcp->ack){
            return TCP_STATE_ESTABLISHED;
        } else {
            return TCP_STATE_OPEN;
        }
    }
    return TCP_STATE_UNKNOW;
}

/** 
 * Fill ICMP fields (type and code) of the connection tracking
 * (::tracking_t) structure.
 * 
 * \param connection Pointer to a connection
 * \param dgram Pointer to packet datas
 * \return If an error occurs return 1, else returns 0
 */
int get_icmp_headers(tracking_t *tracking, unsigned char *dgram, unsigned int dgram_size)
{
    struct icmphdr *icmp = (struct icmphdr *)dgram;

    /* check udp headers minimum size */
    if (dgram_size < sizeof(struct icmphdr))
        return 1;

    tracking->source = 0;
    tracking->dest = 0;
    tracking->type = icmp->type;
    tracking->code = icmp->code;
    return 0;
}

/**
 * Parse message content for message of type #AUTH_REQUEST or #AUTH_CONTROL
 * using structure ::nufw_to_nuauth_auth_message_t. 
 * 
 * \param dgram Pointer to packet datas
 * \param dgram_size Number of bytes in the packet
 * \return A new connection or NULL if fails 
 */
connection_t* authpckt_new_connection(unsigned char *dgram, unsigned int dgram_size)
{
    nufw_to_nuauth_auth_message_t *msg = (nufw_to_nuauth_auth_message_t *)dgram;
    unsigned int ip_hdr_size; 

    if (dgram_size < sizeof(nufw_to_nuauth_auth_message_t))
    {
        /* TODO: Display warning message */
        return NULL;
    }
    dgram += sizeof(nufw_to_nuauth_auth_message_t);
    dgram_size -= sizeof(nufw_to_nuauth_auth_message_t);

    /* allocate new connection */
    connection_t *connection = g_new0(connection_t, 1);
    if (connection == NULL){
        if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_PACKET)){
            g_message("Can not allocate connection\n");
        }
        return NULL;
    }
#ifdef PERF_DISPLAY_ENABLE
    gettimeofday(&(connection->arrival_time),NULL);
#endif
    connection->acl_groups = NULL;
    connection->user_groups = NULL;

    connection->packet_id = g_slist_append(NULL, GUINT_TO_POINTER(ntohl(msg->packet_id)));
#ifdef DEBUG_ENABLE
    if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_PACKET)) {
        g_message("Working on  %u\n",(uint32_t)GPOINTER_TO_UINT(connection->packet_id->data));
    }
#endif

    /* timestamp */
    connection->timestamp = ntohl(msg->timestamp);
    if ( connection->timestamp == 0 )
        connection->timestamp = time(NULL);

    /* get ip headers till tracking is filled */
    ip_hdr_size = get_ip_headers(&connection->tracking, dgram, dgram_size);
    if (ip_hdr_size == 0)  {
        if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_PACKET))
            g_message ("Can't parse IP headers\n");
        free_connection(connection);
        return NULL;
    }
    dgram += ip_hdr_size;
    dgram_size -= ip_hdr_size;

    /* get saddr and daddr */
    /* check if proto is in Hello mode list (when hello authentication is used) */
    if ( nuauthconf->hello_authentication &&  localid_authenticated_protocol(connection->tracking.protocol) ) {
        connection->state=AUTH_STATE_HELLOMODE;
    } 
    switch (connection->tracking.protocol) {
        case IPPROTO_TCP:
        {
            tcp_state_t tcp_state = get_tcp_headers(&connection->tracking, dgram, dgram_size);
            switch (tcp_state){
                case TCP_STATE_OPEN:
                    break; 
                case TCP_STATE_CLOSE:
                    if (msg->msg_type == AUTH_CONTROL ){
                        log_user_packet(*connection, TCP_STATE_CLOSE);
                        free_connection(connection);
                        return NULL;
                    }
                    break;
                case TCP_STATE_ESTABLISHED:
                    if (msg->msg_type == AUTH_CONTROL ){
                        log_user_packet(*connection, TCP_STATE_ESTABLISHED);
                        free_connection(connection);
                        return NULL;
                    }
                    break;
                default:
                    if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_PACKET))
                        g_warning ("Can't parse TCP headers\n");
                    free_connection(connection);
                    return NULL;
            }
            break;
        }

        case IPPROTO_UDP:
            if (!get_udp_headers(&connection->tracking, dgram, dgram_size)) {
                free_connection(connection);
                return NULL;
            }
            break;

        case IPPROTO_ICMP:
            if (!get_icmp_headers(&connection->tracking, dgram, dgram_size)) {
                free_connection(connection);
                return NULL;
            }
            break;

        default:
            if ( connection->state != AUTH_STATE_HELLOMODE){
                if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_PACKET))
                    g_message ("Can't parse protocol %u\n", connection->tracking.protocol);
                free_connection(connection);
                return NULL;
            }
    }
    connection->user_groups = ALLGROUP;
    
#ifdef DEBUG_ENABLE
    if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_PACKET)){
        g_message("Packet: ");
        print_connection(connection,NULL);
    }
#endif
    return connection;
}

/**
 * Parse message content for message of type #AUTH_CONN_DESTROY 
 * or #AUTH_CONN_UPDATE using structure ::nu_conntrack_message_t structure.
 *
 * Send a message FREE_MESSAGE or UPDATE_MESSAGE to limited_connections_queue
 * (member of ::nuauthdatas).
 * 
 * \param dgram Pointer to packet datas
 * \param dgram_size Number of bytes in the packet
 */
void authpckt_conntrack (unsigned char *dgram, unsigned int dgram_size)
{
    struct nu_conntrack_message_t* conntrack;
    tracking_t* datas;
    struct internal_message *message;

    /* Check message content size */
    if (dgram_size != sizeof(struct nu_conntrack_message_t))
    {
        // TODO: Display warning
        return;
    }
    
    /* Create a message for limited_connexions_queue */
    conntrack = (struct nu_conntrack_message_t*)dgram;
    datas = g_new0(tracking_t, 1);
    message = g_new0(struct internal_message, 1);
    datas->protocol = conntrack->ipv4_protocol;
    datas->saddr = ntohl(conntrack->ipv4_src);
    datas->daddr = ntohl(conntrack->ipv4_dst);
    if (conntrack->ipv4_protocol == IPPROTO_ICMP) {
        datas->type = ntohs(conntrack->src_port);
        datas->code = ntohs(conntrack->dest_port);
    } else {
        datas->source = ntohs(conntrack->src_port);
        datas->dest = ntohs(conntrack->dest_port);
    }               
    message->datas = datas;
    if (conntrack->msg_type == AUTH_CONN_DESTROY)
        message->type = FREE_MESSAGE;
    else
        message->type = UPDATE_MESSAGE;
    g_async_queue_push (nuauthdatas->limited_connections_queue, message);
}

/**
 * Parse a datagram packet from NuFW using structure 
 * ::nufw_to_nuauth_message_header_t. Create a connection
 * (type ::connection_t) for message of type #AUTH_REQUEST or #AUTH_CONTROL.
 * Update conntrack for message of type #AUTH_CONN_DESTROY 
 * or #AUTH_CONN_UPDATE.
 *
 * Call:
 *   - authpckt_new_connection(): Message type #AUTH_REQUEST or #AUTH_CONTROL
 *   - authpckt_conntrack(): Message type #AUTH_CONN_DESTROY
 *     or #AUTH_CONN_UPDATE
 * 
 * \param dgram Pointer to datagram
 * \param dgramsize Size of the datagram (in bytes)
 * \return Pointer to new connection or NULL
 */
connection_t* authpckt_decode(unsigned char *dgram, unsigned int dgram_size)
{
    nufw_to_nuauth_message_header_t *header;

    /* Check message header size */
    if (dgram_size < sizeof(nufw_to_nuauth_message_header_t))
        return NULL;
    
    /* Check protocol version */
    header = (nufw_to_nuauth_message_header_t *)dgram;
    if (header->protocol_version != PROTO_VERSION)
        return NULL;

    /* Check if message length looks correct */
    if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_PACKET)){
        int msg_length = ntohs(header->msg_length);
        if (msg_length != dgram_size){
            g_warning("packet seems to contain other datas, left %d byte(s) (announced : %d, get : %d)",
                    dgram_size - msg_length,
                    msg_length,
                    dgram_size);
        }
    }

    switch (header->msg_type){
        case AUTH_REQUEST:
        case AUTH_CONTROL:
            return authpckt_new_connection(dgram, dgram_size);
            
        case AUTH_CONN_DESTROY:
        case AUTH_CONN_UPDATE:
            authpckt_conntrack(dgram, dgram_size);
            return NULL;

        default:
            if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_PACKET)) {
                g_message("Not for us\n");
            }
    }
    return NULL;
}


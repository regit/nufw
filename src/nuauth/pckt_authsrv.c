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
int get_ip_headers(tracking_t *tracking, unsigned char *dgram)
{
    struct iphdr * iphdrs = (struct iphdr *)dgram;
    /* check IP version (should be IPv4) */
    if (iphdrs->version == 4){
        tracking->saddr = ntohl(iphdrs->saddr);
        tracking->daddr = ntohl(iphdrs->daddr);
        tracking->protocol = iphdrs->protocol;
        return 4*iphdrs->ihl;
    }
#ifdef DEBUG_ENABLE
    if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_PACKET)){
        g_message("IP version is %d, ihl : %d",iphdrs->version,iphdrs->ihl);
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
 */
void get_udp_headers(tracking_t *tracking, unsigned char *dgram)
{
    struct udphdr * udphdrs=(struct udphdr *)dgram;
    tracking->source=ntohs(udphdrs->source);
    tracking->dest=ntohs(udphdrs->dest);
    tracking->type=0;
    tracking->code=0;
}


/**
 * Fill TCP fields (source and dest) of the connection tracking
 * (::tracking_t) structure.
 *
 * \param connection Pointer to a connection
 * \param dgram Pointer to packet datas
 * \return State of the TCP connection (open, established, close).
 */
tcp_state_t get_tcp_headers(tracking_t *tracking, unsigned char *dgram)
{
    struct tcphdr * tcphdrs=(struct tcphdr *) dgram;
    tracking->source=ntohs(tcphdrs->source);
    tracking->dest=ntohs(tcphdrs->dest);
    tracking->type=0;
    tracking->code=0;

    /* test if fin ack or syn */
    /* if fin ack return 0 end of connection */
    if (tcphdrs->fin || tcphdrs->rst )
        return TCP_STATE_CLOSE;

    /* if syn return 1 */
    if (tcphdrs->syn) {
        if (tcphdrs->ack){
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
 */
void get_icmp_headers(tracking_t *tracking, unsigned char *dgram)
{
    struct icmphdr * icmphdrs= (struct icmphdr *)dgram;
    tracking->source=0;
    tracking->dest=0;
    tracking->type=icmphdrs->type;
    tracking->code=icmphdrs->code;
}

/**
 * Parse message content for message of type #AUTH_REQUEST or #AUTH_CONTROL.
 *
 * Message structure:
 * \code
 *  ofs | size | description
 * -----+------+-------------------
 *   0  |   2  | Message length
 *   2  |   4  | Netfilter packet unique identifier
 *   6  |   4  | Timestamp (Epoch format)
 *  10  |   n  | IPv4 headers (see get_ip_headers()) +
 *      |      |      TCP headers (get_tcp_headers())
 *      |      |   or UDP headers (get_udp_headers())
 *      |      |   or ICMP message (get_icmp_headers())
 * \endcode
 */
connection_t* authpckt_new_connection(int8_t msg_type, unsigned char *dgram, int  dgramsiz) {
    unsigned char *pointer;
    uint16_t data_len;
    int offset; 

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

    /* parse packet */
    pointer = dgram;
    data_len = ntohs(*(uint16_t *)pointer);
    if (data_len != dgramsiz){
        if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_PACKET)){
            g_warning("packet seems to contain other datas, left %d byte(s) (announced : %d, get : %d)",
                    dgramsiz-data_len,
                    data_len,
                    dgramsiz);
        }
    }
    pointer += sizeof(uint16_t);
    connection->acl_groups = NULL;
    connection->user_groups = NULL;

    connection->packet_id = g_slist_append(NULL, GUINT_TO_POINTER(ntohl(*(uint32_t *)pointer)));
#ifdef DEBUG_ENABLE
    if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_PACKET)) {
        g_message("Working on  %u\n",(uint32_t)GPOINTER_TO_UINT(connection->packet_id->data));
    }
#endif
    pointer += sizeof(uint32_t);

    /* timestamp */
    connection->timestamp = ntohl(*(uint32_t *)pointer);
    if ( connection->timestamp == 0 )
        connection->timestamp = time(NULL);
    pointer += sizeof(int32_t);

    /* get ip headers till tracking is filled */
    offset = get_ip_headers(&connection->tracking, pointer);
    if (offset == 0) 
    {
        if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_PACKET))
            g_message ("Can't parse IP headers\n");
        free_connection(connection);
        return NULL;
    }
    pointer += offset;

    /* get saddr and daddr */
    /* check if proto is in Hello mode list (when hello authentication is used) */
    if ( nuauthconf->hello_authentication &&  localid_authenticated_protocol(connection->tracking.protocol) ) {
        connection->state=AUTH_STATE_HELLOMODE;
    } 
    switch (connection->tracking.protocol) {
        case IPPROTO_TCP:
        {
            tcp_state_t tcp_state = get_tcp_headers(&connection->tracking, pointer);
            switch (tcp_state){
                case TCP_STATE_OPEN:
                    break; 
                case TCP_STATE_CLOSE:
                    if (msg_type == AUTH_CONTROL ){
                        log_user_packet(*connection, TCP_STATE_CLOSE);
                        free_connection(connection);
                        return NULL;
                    }
                    break;
                case TCP_STATE_ESTABLISHED:
                    if (msg_type == AUTH_CONTROL ){
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
            get_udp_headers(&connection->tracking, pointer);
            break;

        case IPPROTO_ICMP:
            get_icmp_headers(&connection->tracking, pointer);
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
 * or #AUTH_CONN_UPDATE.
 *
 * Message structure:
 * \code
 *  ofs | size | description
 * -----+------+-------------------
 *   0  |   2  | Message length 
 *   2  |   4  | Timeout 
 *   6  |   4  | IPv4 source
 *  10  |   4  | IPv4 destination 
 *  14  |   1  | IPv4 protocol
 *  15  |   2  | TCP/UDP source port 
 *  17  |   2  | TCP/UDP destination port 
 * \endcode
 * (see ::nuv2_conntrack_message structure)
 */
void authpckt_conntrack (nufw_message_t msg_type, unsigned char *dgram) {
    struct nuv2_conntrack_message* msg = (struct nuv2_conntrack_message*)dgram;
    tracking_t* datas=g_new0(tracking_t,1);
    struct internal_message  *message = g_new0(struct internal_message,1);
    datas->protocol = msg->ipproto;
    datas->saddr = ntohl(msg->src);
    datas->daddr = ntohl(msg->dst);
    if (msg->ipproto == IPPROTO_ICMP) {
        datas->type = ntohs(msg->sport);
        datas->code = ntohs(msg->dport);
    } else {
        datas->source = ntohs(msg->sport);
        datas->dest = ntohs(msg->dport);
    }               
    message->datas = datas;
    if (msg_type == AUTH_CONN_DESTROY)
        message->type = FREE_MESSAGE;
    else
        message->type = UPDATE_MESSAGE;
}

/**
 * Decode a datagram packet from NuFW. Create a connection 
 * (type ::connection_t) for message of type #AUTH_REQUEST or #AUTH_CONTROL.
 * Update conntrack for message of type #AUTH_CONN_DESTROY or 
 * #AUTH_CONN_UPDATE.
 *
 * Structure of a datagram:
 * \code
 *  ofs | size | description
 * -----+------+-------------------
 *   0  |   1  | Protocol version (equals to PROTO_VERSION)
 *   1  |   1  | Message type (from nufw_message_t)
 *   2  |   n  | Mesage content (parse by next function)
 * \endcode
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
connection_t* authpckt_decode(unsigned char *dgram, unsigned int dgramsize)
{
    nufw_message_t msg_type;

    if (dgram[0] != PROTO_VERSION)
        return NULL;

    msg_type = dgram[1];
    switch (msg_type){
        case AUTH_REQUEST:
        case AUTH_CONTROL:
            return authpckt_new_connection(msg_type, dgram+2, dgramsize);
            
        case AUTH_CONN_DESTROY:
        case AUTH_CONN_UPDATE:
            authpckt_conntrack(msg_type, dgram);
            return NULL;

        default:
            if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_PACKET)) {
                g_message("Not for us\n");
            }
    }
    return NULL;
}




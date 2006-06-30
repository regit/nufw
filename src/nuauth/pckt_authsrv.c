/*
 ** Copyright(C) 2003-2006 Eric Leblond <regit@inl.fr>
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
#include <errno.h>

/**
 * Parse message content for message of type #AUTH_REQUEST or #AUTH_CONTROL
 * using structure ::nufw_to_nuauth_auth_message_t. 
 * 
 * \param dgram Pointer to packet datas
 * \param dgram_size Number of bytes in the packet
 * \param conn Pointer of pointer to the ::connection_t that we have to authenticate
 * \return A new connection or NULL if fails 
 */
nu_error_t authpckt_new_connection(unsigned char *dgram, unsigned int dgram_size,connection_t **conn)
{
    nufw_to_nuauth_auth_message_t *msg = (nufw_to_nuauth_auth_message_t *)dgram;
    unsigned int ip_hdr_size; 
    connection_t *connection;

    if (dgram_size < sizeof(nufw_to_nuauth_auth_message_t))
    {
        /* TODO: Display warning message */
        return NU_EXIT_ERROR;
    }
    dgram += sizeof(nufw_to_nuauth_auth_message_t);
    dgram_size -= sizeof(nufw_to_nuauth_auth_message_t);

    /* allocate new connection */
    connection = g_new0(connection_t, 1);
    if (connection == NULL){
        log_message (WARNING, AREA_PACKET, "Can not allocate connection");
        return NU_EXIT_ERROR;
    }
#ifdef PERF_DISPLAY_ENABLE
    gettimeofday(&(connection->arrival_time),NULL);
#endif
    connection->acl_groups = NULL;
    connection->user_groups = NULL;
    connection->expire = -1;

    connection->packet_id = g_slist_append(NULL, GUINT_TO_POINTER(ntohl(msg->packet_id)));
    debug_log_message(DEBUG, AREA_PACKET,
        "Auth pckt: Working on new connection (id=%u)",
        (uint32_t)GPOINTER_TO_UINT(connection->packet_id->data));

    /* timestamp */
    connection->timestamp = ntohl(msg->timestamp);
    if ( connection->timestamp == 0 )
        connection->timestamp = time(NULL);

    /* get ip headers till tracking is filled */
    ip_hdr_size = get_ip_headers(&connection->tracking, dgram, dgram_size);
    if (ip_hdr_size == 0)  {
        log_message (WARNING, AREA_PACKET, "Can't parse IP headers");
        free_connection(connection);
        return NU_EXIT_ERROR;
    }
    dgram += ip_hdr_size;
    dgram_size -= ip_hdr_size;

    /* get saddr and daddr */
    /* check if proto is in Hello mode list (when hello authentication is used) */
    if ( nuauthconf->hello_authentication &&  localid_authenticated_protocol(connection->tracking.protocol) ) {
        connection->state = AUTH_STATE_HELLOMODE;
        *conn = connection;
    } else {
        connection->state = AUTH_STATE_AUTHREQ;
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
			connection->state = AUTH_STATE_DONE;
                        log_user_packet(connection, TCP_STATE_CLOSE);
                        free_connection(connection);
                        return NU_EXIT_NO_RETURN;
                    }
                    break;
                case TCP_STATE_ESTABLISHED:
                    if (msg->msg_type == AUTH_CONTROL ){
			connection->state = AUTH_STATE_DONE;
                        log_user_packet(connection, TCP_STATE_ESTABLISHED);
                        free_connection(connection);
                        return NU_EXIT_NO_RETURN;
                    }
                    break;
                default:
                    log_message(WARNING, AREA_PACKET, "Can't parse TCP headers\n");
                    free_connection(connection);
                    return NU_EXIT_ERROR;
            }
            break;
        }
	break;

        case IPPROTO_UDP:
            if (get_udp_headers(&connection->tracking, dgram, dgram_size) < 0) {
                free_connection(connection);
                return NU_EXIT_OK;
            }
            break;

        case IPPROTO_ICMP:
            if (get_icmp_headers(&connection->tracking, dgram, dgram_size) < 0) {
                free_connection(connection);
                return NU_EXIT_OK;
            }
            break;

        case IPPROTO_ICMPV6:
            if (get_icmpv6_headers(&connection->tracking, dgram, dgram_size) < 0) {
                free_connection(connection);
                return NU_EXIT_OK;
            }
            break;

        default:
            if ( connection->state != AUTH_STATE_HELLOMODE){
                log_message (WARNING, AREA_PACKET,
                        "Can't parse protocol %u",
                        connection->tracking.protocol);
                free_connection(connection);
                return NU_EXIT_ERROR;
            }
    }
    connection->user_groups = ALLGROUP;
    
#ifdef DEBUG_ENABLE
    if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_PACKET)){
        g_message("Packet: ");
        print_connection(connection,NULL);
    }
#endif
    *conn = connection;
    return NU_EXIT_OK;
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

    debug_log_message(VERBOSE_DEBUG, AREA_PACKET,
        "Auth conntrack: Working on new packet");

    /* Check message content size */
    if (dgram_size != sizeof(struct nu_conntrack_message_t))
    {
        debug_log_message(WARNING, AREA_PACKET,
            "Auth conntrack: Improper length of packet");
        return;
    }
    
    /* Create a message for limited_connexions_queue */
    conntrack = (struct nu_conntrack_message_t*)dgram;
    datas = g_new0(tracking_t, 1);
    message = g_new0(struct internal_message, 1);
    datas->protocol = conntrack->ip_protocol;

    datas->saddr.s6_addr32[0] = ntohl(conntrack->ip_src.s6_addr32[0]);
    datas->saddr.s6_addr32[1] = ntohl(conntrack->ip_src.s6_addr32[1]);
    datas->saddr.s6_addr32[2] = ntohl(conntrack->ip_src.s6_addr32[2]);
    datas->saddr.s6_addr32[3] = ntohl(conntrack->ip_src.s6_addr32[3]);

    datas->daddr.s6_addr32[0] = ntohl(conntrack->ip_dst.s6_addr32[0]);
    datas->daddr.s6_addr32[1] = ntohl(conntrack->ip_dst.s6_addr32[1]);
    datas->daddr.s6_addr32[2] = ntohl(conntrack->ip_dst.s6_addr32[2]);
    datas->daddr.s6_addr32[3] = ntohl(conntrack->ip_dst.s6_addr32[3]);
    
    if ((conntrack->ip_protocol == IPPROTO_ICMP) || (conntrack->ip_protocol == IPPROTO_ICMPV6)) {
        datas->type = ntohs(conntrack->src_port);
        datas->code = ntohs(conntrack->dest_port);
    } else {
        datas->source = ntohs(conntrack->src_port);
        datas->dest = ntohs(conntrack->dest_port);
    }               
    message->datas = datas;
    if (conntrack->msg_type == AUTH_CONN_DESTROY) {
        message->type = FREE_MESSAGE;
        debug_log_message(VERBOSE_DEBUG, AREA_PACKET,
                "Auth conntrack: Sending free message");
    } else {
        message->type = UPDATE_MESSAGE;
        debug_log_message(VERBOSE_DEBUG, AREA_PACKET,
                "Auth conntrack: Sending Update message");
    }
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
 * \param dgram_size Size of the datagram (in bytes)
 * \param conn Pointer of pointer to the ::connection_t that will be modified
 * \return 
 *   - #NU_EXIT_ERROR if failure
 *   - #NU_EXIT_OK if ok and conn created
 *   - #NU_EXIT_NO_RETURN if no conn is needed but work is ok
 */
nu_error_t authpckt_decode(unsigned char *dgram, unsigned int dgram_size, connection_t** conn)
{
    nufw_to_nuauth_message_header_t *header;

    /* Check message header size */
    if (dgram_size < sizeof(nufw_to_nuauth_message_header_t))
        return NU_EXIT_ERROR;
    
    /* Check protocol version */
    header = (nufw_to_nuauth_message_header_t *)dgram;
    if (header->protocol_version != PROTO_VERSION)
        return NU_EXIT_ERROR;

    /* Check if message length looks correct */
    if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_PACKET)){
        uint16_t msg_length = ntohs(header->msg_length);
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
            return  authpckt_new_connection(dgram, dgram_size,conn);
            break;
        case AUTH_CONN_DESTROY:
        case AUTH_CONN_UPDATE:
            authpckt_conntrack(dgram, dgram_size);
            *conn = NULL;
            return NU_EXIT_NO_RETURN;
        default:
            log_message(VERBOSE_DEBUG, AREA_PACKET, "Not for us");
            return 0;
    }
    return NU_EXIT_OK;
}


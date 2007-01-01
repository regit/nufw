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

#include "pckt_authsrv_v3.h"

/**
 * Parse packet payload
 */

nu_error_t parse_dgram(connection_t* connection,unsigned char* dgram, unsigned int dgram_size,connection_t** conn,nufw_message_t msg_type)
{
    unsigned int ip_hdr_size;
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
                    if (msg_type == AUTH_CONTROL ){
                        connection->state = AUTH_STATE_DONE;
                        log_user_packet(connection, TCP_STATE_CLOSE);
                        free_connection(connection);
                        return NU_EXIT_NO_RETURN;
                    }
                    break;
                case TCP_STATE_ESTABLISHED:
                    if (msg_type == AUTH_CONTROL ){
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
            if (connection->state != AUTH_STATE_HELLOMODE) {
                log_message (WARNING, AREA_PACKET,
                        "Can't parse protocol %u",
                        connection->tracking.protocol);
                free_connection(connection);
                return NU_EXIT_ERROR;
            }
    }
    return NU_EXIT_CONTINUE;
}

/**
 * Parse message content for message of type #AUTH_REQUEST or #AUTH_CONTROL
 * using structure ::nufw_to_nuauth_auth_message_t.
 *
 * \param dgram Pointer to packet datas
 * \param dgram_size Number of bytes in the packet
 * \param conn Pointer of pointer to the ::connection_t that we have to authenticate
 * \return A nu_error_t
 */
nu_error_t authpckt_new_connection(unsigned char *dgram, unsigned int dgram_size,connection_t **conn)
{
    nuv4_nufw_to_nuauth_auth_message_t *msg = (nuv4_nufw_to_nuauth_auth_message_t *)dgram;
    connection_t *connection;
    nu_error_t ret;

    if (dgram_size < sizeof(nuv4_nufw_to_nuauth_auth_message_t))
    {
        /** \todo Display warning message */
        return NU_EXIT_ERROR;
    }
    dgram += sizeof(nuv4_nufw_to_nuauth_auth_message_t);
    dgram_size -= sizeof(nuv4_nufw_to_nuauth_auth_message_t);

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
    if ( connection->timestamp == 0 ){
        connection->timestamp = time(NULL);
    }

    /* connection is proto v4 because we are here */
    connection->nufw_version =  PROTO_VERSION_V22;

    ret = parse_dgram(connection,dgram,dgram_size,conn,msg->msg_type);
    if (ret != NU_EXIT_CONTINUE){
        return ret;
    }

    /** \todo parse supplementary fields */

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
    struct nuv4_conntrack_message_t* conntrack;
    struct accounted_connection* datas;
    struct internal_message *message;
    tcp_state_t pstate;

    debug_log_message(VERBOSE_DEBUG, AREA_PACKET,
        "Auth conntrack: Working on new packet");

    /* Check message content size */
    if (dgram_size != sizeof(struct nuv4_conntrack_message_t)){
        debug_log_message(WARNING, AREA_PACKET,
            "Auth conntrack: Improper length of packet");
        return;
    }

    /* Create a message for limited_connexions_queue */
    conntrack = (struct nuv4_conntrack_message_t*)dgram;
    datas = g_new0(struct accounted_connection, 1);
    message = g_new0(struct internal_message, 1);

    datas->tracking.protocol = conntrack->ip_protocol;

    datas->tracking.saddr.s6_addr32[0] = conntrack->ip_src.s6_addr32[0];
    datas->tracking.saddr.s6_addr32[1] = conntrack->ip_src.s6_addr32[1];
    datas->tracking.saddr.s6_addr32[2] = conntrack->ip_src.s6_addr32[2];
    datas->tracking.saddr.s6_addr32[3] = conntrack->ip_src.s6_addr32[3];

    datas->tracking.daddr.s6_addr32[0] = conntrack->ip_dst.s6_addr32[0];
    datas->tracking.daddr.s6_addr32[1] = conntrack->ip_dst.s6_addr32[1];
    datas->tracking.daddr.s6_addr32[2] = conntrack->ip_dst.s6_addr32[2];
    datas->tracking.daddr.s6_addr32[3] = conntrack->ip_dst.s6_addr32[3];

    if ((conntrack->ip_protocol == IPPROTO_ICMP) || (conntrack->ip_protocol == IPPROTO_ICMPV6)) {
        datas->tracking.type = ntohs(conntrack->src_port);
        datas->tracking.code = ntohs(conntrack->dest_port);
    } else {
        datas->tracking.source = ntohs(conntrack->src_port);
        datas->tracking.dest = ntohs(conntrack->dest_port);
    }

    datas->packets_in=conntrack->packets_in;
    datas->bytes_in=conntrack->bytes_in;
    datas->packets_out=conntrack->packets_out;
    datas->bytes_out=conntrack->bytes_out;

    message->datas = datas;

    if (conntrack->msg_type == AUTH_CONN_DESTROY) {
        message->type = FREE_MESSAGE;
        debug_log_message(VERBOSE_DEBUG, AREA_PACKET,
                "Auth conntrack: Sending free message");
        pstate=TCP_STATE_CLOSE;
    } else {
        message->type = UPDATE_MESSAGE;
        debug_log_message(VERBOSE_DEBUG, AREA_PACKET,
                "Auth conntrack: Sending Update message");
        pstate=TCP_STATE_ESTABLISHED;
    }

    log_user_packet_from_accounted_connection(datas,pstate);
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
 * \param pdgram Pointer to datagram
 * \param pdgram_size Pointer to size of the datagram (in bytes)
 * \param conn Pointer of pointer to the ::connection_t that will be modified
 * \return
 *   - #NU_EXIT_ERROR if failure
 *   - #NU_EXIT_OK if ok and conn created
 *   - #NU_EXIT_NO_RETURN if no conn is needed but work is ok
 */
nu_error_t authpckt_decode(unsigned char **pdgram, unsigned int * pdgram_size, connection_t** conn)
{
  unsigned char* dgram=*pdgram;
  unsigned int dgram_size=*pdgram_size;
  nufw_to_nuauth_message_header_t *header;

  /* Switch following protocol version */
  header = (nufw_to_nuauth_message_header_t *)dgram;
  switch (header->protocol_version){
    case PROTO_VERSION_V22:
        switch (header->msg_type){
          case AUTH_REQUEST:
          case AUTH_CONTROL:
              authpckt_new_connection(dgram, dgram_size,conn);
              if (ntohs(header->msg_length) < dgram_size){
                  *pdgram_size = dgram_size - ntohs(header->msg_length);
                  *pdgram = dgram + ntohs(header->msg_length);
              } else {
                  *pdgram_size=0;
              }
              return NU_EXIT_OK;

              break;
          case AUTH_CONN_DESTROY:
          case AUTH_CONN_UPDATE:
              authpckt_conntrack(dgram, dgram_size);
              *conn = NULL;
              if (ntohs(header->msg_length) < dgram_size){
                  *pdgram_size = dgram_size - ntohs(header->msg_length);
                  *pdgram = dgram + ntohs(header->msg_length);
              } else {
                  *pdgram_size=0;
              }
              return NU_EXIT_NO_RETURN;
          default:
              log_message(VERBOSE_DEBUG, AREA_PACKET, "NuFW packet type is unknown");
              return NU_EXIT_ERROR;
        }
        return NU_EXIT_OK;
    case PROTO_VERSION_V20:
        switch (header->msg_type){
          case AUTH_REQUEST:
          case AUTH_CONTROL:
              authpckt_new_connection_v3(dgram, dgram_size,conn);
              if (ntohs(header->msg_length) < dgram_size){
                  *pdgram_size = dgram_size - ntohs(header->msg_length);
                  *pdgram = dgram + ntohs(header->msg_length);
              } else {
                  *pdgram_size=0;
              }
              return NU_EXIT_OK;

              break;
          case AUTH_CONN_DESTROY:
          case AUTH_CONN_UPDATE:
              authpckt_conntrack_v3(dgram, dgram_size);
              *conn = NULL;
              if (ntohs(header->msg_length) < dgram_size){
                  *pdgram_size = dgram_size - ntohs(header->msg_length);
                  *pdgram = dgram + ntohs(header->msg_length);
              } else {
                  *pdgram_size=0;
              }
              return NU_EXIT_NO_RETURN;
          default:
              log_message(VERBOSE_DEBUG, AREA_PACKET, "NuFW packet type is unknown");
              return NU_EXIT_ERROR;
        }
        return NU_EXIT_OK;
    default:
        {
            log_message(WARNING, AREA_PACKET, "NuFW protocol is unknown");
        }

  }
  return NU_EXIT_OK;
}

/**
 * \return 0 if there is an error, value of protocol elsewhere
 */
unsigned char get_proto_version_from_packet(const unsigned char* dgram,size_t dgram_size)
{
  nufw_to_nuauth_message_header_t *header;

  if (dgram_size<sizeof(nufw_to_nuauth_message_header_t)){
      return 0;
  }
  /* Check protocol version */
  header = (nufw_to_nuauth_message_header_t *)dgram;
  /* Is protocol supported */
  if ( check_protocol_version(header->protocol_version) == NU_EXIT_OK ){
      return header->protocol_version;
  } else {
      return 0;
  }
}

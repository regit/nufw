/*
 ** Copyright (C) 2005-2006 INL http://www.inl.fr/
 **   written by Eric Leblond <regit@inl.fr>
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

/** \file nufw/conntrack.c
 *  \brief Connection tracking
 *   
 * Connection tracking function if NuFW is compiled with \#HAVE_LIBCONNTRACK.
 */

#include "nufw.h"
#ifdef HAVE_LIBCONNTRACK

/**
 * Send message to TLS tunnel on new netfilter conntrack event.
 * 
 * \param arg Pointer to a connection of type ::nfct_conntrack
 * \param type Event type (IPCTNL_MSG_CT_DELETE, IPCTNL_MSG_CT_NEW, ...)
 * \param flags Event flags (no used)
 * \param data (no data, NULL pointer)
 * \return If an error occurs returns -1, else returns 0
 */
int update_handler (void *arg, unsigned int flags, int type,void *data)
{
#if 1
char ascii[INET6_ADDRSTRLEN];
#endif
    struct nfct_conntrack *conn = arg;
    struct nuv4_conntrack_message_t message;
    int ret;

    /* if nufw_conntrack_uses_mark is set we should have mark set here 
     * This REQUIRES correct CONNMARK rules and correct kernel */
    if (nufw_conntrack_uses_mark == 1){
        if (conn->mark == 0){
            return 0;
        }
    }
    message.protocol_version=PROTO_VERSION;
    message.msg_length= htons(sizeof(struct nuv4_conntrack_message_t));
    switch (type) {
        case NFCT_MSG_DESTROY:
            message.msg_type=AUTH_CONN_DESTROY;
            debug_log_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_VERBOSE_DEBUG,
                    "Destroy event to be send to nuauth.");
            break;
        case NFCT_MSG_UPDATE:
             if (! (conn->status & IPS_ASSURED)) {
                 return 0;
             }
#if 0
            if (flags & (NLM_F_CREATE|NLM_F_EXCL)){
                debug_log_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_VERBOSE_DEBUG,
                        "Not our business (type %d).",type);
                return 0;
            }
#endif
            message.msg_type=AUTH_CONN_UPDATE;
            debug_log_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_VERBOSE_DEBUG,
                    "Update event to be send to nuauth.");
            break;
        default:
            debug_log_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_INFO,
                        "Strange, get message (type %d) not %d or %d",type,NFCT_MSG_DESTROY,NFCT_MSG_UPDATE);
            return 0;
    }
    message.ip_protocol=conn->tuple[0].protonum;
#if 1     
    printf("(*) New packet ; ");
    if (inet_ntop(conn->tuple[0].l3protonum, &conn->tuple[0].src, ascii, sizeof(ascii)))
    {
        printf(" src=%s", ascii);
    }
    if (inet_ntop(conn->tuple[0].l3protonum, &conn->tuple[0].dst, ascii, sizeof(ascii)))
    {
        printf(" dst=%s", ascii);
    }
    printf("\n");
#endif    
    if (conn->tuple[0].l3protonum == AF_INET6) {
        message.ip_src.s6_addr32[0] = 0;
        message.ip_src.s6_addr32[1] = 0;
        message.ip_src.s6_addr32[2] = 0xffff0000;
        message.ip_src.s6_addr32[3] = conn->tuple[0].src.v4;

        message.ip_dst.s6_addr32[0] = 0;
        message.ip_dst.s6_addr32[1] = 0;
        message.ip_dst.s6_addr32[2] = 0xffff0000;
        message.ip_dst.s6_addr32[3] = conn->tuple[0].dst.v4;
    } else {
        memcpy(&message.ip_src, &conn->tuple[0].src.v6, sizeof(message.ip_src));
        memcpy(&message.ip_dst, &conn->tuple[0].dst.v6, sizeof(message.ip_dst));
    }

    switch (conn->tuple[0].protonum){
        case IPPROTO_TCP :
            message.src_port = conn->tuple[0].l4src.tcp.port;
            message.dest_port = conn->tuple[0].l4dst.tcp.port;
            break;
        case IPPROTO_UDP :
            message.src_port = conn->tuple[0].l4src.udp.port;
            message.dest_port = conn->tuple[0].l4dst.udp.port;
            break;
        default :
            message.src_port = 0;
            message.dest_port = 0;
            break;
    }

    if (pthread_mutex_trylock(&tls.mutex) != EBUSY){
        if (tls.session){
            debug_log_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG,
                    "Sending conntrack event to nuauth.");
            ret = gnutls_record_send(
                    *(tls.session),
                    &message,
                    sizeof(struct nuv4_conntrack_message_t)
                    ); 
            if (ret <0){
                if ( gnutls_error_is_fatal(ret) ){
                    /* warn sender thread that it will need to reconnect at next access */
                    tls.auth_server_running=0;
                    pthread_cancel(tls.auth_server);
                    pthread_mutex_unlock(&tls.mutex);
                    return -1;
                }
            }
        }
        pthread_mutex_unlock(&tls.mutex);
    } 
    return 0;
}

/**
 * Install netfilter conntrack event handler: update_handler(). 
 *
 * \return NULL pointer
 */
void* conntrack_event_handler(void *data)
{
    struct nfct_handle *cth;
    int res;
    
    debug_log_printf(DEBUG_AREA_MAIN,DEBUG_LEVEL_VERBOSE_DEBUG, "Starting conntrack thread");
    cth = nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_DESTROY|NF_NETLINK_CONNTRACK_UPDATE);
    if (!cth)
        log_printf(DEBUG_LEVEL_WARNING, "Not enough memory to open netfilter conntrack");
    nfct_register_callback(cth, update_handler, NULL); 
    res = nfct_event_conntrack(cth);
    nfct_close(cth);
    debug_log_printf(DEBUG_AREA_MAIN,DEBUG_LEVEL_VERBOSE_DEBUG, "Conntrack thread has exited");
    return NULL;
}

#endif   /* ifdef HAVE_LIBCONNTRACK */

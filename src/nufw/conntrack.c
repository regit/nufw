/*
 ** Copyright (C) 2005 INL http://www.inl.fr/
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
 * Connection tracking function if NuFW is compiled with #HAVE_LIBCONNTRACK.
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
    struct nfct_conntrack *conn = arg;
    struct nuv2_conntrack_message message;
    int ret;

    if (nufw_set_mark == 1){
        if (conn->mark == 0){
            return 0;
        }
    }
    message.protocol=1;
    switch (type) {
        case IPCTNL_MSG_CT_DELETE:
            message.type=AUTH_CONN_DESTROY;
            break;
        case IPCTNL_MSG_CT_NEW:
            /* check for ASSURED, elsewhere timeout is so small it is useless to
             * have a fixed one */
            if (conn->status & IPS_ASSURED) {
                message.type=AUTH_CONN_UPDATE;
            } else {
                /* not really your business we leave */
                return 0;
            }
            break;
        default:
            message.type=AUTH_CONN_UPDATE;
    }
    message.ipproto=conn->tuple[0].protonum;
    message.src= conn->tuple[0].src.v4;
    message.dst=conn->tuple[0].dst.v4;

    switch (conn->tuple[0].protonum){
        case IPPROTO_TCP :
            message.sport = conn->tuple[0].l4src.tcp.port;
            message.dport = conn->tuple[0].l4dst.tcp.port;
            break;
        case IPPROTO_UDP :
            message.sport = conn->tuple[0].l4src.udp.port;
            message.dport = conn->tuple[0].l4dst.udp.port;
            break;
        default :
            message.sport = 0;
            message.dport = 0;
            break;
    }
    ret = gnutls_record_send(
            *(tls.session),
            &message,
            sizeof(struct nuv2_conntrack_message)
            ); 
    if (ret <0){
        if ( gnutls_error_is_fatal(ret) ){
            pthread_mutex_lock(tls.mutex);
            /* warn sender thread that it will need to reconnect at next access */
            tls.auth_server_running=0;
            pthread_cancel(tls.auth_server);
            pthread_mutex_unlock(tls.mutex);
            return -1;
        }
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
    if (nufw_set_mark == 1){
        cth = nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_DESTROY|NF_NETLINK_CONNTRACK_UPDATE);
    } else {
        cth = nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_DESTROY);
    }
    if (!cth)
        log_printf(DEBUG_LEVEL_WARNING, "Not enough memory to open netfilter conntrack");
    nfct_register_callback(cth, update_handler, NULL);
    res = nfct_event_conntrack(cth);
    nfct_close(cth);
    return NULL;
}

#endif   /* ifdef HAVE_LIBCONNTRACK */

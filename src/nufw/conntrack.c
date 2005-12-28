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


#include "nufw.h"
#ifdef HAVE_LIBCONNTRACK

int update_handler (void *arg, unsigned int flags, int type,void *data)
{
  struct nfct_conntrack *conn = arg;
  struct nuv2_destroy_message message;
  int ret;


  message.protocol=1;
  message.type=AUTH_CONN_DESTROY;
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
                  *(tls.session) ,
                  &message,
                  sizeof(struct nuv2_destroy_message)
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

void* conntrack_event_handler(void *data)
{
    struct nfct_handle *cth;
    int res;
    cth = nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_DESTROY);
    if (!cth)
      fprintf(stderr,"%s : Not enough memory",PACKAGE_NAME);
    nfct_register_callback(cth, update_handler, NULL);
    res = nfct_event_conntrack(cth);
    nfct_close(cth);

}

#endif


/*
 ** Copyright(C) 2003 Eric Leblond <eric@regit.org>
 **		     Vincent Deffontaines <vincent@gryzor.com>
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
#include <string.h>
#include <errno.h>


G_MODULE_EXPORT gint user_packet_logs (connection element, int state){
    char *str_state;
    char source_addr[16];
    char dest_addr[16];
    struct in_addr oneip;

    /* contruct request */
    switch (state) {
      case STATE_OPEN:
        str_state="Open ";
        break;
      case STATE_CLOSE:
        str_state="Close ";
        break;
      case STATE_ESTABLISHED:
        str_state="Established ";
        break;
      case STATE_DROP:
          str_state="Drop ";

    } 
    oneip.s_addr=htonl((element.tracking_hdrs).saddr);
    strncpy(source_addr,inet_ntoa(oneip),16);
    oneip.s_addr=htonl((element.tracking_hdrs).daddr);
    strncpy(dest_addr,inet_ntoa(oneip),16);

    if ( ((element.tracking_hdrs).protocol == IPPROTO_TCP) || ((element.tracking_hdrs).protocol == IPPROTO_UDP) ) {
        g_message("%s[%u] %ld : SRC=%s DST=%s PROTO=%d SPT=%u DPT=%u",
            str_state,
            element.user_id,
            element.timestamp,
            source_addr,
            dest_addr,
            (element.tracking_hdrs).protocol,
            (element.tracking_hdrs).source,
            (element.tracking_hdrs).dest
            );
    } else {
        g_message("[%u] %ld : SRC=%s DST=%s PROTO=%d",
            str_state,
            element.user_id,
            element.timestamp,
            source_addr,
            dest_addr,
            (element.tracking_hdrs).protocol
            );
    }
}


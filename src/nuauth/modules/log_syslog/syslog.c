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
#include "security.h"

/**
 * \ingroup NuauthModules
 * \defgroup LoggingNuauthModules Logging modules
 */

/**
 * \ingroup LoggingNuauthModules
 * \defgroup SyslogModule Syslog logging module
 *
 * @{ */



G_MODULE_EXPORT gint user_packet_logs (connection_t* element, tcp_state_t state,gpointer params)
{
    char *prefix = "[nuauth] ";
    char *str_state;
    char source_addr[INET6_ADDRSTRLEN];
    char dest_addr[INET6_ADDRSTRLEN];
    char *saddr;
    char* daddr;
    u_int16_t sport;
    u_int16_t dport;

    /* contruct request */
    switch (state)
    {
      case TCP_STATE_OPEN:
        str_state="Open ";
        break;
      case TCP_STATE_CLOSE:
        str_state="Close ";
        break;
      case TCP_STATE_ESTABLISHED:
        str_state="Established ";
        break;
      case TCP_STATE_DROP:
          str_state="Drop ";
	  break;
      default:
    	  str_state="Unknown ";
    } 

    /* convert IP source and destination addresses to string */
    if (inet_ntop(AF_INET6, &element->tracking.saddr, source_addr, sizeof(source_addr)) == NULL)
            return 1;
    if (inet_ntop(AF_INET6, &element->tracking.daddr, dest_addr, sizeof(dest_addr)) == NULL)
            return 1;
    
    if ( ((element->tracking).protocol == IPPROTO_TCP) || ((element->tracking).protocol == IPPROTO_UDP) ) {
        if (state==TCP_STATE_ESTABLISHED){
            saddr = dest_addr;
            daddr = source_addr;
            sport = (element->tracking).dest;
            dport = (element->tracking).source;
        } else {
            saddr = source_addr;
            daddr = dest_addr;
            sport = (element->tracking).source;
            dport = (element->tracking).dest;
        }
        g_message("%s%s[%s] %ld : SRC=%s DST=%s PROTO=%d SPT=%u DPT=%u",
            prefix, str_state,
            element->username, element->timestamp,
            saddr, daddr, element->tracking.protocol,
            sport, dport);
    } else {
        g_message("%s%s[%s] %ld : SRC=%s DST=%s PROTO=%d",
            prefix, str_state,
            element->username, element->timestamp,
            source_addr, dest_addr,
            (element->tracking).protocol);
    }
    return 0;
}

G_MODULE_EXPORT int user_session_logs(user_session_t *c_session, session_state_t state,gpointer params)
{
    char *prefix = "[nuauth] ";
    char address[INET6_ADDRSTRLEN];
    const char *err = inet_ntop(AF_INET6, &c_session->addr, address, sizeof(address));
    if (err == NULL) {
        return -1;
    }
    switch (state) {
        case SESSION_OPEN:
            g_message("%sUser %s connect on %s", prefix, c_session->user_name,address);
            break;
        case SESSION_CLOSE:
            g_message("%sUser %s disconnect on %s", prefix, c_session->user_name,address);
            break;
    }
    return 1;
}

G_MODULE_EXPORT gchar* g_module_unload(void)
{
        return NULL;
}

G_MODULE_EXPORT gboolean init_module_from_conf(module_t* module)
{
        return TRUE;
}

G_MODULE_EXPORT gboolean unload_module_with_params(gpointer params_p)
{
        return TRUE;
}

/** @} */

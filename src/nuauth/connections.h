/*
** Copyright(C) 2005 Eric Leblond <regit@inl.fr>
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

#ifndef CONNECTIONS_H
#define CONNECTIONS_H


/** 
 * State of a connection in the authentification server.
 * See field state of a structure ::connection_t and function
 * change_state().
 */
typedef enum
{
    AUTH_STATE_NONE = 0,
    AUTH_STATE_AUTHREQ,    // 0x1
    AUTH_STATE_USERPCKT,   // 0x2
    AUTH_STATE_READY,      // 0x3
    AUTH_STATE_COMPLETING, // 0x4
    AUTH_STATE_DONE,       // 0x5
    AUTH_STATE_HELLOMODE   // 0x6
} auth_state_t;

/** State of a TCP connection */
typedef enum
{
    TCP_STATE_DROP = 0,    // 0
    TCP_STATE_OPEN,        // 1
    TCP_STATE_ESTABLISHED, // 2
    TCP_STATE_CLOSE,       // 3
    TCP_STATE_UNKNOW       // 4: get_tcp_headers() function error
} tcp_state_t;

/**
 * Informations about an IPv4 connection used as key for connection
 * identification.
 */
typedef struct {
  u_int32_t saddr;    /*!< IPv4 source address */
  u_int32_t daddr;    /*!< IPv4 destination address */
  u_int8_t protocol;  /*!< IPv4 protocol */

  u_int16_t source;   /*!< TCP/UDP source port */
  u_int16_t dest;     /*!< TCP/UDP destination port */

  u_int8_t type;      /*!< ICMP message type */
  u_int8_t code;      /*!< ICMP code type */
} tracking_t;

/**
 * connection element
 * 
 * It contains all datas relative to a packet
 */
typedef struct {
  GSList *packet_id;      /*!< Netfilter unique identifier */
  long timestamp;         /*!< Packet arrival time (seconds) */
  int socket;             /*!< Socket from which NuFW request is coming */
  nufw_session *tls;      /*!< Infos on NuFW which sent the request */
  tracking_t tracking;    /*!< IPv4 connection tracking (headers) */
  u_int16_t user_id;      /*!< User numeric identity used for marking */
  char *username;         /*!< User name */

 /**
  * acl related groups.
  *
  * Contains the list of acl corresponding to the ipv4 header
  */
  GSList *acl_groups;
  GSList *user_groups;    /*!< User groups */
  struct user_cached_datas *cacheduserdatas;  /* Pointer to cache */
  
  gchar *os_sysname;      /*!< Operating system name */
  gchar *os_release;      /*!< Operating system release */
  gchar *os_version;      /*!< Operating system version */
  gchar *app_name;        /*!< Application name (full path) */
  gchar *app_md5;         /*!< Application binary MD5 checksum */

  auth_state_t state; /*!< State of the packet */
  char decision;            /*!< Decision on packet. */
  time_t expire;            /*!< Expire time (never: -1) */

#ifdef PERF_DISPLAY_ENABLE
  struct timeval arrival_time;   /*!< Performance datas */
#endif
} connection_t;


/** 
 * 
 * Used to store the acl that apply for a packet
 */ 

struct acl_group {
  GSList * groups;
  char answer;
  time_t expire;
};


GSList * ALLGROUP;

#endif

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
 * State of a connection (type ::connection_t) in the authentification server.
 * See field state of a structure ::connection_t and function
 * change_state().
 */
typedef enum
{
    AUTH_STATE_NONE = 0,    /*!< Unknow state (when a connection is created) */
    AUTH_STATE_AUTHREQ = 1, /*!< Waiting for authentification */
    AUTH_STATE_USERPCKT,    /*!< (see user_request()) */
    AUTH_STATE_READY,       /*!< (see search_and_fill_completing()) */

    /** 
     * State used when a connection is send to acl_checkers queue: read ACLs
     * from cache or external source. See acl_check_and_decide().
     */
    AUTH_STATE_COMPLETING,
    AUTH_STATE_DONE,       
    AUTH_STATE_HELLOMODE  
} auth_state_t;

/** State of a connection */
typedef enum
{
    TCP_STATE_DROP = 0,    /*!< NuAuth decide to drop the connection */
    TCP_STATE_OPEN,        /*!< A new connection is just created (SYN) */
    TCP_STATE_ESTABLISHED, /*!< The connection is established (SYN,ACK) */
    TCP_STATE_CLOSE,       /*!< The connection is closed (RST) */
    TCP_STATE_UNKNOW       /*!< Error code of get_tcp_headers() function */
} tcp_state_t;

#define PAYLOAD_SAMPLE 8
#define PAYLOAD6_SAMPLE PAYLOAD_SAMPLE
#define IPHDR_REJECT_LENGTH 20
#define IP6HDR_REJECT_LENGTH 40
/**
 * this is IPHDR_REJECT_LENGTH / 4
 */
#define IPHDR_REJECT_LENGTH_BWORD 5

/**
 * Informations about an IPv4 connection used as key for connection
 * identification.
 */
typedef struct {
  struct in6_addr saddr;    /*!< IPv6 source address */
  struct in6_addr daddr;    /*!< IPv6 destination address */
  u_int8_t protocol;        /*!< IP protocol */

  u_int16_t source;         /*!< TCP/UDP source port */
  u_int16_t dest;           /*!< TCP/UDP destination port */

  u_int8_t type;            /*!< ICMP message type */
  u_int8_t code;            /*!< ICMP code type */

  char payload[PAYLOAD_SAMPLE];  /*!< First 8 bytes of protocol payload used for ICMP reject */
} tracking_t;

/** 
 * Used to store the acl that apply for a packet
 */ 
struct acl_group {
  GSList *groups;
  decision_t answer;
  gchar *period;
};

/**
 * This is a packet blocked by NuFW and waiting for an authentification 
 * of NuAuth. They are created in authpckt_new_connection().
 * 
 * It contains all datas relative to a packet
 */
typedef struct
{
  GSList *packet_id;      /*!< Netfilter unique identifier */
  long timestamp;         /*!< Packet arrival time (seconds) */
  int socket;             /*!< Socket (file descriptor) from which NuFW request is coming */
  nufw_session_t *tls;    /*!< TLS connection to NuFW from which comes the packet */
  tracking_t tracking;    /*!< IPv4 connection tracking (headers) */
  uint32_t user_id;       /*!< User numeric identity used for marking */
  char *username;         /*!< User name */
  
 /**
  * ACL related groups.
  *
  * Contains the list of acl corresponding to the IPv4 header
  */
  GSList *acl_groups;     /*!< ACL group list (of type ::acl_group) */
  GSList *user_groups;    /*!< User groups */
  struct user_cached_datas *cacheduserdatas;  /* Pointer to cache */
  
  gchar *os_sysname;      /*!< Operating system name */
  gchar *os_release;      /*!< Operating system release */
  gchar *os_version;      /*!< Operating system version */
  gchar *app_name;        /*!< Application name (full path) */
  gchar *app_md5;         /*!< Application binary MD5 checksum */

  auth_state_t state;     /*!< State of the packet */
  decision_t decision;    /*!< Decision on packet. */
  time_t expire;          /*!< Expire time (never: -1) */

#ifdef PERF_DISPLAY_ENABLE
  struct timeval arrival_time;   /*!< Performance datas */
#endif
} connection_t;

GSList * ALLGROUP;

#endif

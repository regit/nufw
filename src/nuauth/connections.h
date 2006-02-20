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


/* internal auth srv */
#define STATE_NONE 0x0
#define STATE_AUTHREQ 0x1
#define STATE_USERPCKT 0x2
#define STATE_READY 0x3
#define STATE_COMPLETING 0x4
#define STATE_DONE 0x5
#define STATE_HELLOMODE 0x6

#define STATE_DROP 0x0
#define STATE_OPEN 0x1
#define STATE_ESTABLISHED 0x2
#define STATE_CLOSE 0x3

#define ALL_GROUPS 0

/**
 * ipv4 headers related sructure used as key for connection identification.
 */
typedef struct uniq_headers {
  u_int32_t saddr;/*!< IPV4 source address. */
  u_int32_t daddr;/*!< IPV4 dest address. */
  u_int8_t protocol;/*!< IPV4 protocol. */
  /* TCP or UDP */
  u_int16_t source; /*!< TCP/UDP source port. */
  u_int16_t dest; /*!< TCP/UDP dest port. */
  /* ICMP Things */
  u_int8_t type; /*!< icmp message type. */
  u_int8_t code; /*!< icmp code type. */
} tracking;

/**
 * connection element
 * 
 * It contains all datas relative to a packet
 * 
 */
typedef struct {
  GSList * packet_id;     /*!< Netfilter unique identifier */
  long timestamp;         /*!< Packet arrival time (seconds). */
  int socket;             /*!< Socket from which nufw request is coming. */
  nufw_session* tls;      /*!< Infos on nufw which sent the request. */
  tracking tracking_hdrs; /*!< IPV4  stuffs (headers). */
  u_int16_t user_id;      /*!< User numeric identity used for marking. */
  char * username;        /*!< User name. */

 /**
  * acl related groups.
  *
  * Contains the list of acl corresponding to the ipv4 header
  */
  GSList * acl_groups;
  GSList * user_groups;  /*!< User groups */
  struct user_cached_datas * cacheduserdatas;  /* Pointer to cache */
  
  gchar *os_sysname;  /*!< Operating system name */
  gchar *os_release;  /*!< Operating system release */
  gchar *os_version;  /*!< Operating system version */
  gchar *app_name;    /*!< Application name (full path) */
  gchar *app_md5;     /*!< Application binary MD5 checksum */

  char state;         /*!< State of the packet */
  char decision;      /*!< Decision on packet. */
  time_t expire;      /*!< Expire time (never: -1) */

#ifdef PERF_DISPLAY_ENABLE
  /* performance datas */
  struct timeval arrival_time;
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

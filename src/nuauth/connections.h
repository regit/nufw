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

#include "packet_parser.h"   /* tracking_t structure and packet parsing functions */

/**
 * \addtogroup NuauthCore
 * @{
 */

/**
 * State of a connection (type ::connection_t) in the authentification server.
 * See field state of a structure ::connection_t and function
 * change_state().
 */
typedef enum
{
    AUTH_STATE_NONE = 0,    /*!< Unknow state (when a connection is created) */
    AUTH_STATE_AUTHREQ = 1, /*!< Waiting for authentification */
    AUTH_STATE_USERPCKT,    /*!< Connection received from an user: see user_request() */
    AUTH_STATE_READY,       /*!< (see search_and_fill_completing()) */

    /**
     * State used when a connection is send to acl_checkers queue: read ACLs
     * from cache or external source. See acl_check_and_decide().
     */
    AUTH_STATE_COMPLETING,
    AUTH_STATE_DONE,
    AUTH_STATE_HELLOMODE
} auth_state_t;

#define IPHDR_REJECT_LENGTH 20
#define IP6HDR_REJECT_LENGTH 40
/**
 * this is IPHDR_REJECT_LENGTH / 4
 */
#define IPHDR_REJECT_LENGTH_BWORD 5

/**
 * Used to store the acl that apply for a packet
 */
struct acl_group {
  GSList *groups;
  decision_t answer;
  gchar *period;
  gchar *log_prefix;
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
  uint32_t mark;       /*!< Number used for marking set to user numeric identity at start */
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
  gchar* log_prefix;          /*!< Log prefix. */

  time_t expire;          /*!< Expire time (never: -1) */


  int nufw_version;
  int client_version;
#ifdef PERF_DISPLAY_ENABLE
  struct timeval arrival_time;   /*!< Performance datas */
#endif
} connection_t;

/** @} */

#endif

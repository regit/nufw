/*
** Copyright(C) 2003-2005 Eric Leblond <regit@inl.fr>
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

#ifndef AUTH_SRV_H
#define AUTH_SRV_H

#define PERF_DISPLAY_ENABLE 1

/* Use glib to treat data structures */
#include <glib.h>
#include <gmodule.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
/* config dependant */
#include <config.h>
#include <gnutls/gnutls.h>
#include <sasl/sasl.h>
#include <locale.h>
#include <sys/time.h>

/* NUFW Protocol */
#include <proto.h>

/*debug functions*/
#include <nuauth_debug.h>

/* config file related */
#include <conffile.h>
#include "log.h"
#include "tls.h"
#include "connections.h"
#include "conntrack.h"
#include "auth_common.h"
#include "period.h"
#include "check_acls.h"
#include "users.h"
#include "user_logs.h"
#include "pckt_authsrv.h"
#include "modules.h"
#include "cache.h"
#include "acls.h"
#include "user_authsrv.h"
#include "internal_messages.h"
#include "client_mngr.h"
#include "nu_gcrypt.h"
#include "ip_auth.h"
#include "x509_parsing.h"
#include "parsing.h"
#include "localid_auth.h"
#include "audit.h"
#include "sasl.h"

#include "nuauth_params.h"
#include "nuauthconf.h"

/*
 * declare some global variables and do some definitions
 */

#define NUAUTH_TLS_MAX_CLIENTS 1024
#define NUAUTH_TLS_MAX_SERVERS 16
#define TLS_CLIENT_MIN_DELAY 25000
#define AUTH_NEGO_TIMEOUT 30

#define UNKNOWN_STRING "UNKNOWN"

#define POOL_TYPE FALSE

#define AUTHREQ_CLIENT_LISTEN_ADDR "0.0.0.0"
#define AUTHREQ_NUFW_LISTEN_ADDR "127.0.0.1"
#define AUTHREQ_PORT 4129
#define USERPCKT_PORT 4130
#define GWSRV_ADDR "127.0.0.1"

/** Maximum length of a hostname (including final '\0') */
#define HOSTNAME_SIZE 128

/** 
 * Default value of packet timeout (in second), 
 * option "nuauth_packet_timeout"
 */
#define PACKET_TIMEOUT 15

/**
 * Default value of session duration (in second),
 * option "nuauth_session_duration". See member session_duration of ::nuauth_params. 
 */
#define SESSION_DURATION 0
#define DEFAULT_USERAUTH_MODULE "libsystem"
#define DEFAULT_ACLS_MODULE "libplaintext"
#define DEFAULT_PERIODS_MODULE "libplaintext"
#define DEFAULT_LOGS_MODULE "libsyslog"
#define DEFAULT_IPAUTH_MODULE "libident"
#define MODULE_PATH MODULE_DIR "/nuauth/modules/"
#define NUAUTH_PID_FILE  LOCAL_STATE_DIR "/run/nuauth/nuauth.pid"
/* define the number of threads that will do user check */
#define NB_USERCHECK 5
/* define the number of threads that will check acls  */
#define NB_ACLCHECK 5
/* define the number of threads that will log  */
#define NB_LOGGERS 3

/**
 * Size of buffer used to store one packet read
 * on TLS connection (from NuFW)
 */
#define MAX_NUFW_PACKET_SIZE 1024

/*----------------------- SSL stuffs ----------------------------------*/

/** 
 * Default value for "nuauth_tls_key" option: filename of
 * the key file. Value used in ::create_x509_credentials().
 */
#define NUAUTH_KEYFILE CONFIG_DIR "/nuauth-key.pem"

/** 
 * Default value for "nuauth_tls_cert" option: file name of the
 * certification. Value used in ::create_x509_credentials().
 */
#define NUAUTH_CERTFILE CONFIG_DIR "/nuauth-cert.pem"

/** 
 * Default value for "nuauth_tls_cacert" option: filename of the
 * CA certificate. Value used in ::create_x509_credentials().
 */
#define NUAUTH_CACERTFILE CONFIG_DIR "/NuFW-cacert.pem"

/** 
 * Default value for "nuauth_tls_max_clients" option: maximum number
 * of SSL users. Value used in ::tls_user_init().
 */
#define NUAUTH_SSL_MAX_CLIENTS 256

#endif

/*
** Copyright(C) 2003-2007 Eric Leblond <regit@inl.fr>
**
** $Id$
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

#include "nufw_source.h"

/* workaround SPlint error (don't know __gnuc_va_list) */
#ifdef S_SPLINT_S
#  include <err.h>
#  define CONFIG_DIR "/etc/nufw"
#  define MODULE_DIR "/usr/local/lib"
#  define LOCAL_STATE_DIR "/usr/local/var"
#endif

#define MODULES_CONF_DIR "modules"
#define MODULES_CONF_EXTENSION ".conf"
#define TRACKING_WITH_PAYLOAD

/* Use glib to treat data structures */
#include <glib.h>
#include <gmodule.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
/* config dependant */
#include <config.h>
#include <sasl/sasl.h>
#include <locale.h>
#include <sys/time.h>

#ifdef DEBUG_ENABLE
/* Some code change to help debug using Valgrind */
/*#  define DEBUG_WITH_VALGRIND*/
#endif

typedef enum {
	NU_EXIT_ERROR = -1,
	NU_EXIT_OK = 0,
	NU_EXIT_NO_RETURN,
	NU_EXIT_CONTINUE
} nu_error_t;

#define PROTO_IPV4 4
#define PROTO_IPV6 6

/* NUFW Protocol */
#include <proto.h>

/*debug functions*/
#include "nuauth_debug.h"

/* config file related */
#include "nuthread.h"
#include "conffile.h"
#include "log.h"
#include "tls.h"
#include "nufw_servers.h"
#include "connections.h"
#include "conntrack.h"
#include "auth_common.h"
#include "take_decision.h"
#include "period.h"
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
#include "command.h"

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

#define POOL_TYPE TRUE

#define AUTHREQ_CLIENT_LISTEN_ADDR "0.0.0.0"
#define AUTHREQ_NUFW_LISTEN_ADDR "127.0.0.1"
#define GWSRV_ADDR "127.0.0.1"

/** Maximum length of a hostname (including final '\\0') */
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
#define DEFAULT_PROTO_WAIT_DELAY 2
#define DEFAULT_USERAUTH_MODULE "libplaintext"
#define DEFAULT_ACLS_MODULE "libplaintext"
#define DEFAULT_PERIODS_MODULE "libxml_defs"
#define DEFAULT_LOGS_MODULE "libsyslog"
#define DEFAULT_IPAUTH_MODULE "ipauth_guest"
#define DEFAULT_CERTIFICATE_CHECK_MODULE "libx509_std"
#define DEFAULT_CERTIFICATE_TO_UID_MODULE "libx509_std"
#define DEFAULT_USER_SESSION_MODIFY_MODULE "libsession_expire"
#define DEFAULT_FINALIZE_PACKET_MODULE "libmark_uid"

#define MODULE_PATH MODULE_DIR "/nuauth/modules"

#ifdef S_SPLINT_S
#  define NUAUTH_PID_FILE  "/usr/local/var/run/nuauth/nuauth.pid"
#else
#  define NUAUTH_PID_FILE  LOCAL_STATE_DIR "/run/nuauth/nuauth.pid"
#endif

/* define the number of threads that will do user check */
#define NB_USERCHECK 5
/* define the number of threads that will check acls  */
#define NB_ACLCHECK 5
/* define the number of threads that will log  */
#define NB_LOGGERS 3

/**
 * "Classic" size of buffer used to store one packet read
 * on TLS connection (from NuFW or the users)
 */
#define CLASSIC_NUFW_PACKET_SIZE 1400

/**
 * Maximum size of buffer used to store one packet read
 * on TLS connection (from NuFW or the users)
 */
#define MAX_NUFW_PACKET_SIZE 1800

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

/**
 * Identifier used to generate #NUAUTH_API_VERSION value. Increment it
 * if you changed API internals (eg. change public function prototype).
 */
#define _NUAUTH_API_ID 20002000

/**
 * Version of nuauth API, used by module to check if
 * everybody have the same API version.
 */
#define NUAUTH_API_VERSION ((uint32_t)( _NUAUTH_API_ID + sizeof(connection_t) \
	+ sizeof(module_t) + sizeof(nufw_session_t) + sizeof(struct nuauth_datas) \
	+ sizeof(tracking_t) + sizeof(user_session_t) ))

/**
 * Nuauth full version, eg. "nuauth 2.1.2 (Revision: 2730)"
 */
#define NUAUTH_FULL_VERSION (VERSION " ($Revision$)")

void nuauth_ask_exit();
void stop_all_thread_pools(gboolean wait);
void block_thread_pools();
void release_thread_pools();
void start_all_thread_pools();
void stop_thread_pool(const char *name, GThreadPool **pool);
void nuauth_install_signals(gboolean action);

int nuauth_bind(char **errmsg, const char *addr, const char *port, char *context);

#endif

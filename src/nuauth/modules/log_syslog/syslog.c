/*
 ** Copyright(C) 2003-2009 Eric Leblond <eric@regit.org>
 **		     Vincent Deffontaines <vincent@gryzor.com>
 **
 ** $Id$
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, version 3 of the License.
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

#include <inttypes.h>

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


/*
 * Returns version of nuauth API
 */
G_MODULE_EXPORT uint32_t get_api_version()
{
	return NUAUTH_API_VERSION;
}


/**
 * This one forgot the treatment of ESTABLISHED and CLOSE case.
 * */
G_MODULE_EXPORT gint user_packet_logs(void *element, tcp_state_t state,
				      gpointer params)
{
	char *prefix = "[nuauth] ";
	char *str_state;
	char source_addr[INET6_ADDRSTRLEN];
	char dest_addr[INET6_ADDRSTRLEN];
	char *saddr;
	char *daddr;
	char *log_prefix = "Default";
	u_int16_t sport;
	u_int16_t dport;

	/* contruct request */
	switch (state) {
	case TCP_STATE_OPEN:
		str_state = "Open ";
		break;
	case TCP_STATE_CLOSE:
		str_state = "Close ";
		break;
	case TCP_STATE_ESTABLISHED:
		str_state = "Established ";
		break;
	case TCP_STATE_DROP:
		str_state = "Drop ";
		break;
	default:
		str_state = "Unknown ";
	}

	if ((state == TCP_STATE_OPEN) || (state == TCP_STATE_DROP)) {
		const connection_t *connection = element;

		/* convert IP source and destination addresses to string */
		format_ipv6(&connection->tracking.saddr, source_addr, INET6_ADDRSTRLEN, NULL);
		format_ipv6(&connection->tracking.daddr, dest_addr, INET6_ADDRSTRLEN, NULL);

		if (connection->log_prefix) {
			log_prefix =
			    connection->log_prefix;
		}

		saddr = source_addr;
		daddr = dest_addr;
		if (((connection->tracking).protocol == IPPROTO_TCP)
		    || ((connection->tracking).protocol == IPPROTO_UDP)) {
			sport = (connection->tracking).source;
			dport = (connection->tracking).dest;
			g_message
			    ("%s%s %s[%s] %ld : IN=%s OUT=%s SRC=%s DST=%s PROTO=%d SPT=%u DPT=%u",
			     prefix, log_prefix, str_state,
			     connection->username,
			     connection->timestamp,
			     connection->iface_nfo.indev,
			     connection->iface_nfo.outdev, saddr, daddr,
			     connection->tracking.protocol, sport, dport);
		} else {
			g_message
			    ("%s%s %s[%s] %ld : IN=%s OUT=%s SRC=%s DST=%s PROTO=%d",
			     prefix, log_prefix, str_state,
			     connection->username,
			     connection->timestamp,
			     connection->iface_nfo.indev,
			     connection->iface_nfo.outdev,
			     source_addr, dest_addr,
			     connection->tracking.protocol);

		}
	}
	return 0;
}

G_MODULE_EXPORT int user_session_logs(user_session_t * c_session,
				      session_state_t state,
				      gpointer params)
{
	char *prefix = "[nuauth] ";
	char address[INET6_ADDRSTRLEN];

	format_ipv6(&c_session->addr, address, INET6_ADDRSTRLEN, NULL);
	switch (state) {
	case SESSION_OPEN:
		g_message("%sUser %s connect on %s", prefix,
			  c_session->user_name, address);
		break;
	case SESSION_CLOSE:
		g_message("%sUser %s disconnect on %s", prefix,
			  c_session->user_name, address);
		break;
	}
	return 1;
}

G_MODULE_EXPORT gboolean init_module_from_conf(module_t * module)
{
	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		    "Log_syslog module ($Revision$)");
	return TRUE;
}

G_MODULE_EXPORT gboolean unload_module_with_params(gpointer params_p)
{
	return TRUE;
}

G_MODULE_EXPORT void auth_error_log(user_session_t * session,
				    nuauth_auth_error_t error,
				    const char *text, gpointer params_ptr)
{
	char ipaddr[INET6_ADDRSTRLEN];
	format_ipv6(&session->addr, ipaddr, INET6_ADDRSTRLEN, NULL);

	g_message("Authentication error: %s", text);
	g_message("Authentication error: user: %s from %s (port %d), protocol version %d",
		session->user_name,
		ipaddr, session->sport,
		session->proto_version);
}

/** @} */

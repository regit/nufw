/*
 ** Copyright(C) 2003 Eric Leblond <eric@regit.org>
 **		     Vincent Deffontaines <vincent@gryzor.com>
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


/*
 * Returns version of nuauth API
 */
G_MODULE_EXPORT uint32_t get_api_version()
{
	return NUAUTH_API_VERSION;
}


/** \todo Take into account connection_t* to void* change
 *
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
		/* convert IP source and destination addresses to string */
		if (inet_ntop
		    (AF_INET6,
		     &(((connection_t *) element)->tracking.saddr),
		     source_addr, sizeof(source_addr)) == NULL)
			return 1;
		if (inet_ntop
		    (AF_INET6,
		     &(((connection_t *) element)->tracking.daddr),
		     dest_addr, sizeof(dest_addr)) == NULL)
			return 1;

		if (((connection_t *) element)->log_prefix) {
			log_prefix =
			    ((connection_t *) element)->log_prefix;
		}

		saddr = source_addr;
		daddr = dest_addr;
		if (((((connection_t *) element)->tracking).protocol ==
		     IPPROTO_TCP)
		    || ((((connection_t *) element)->tracking).protocol ==
			IPPROTO_UDP)) {
			sport =
			    (((connection_t *) element)->tracking).source;
			dport =
			    (((connection_t *) element)->tracking).dest;
			g_message
			    ("%s%s %s[%s] %ld : IN=%s OUT=%s SRC=%s DST=%s PROTO=%d SPT=%u DPT=%u",
			     prefix, log_prefix, str_state,
			     ((connection_t *) element)->username,
			     ((connection_t *) element)->timestamp,
			     ((connection_t *) element)->iface_nfo.indev,
			     ((connection_t *) element)->iface_nfo.outdev,
			     saddr, daddr,
			     ((connection_t *) element)->tracking.protocol,
			     sport, dport);
		} else {
			g_message
			    ("%s%s %s[%s] %ld : IN=%s OUT=%s SRC=%s DST=%s PROTO=%d",
			     prefix, log_prefix, str_state,
			     ((connection_t *) element)->username,
			     ((connection_t *) element)->timestamp,
			     ((connection_t *) element)->iface_nfo.indev,
			     ((connection_t *) element)->iface_nfo.outdev,
			     source_addr, dest_addr,
			     ((connection_t *) element)->tracking.
			     protocol);

		}
	} else {
		/* convert IP source and destination addresses to string */
		if (inet_ntop
		    (AF_INET6,
		     &(((struct accounted_connection *) element)->tracking.
		       saddr), source_addr, sizeof(source_addr)) == NULL)
			return 1;
		if (inet_ntop
		    (AF_INET6,
		     &(((struct accounted_connection *) element)->tracking.
		       daddr), dest_addr, sizeof(dest_addr)) == NULL)
			return 1;

		saddr = dest_addr;
		daddr = source_addr;
		if (((((struct accounted_connection *) element)->tracking).
		     protocol == IPPROTO_TCP)
		    ||
		    ((((struct accounted_connection *) element)->tracking).
		     protocol == IPPROTO_UDP)) {

			sport =
			    ((struct accounted_connection *) element)->
			    tracking.dest;
			dport =
			    ((struct accounted_connection *) element)->
			    tracking.source;
			g_message
			    ("%s%s %ld : SRC=%s DST=%s PROTO=%d SPT=%u DPT=%u (in: %llu pckts/%llu bytes, out: %llu pckts/%llu bytes)",
			     prefix, str_state,
			     ((struct accounted_connection *) element)->
			     timestamp, saddr, daddr,
			     ((struct accounted_connection *) element)->
			     tracking.protocol, sport, dport,
			     ((struct accounted_connection *) element)->
			     packets_in,
			     ((struct accounted_connection *) element)->
			     bytes_in,
			     ((struct accounted_connection *) element)->
			     packets_out,
			     ((struct accounted_connection *) element)->
			     bytes_out);
		} else {
			g_message
			    ("%s%s %ld : SRC=%s DST=%s PROTO=%d (in: %llu pckts/%llu bytes, out: %llu pckts/%llu bytes)",
			     prefix, str_state,
			     ((struct accounted_connection *) element)->
			     timestamp, source_addr, dest_addr,
			     ((struct accounted_connection *) element)->
			     tracking.protocol,
			     ((struct accounted_connection *) element)->
			     packets_in,
			     ((struct accounted_connection *) element)->
			     bytes_in,
			     ((struct accounted_connection *) element)->
			     packets_out,
			     ((struct accounted_connection *) element)->
			     bytes_out);

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
	const char *err =
	    inet_ntop(AF_INET6, &c_session->addr, address,
		      sizeof(address));
	if (err == NULL) {
		return -1;
	}
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

G_MODULE_EXPORT gchar *g_module_unload(void)
{
	return NULL;
}

G_MODULE_EXPORT gboolean init_module_from_conf(module_t * module)
{
	log_message(VERBOSE_DEBUG, AREA_MAIN,
		    "Log_syslog module ($Revision$)");
	return TRUE;
}

G_MODULE_EXPORT gboolean unload_module_with_params(gpointer params_p)
{
	return TRUE;
}

/** @} */

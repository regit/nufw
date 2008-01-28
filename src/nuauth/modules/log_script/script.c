/*
 ** Copyright(C) 2005-2007 INL
 ** 	written by  Eric Leblond <regit@inl.fr>
 **
 ** Changelog:
 **	IPv6 port by Victor Stinner
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

#include <nubase.h>

/**
 *
 * \ingroup LoggingNuauthModules
 * \defgroup ScriptModule Script logging module
 *
 * @{ */


/*
 * Returns version of nuauth API
 */
G_MODULE_EXPORT uint32_t get_api_version()
{
	return NUAUTH_API_VERSION;
}



G_MODULE_EXPORT int user_session_logs(user_session_t * c_session,
				      session_state_t state,
				      gpointer params)
{
	char address[INET6_ADDRSTRLEN];
	char cmdbuffer[200];
	char *quoted_username = g_shell_quote(c_session->user_name);
	char *quoted_address;
	char *format;
	gboolean ok;

	FORMAT_IPV6(&c_session->addr, address);
	quoted_address = g_shell_quote(address);

	if (state == SESSION_OPEN) {
		format = CONFIG_DIR "/user-up.sh %s %s";
	} else {		/* state == SESSION_CLOSE */
		format = CONFIG_DIR "/user-down.sh %s %s";
	}
	ok = secure_snprintf(cmdbuffer, sizeof(cmdbuffer), format,
			     quoted_username, quoted_address);
	if (ok) {
		system(cmdbuffer);
	} else {
		log_message(WARNING, DEBUG_AREA_MAIN,
			    "Can't call script, command line truncated!");
	}
	g_free(quoted_username);
	g_free(quoted_address);
	return 1;
}


G_MODULE_EXPORT gboolean unload_module_with_params(gpointer params_p)
{
	return TRUE;
}

G_MODULE_EXPORT gboolean init_module_from_conf(module_t * module)
{
	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		    "Log_script module ($Revision$)");
	return TRUE;
}

/** @} */

/*
** Copyrigh 2002-2004 Vincent Deffontaines <vincent@gryzor.com>
** INL http://www.inl.fr/
**
** $Id$
**
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

#include "auth_srv.h"
#include "nuauth_debug.h"
#include <syslog.h>
#include <math.h>

#include <nubase.h>

static inline int _map_g_loglevel_to_debuglevel(int log_level)
{
	if (log_level & G_LOG_FLAG_FATAL)
		return DEBUG_LEVEL_FATAL;
	if (log_level & G_LOG_LEVEL_ERROR)
		return DEBUG_LEVEL_CRITICAL;
	if (log_level & G_LOG_LEVEL_WARNING)
		return DEBUG_LEVEL_WARNING;
	if (log_level & G_LOG_LEVEL_MESSAGE)
		return DEBUG_LEVEL_SERIOUS_MESSAGE;
	if (log_level & G_LOG_LEVEL_INFO)
		return DEBUG_LEVEL_INFO;
	if (log_level & G_LOG_LEVEL_DEBUG)
		return DEBUG_LEVEL_DEBUG;

	return log_level;
}

/* sweet formula : GLIB_LOG_LEVEL=2^SYSLOG_LOG_LEVEL */
void process_g_syslog(const gchar * log_domain, GLogLevelFlags log_level,
		      const gchar * message, gpointer user_data)
{
	int debug_level;

	debug_level = _map_g_loglevel_to_debuglevel(log_level);
	log_printf(debug_level, message);
}

void set_glib_loghandlers(int syslog_only)
{
	if (syslog_only)
		nubase_log_engine_set(LOG_TO_SYSLOG);
	else
		nubase_log_engine_set(LOG_TO_STD | LOG_TO_SYSLOG);
	init_log_engine("nuauth");
	g_log_set_handler(NULL, G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL
			  | G_LOG_FLAG_RECURSION, process_g_syslog, NULL);
}

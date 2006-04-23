
/*
**
** Copyrigh 2002-2004 Vincent Deffontaines <vincent@gryzor.com>
**                    INL http://www.inl.fr/
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

#include "auth_srv.h"
#include "nuauth_debug.h"
#include <syslog.h>
#include <math.h>

/* sweet formula : GLIB_LOG_LEVEL=2^SYSLOG_LOG_LEVEL */
void process_g_syslog (const gchar *log_domain, GLogLevelFlags log_level, const gchar *message, gpointer user_data)
{
  int syslog_level;
  syslog_level = rint(log(log_level)/log(2));
  syslog(LOG_FACILITY || syslog_level,message);
}

void set_glib_loghandlers()
{
	openlog("nuauth",LOG_CONS||LOG_PID,LOG_DAEMON);
	g_log_set_handler (NULL, G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL
                     | G_LOG_FLAG_RECURSION, process_g_syslog, NULL);
}



/*
**
** Written by Vincent Deffontaines <vincent@gryzor.com>
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

#include <debug.h>
#include <syslog.h>

void process_g_fatal (const gchar *log_domain, GLogLevelFlags log_level, const gchar *message, gpointer user_data)
{
	syslog(LOG_FACILITY||LOG_ALERT,message);
}

void process_g_critical (const gchar *log_domain, GLogLevelFlags log_level, const gchar *message, gpointer user_data)
{
	syslog(LOG_FACILITY||LOG_CRIT,message);
}

void process_g_warning (const gchar *log_domain, GLogLevelFlags log_level, const gchar *message, gpointer user_data)
{
	syslog(LOG_FACILITY||LOG_WARNING,message);
}

void process_g_message (const gchar *log_domain, GLogLevelFlags log_level, const gchar *message, gpointer user_data)
{
	syslog(LOG_FACILITY||LOG_NOTICE,message);
}

void process_g_info (const gchar *log_domain, GLogLevelFlags log_level, const gchar *message, gpointer user_data)
{
	syslog(LOG_FACILITY||LOG_INFO,message);
}

void process_g_debug (const gchar *log_domain, GLogLevelFlags log_level, const gchar *message, gpointer user_data)
{
	syslog(LOG_FACILITY||LOG_DEBUG,message);
}


int set_glib_loghandlers()
{
	int error=0;
	g_log_set_handler(NULL,G_LOG_FLAG_FATAL|G_LOG_LEVEL_ERROR,process_g_fatal,NULL);
	g_log_set_handler(NULL,G_LOG_LEVEL_CRITICAL,process_g_critical,NULL);
	g_log_set_handler(NULL,G_LOG_LEVEL_WARNING,process_g_warning,NULL); 
	g_log_set_handler(NULL,G_LOG_LEVEL_MESSAGE,process_g_message,NULL);
	g_log_set_handler(NULL,G_LOG_LEVEL_INFO,process_g_info,NULL);
	g_log_set_handler(NULL,G_LOG_LEVEL_DEBUG,process_g_debug,NULL);
	return error;
}


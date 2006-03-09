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

#include <glib.h>
#include <debug.h>

void set_glib_loghandlers();
void process_g_message (const gchar *log_domain, GLogLevelFlags log_level, const gchar *message, gpointer user_data);
void process_g_fatal (const gchar *log_domain, GLogLevelFlags log_level, const gchar *message, gpointer user_data);

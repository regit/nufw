/*
 ** Copyright(C) 2006 INL
 ** written by  Victor Stinner <haypo@inl.fr>
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

/** \file log.c
 *  \brief Initialize and write messages in log.
 *   
 * Before using the log, call init_log_engine(). After that call log_printf()
 * as you call printf, you just need a priority as first argument.
 *
 * The global variable log_engine choose between printf() (value #LOG_TO_STD)
 * and syslog() (value #LOG_TO_SYSLOG).
 */

#include "auth_srv.h"

/**
 * Display a message to log, the syntax for format is the same as printf().
 * The priority is used for syslog.
 */
void log_print_message(int level, int area, char *format, ...)
{
  va_list args;  

  if (!(area & nuauthconf -> debug_areas) || (level < nuauthconf->debug_level))
      return;
  
  va_start(args, format);
  g_logv(area, level, format, args);
  va_end(args);
}


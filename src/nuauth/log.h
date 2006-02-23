/*
 ** Copyright(C) 2005 INL
 ** Written by Eric Leblond <regit@inl.fr>
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

#ifndef NUAUTH_LOG_H
#define NUAUTH_LOG_H

#include <syslog.h>
#include <debug.h>

#define DEBUG_OR_NOT(LOGLEVEL, LOGAREA) \
    ((LOGAREA & nuauthconf->debug_areas) && ((nuauthconf->debug_level)>=LOGLEVEL))

void log_print_message(int level, int area, char *format, ...);

#define log_message(level, area, format, args...) \
   log_print_message(DEBUG_LEVEL_##level, DEBUG_##area, format, ##args )

/** \def debug_log_printf(area, priority, format, ...)
 * Call log_area_printf(area, priority, ...) if DEBUG_ENABLE is defined 
 */
#ifdef DEBUG_ENABLE
#  define debug_log_message(level, area, format, args...) \
       log_print_message(DEBUG_LEVEL_##level, DEBUG_AREA_##area, format, ##args )
#else
#  define debug_log_message(level, area, format, ...)
#endif

#endif

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

#define log_message(level, area, format, args...) \
  do { if ((DEBUG_##area & nuauthconf->debug_areas) && (nuauthconf->debug_level >= DEBUG_LEVEL_##level)) \
    g_message(format, ##args); } while (0)

#ifdef DEBUG_ENABLE
   /* copy of log_message macro */
#  define debug_log_message(level, area, format, args...) \
      do { if ((DEBUG_##area & nuauthconf->debug_areas) && (nuauthconf->debug_level >= DEBUG_LEVEL_##level)) \
        g_message(format, ##args); } while (0)
#else
#  define debug_log_message(level, area, format, ...)
#endif

#endif

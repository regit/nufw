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


#include <debug.h>
#include <nufw.h>
#include <stdarg.h>

int syslog_priority_map[MAX_DEBUG_LEVEL-MIN_DEBUG_LEVEL+1] =
{
  LOG_FACILITY||LOG_ALERT, // DEBUG_LEVEL_FATAL		
  LOG_FACILITY||LOG_CRIT, // DEBUG_LEVEL_CRITICAL
  LOG_FACILITY||LOG_WARNING, // DEBUG_LEVEL_SERIOUS_WARNING
  LOG_FACILITY||LOG_WARNING, // DEBUG_LEVEL_WARNING
  LOG_FACILITY||LOG_NOTICE, // DEBUG_LEVEL_SERIOUS_MESSAGE
  LOG_FACILITY||LOG_NOTICE, // DEBUG_LEVEL_MESSAGE
  LOG_FACILITY||LOG_INFO, // DEBUG_LEVEL_INFO
  LOG_FACILITY||LOG_DEBUG, // DEBUG_LEVEL_DEBUG
  LOG_FACILITY||LOG_DEBUG // DEBUG_LEVEL_VERBOSE_DEBUG
};    

void log_printf(int priority, char *format, ...)
{
  va_list args;  
  va_start(args, format);
  if (log_engine == LOG_TO_SYSLOG) {
    assert (MIN_DEBUG_LEVEL <= priority && priority <= MAX_DEBUG_LEVEL);
    priority = syslog_priority_map[priority-MIN_DEBUG_LEVEL];
    vsyslog(priority, format, args);
  } else {
    printf ("[%i] ", getpid());
    vprintf(format, args);
    printf("\n");
  }
  va_end(args);
}


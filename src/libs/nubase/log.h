/*
 ** Copyright (C) 2006-2008 INL
 ** Written by Victor Stinner <haypo@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** $Id: log.h 4323 2008-01-18 09:12:11Z pollux $
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


#ifndef NUBASE_LOG_HEADER
#define NUBASE_LOG_HEADER

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif
#include <syslog.h>
#include "debug.h"

/** \file nufw/log.h
 *  \brief Initialize and write messages in log.
 *
 * Some constants used in log, and function prototypes.
 */

#define SYSLOG_OPTS \
	LOG_CONS||LOG_PID		/*!< Syslog options of NuFW */
#define LOG_ID "nufw"		/*!< Syslog identifier of NuFW */
#define LOG_TO_STD	  1	/*!< Value of ::log_engine when using printf() */
#define LOG_TO_SYSLOG 2		/*!< Value of ::log_engine when using syslog() */

/**
 * Log engine used:
 *   - if equals to #LOG_TO_SYSLOG, use syslog
 *   - else use printf()
 * \see log_printf()
 */
int log_engine;

int debug_level;		/*!< Debug level, default valut: #DEFAULT_DEBUG_LEVEL */
int debug_areas;		/*!< Debug areas, default value: #DEFAULT_DEBUG_AREAS (all areas) */

void init_log_engine();
void log_printf(debug_level_t priority, char *format, ...)
#ifdef __GNUC__
	__attribute__((__format__(printf,2,3)))
#endif
;

void log_area_printf(debug_area_t area, debug_level_t priority, char *format, ...)
#ifdef __GNUC__
	__attribute__((__format__(printf,3,4)))
#endif
;

/** \def debug_log_printf(area, priority, format, ...)
 * Call log_area_printf(area, priority, ...) if DEBUG_ENABLE is defined
 */
#ifdef DEBUG_ENABLE
#  define debug_log_printf(area, priority, format, args...) \
       log_area_printf(area, priority, format, ##args )
#else
#  define debug_log_printf(area, priority, format, ...)
#endif

#endif				/* ifndef NUBASE_LOG_HEADER */

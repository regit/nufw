/*
 ** Copyright(C) 2006-2009 INL
 ** Written by Victor Stinner <haypo@inl.fr>
 **            Pierre Chifflier <chifflier@inl.fr>
 ** INL http://www.inl.fr/
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


#ifndef NUBASE_LOG_HEADER
#define NUBASE_LOG_HEADER

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif
#include <syslog.h>
#ifdef HAVE_STDARG_H
#  include <stdarg.h>
#endif
#include "debug.h"

/** \file libs/nubase/log.h
 *  \brief Initialize and write messages in log.
 *
 * Some constants used in log, and function prototypes.
 */

#define SYSLOG_OPTS \
	LOG_CONS||LOG_PID		/*!< Syslog options of NuFW */

enum log_type_t {
	LOG_NONE = 0,
	LOG_TO_STD,	/*!< Value of ::log_engine when using printf() */
	LOG_TO_SYSLOG,	/*!< Value of ::log_engine when using syslog() */
	LOG_TO_CALLBACK,	/*!< Value of ::log_engine when using a callback */
};

/** \brief Callback prototype, for logs
 */
typedef void (*log_callback_t)(debug_area_t area, debug_level_t priority, char *format, va_list args);

/**
 * Log engine used:
 *   - if equals to #LOG_TO_SYSLOG, use syslog
 *   - else use printf()
 * \see log_printf()
 */
extern int log_engine;

extern int debug_level;    /*!< Debug level, default valut: #DEFAULT_DEBUG_LEVEL */
extern int debug_areas;    /*!< Debug areas, default value: #DEFAULT_DEBUG_AREAS (all areas) */

void init_log_engine(const char* log_id);
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

/** \brief Set callback function for log
 *
 * This only makes sense when ::log_engine is #LOG_TO_CALLBACK
 * \return The previously set callback
 */
log_callback_t nubase_log_set_callback(log_callback_t cb);

#endif				/* ifndef NUBASE_LOG_HEADER */

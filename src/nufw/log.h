#include <syslog.h>
#include <debug.h>

/** \file log.h
 *  \brief Initialize and write messages in log.
 *   
 * Some constants used in log, and function prototypes.
 */

#define SYSLOG_OPTS \
    LOG_CONS||LOG_PID     /*!< Syslog options of NuFW */
#define LOG_ID "nufw"     /*!< Syslog identifier of NuFW */
#define LOG_TO_STD	  1   /*!< Value of ::log_engine when using printf() */
#define LOG_TO_SYSLOG 2   /*!< Value of ::log_engine when using syslog() */

/**
 * Log engine used:
 *   - if equals to #LOG_TO_SYSLOG, use syslog
 *   - else use printf()
 * \see log_printf()
 */
int log_engine;

int debug_level; /*!< Debug level, default valut: 0 */
int debug_areas; /*!< Debug areas, default value: #DEFAULT_DEBUG_AREAS (all areas) */

void init_log_engine();
void log_printf(int priority, char *format, ...);
void log_area_printf(int area, int priority, char *format, ...);

/** \def debug_log_printf(area, priority, format, ...)
 * Call log_area_printf(area, priority, ...) if DEBUG_ENABLE is defined 
 */
#ifdef DEBUG_ENABLE
#  define debug_log_printf(area, priority, format, ...) \
       log_area_printf(area, priority, ...)
#else
#  define debug_log_printf(area, priority, format, ...)
#endif


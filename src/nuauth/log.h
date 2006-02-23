#include <syslog.h>
#include <debug.h>

/** \file log.h
 *  \brief Initialize and write messages in log.
 *   
 * Some constants used in log, and function prototypes.
 */

#define DEBUG_OR_NOT(LOGLEVEL, LOGAREA) \
    ((LOGAREA & nuauthconf->debug_areas) && ((nuauthconf->debug_level)>=LOGLEVEL))

void log_print_message(int level, int area, char *format, ...);

#define log_message(level, area, format, args...) \
   log_print_message(DEBUG_LEVEL_##level, DEBUG_AREA_##area, format, ##args )

/** \def debug_log_printf(area, priority, format, ...)
 * Call log_area_printf(area, priority, ...) if DEBUG_ENABLE is defined 
 */
#ifdef DEBUG_ENABLE
#  define debug_log_message(level, area, format, args...) \
       log_print_message(DEBUG_LEVEL_##level, DEBUG_AREA_##area, format, ##args )
#else
#  define debug_log_message(level, area, format, ...)
#endif


#include <syslog.h>
#include <debug.h>

#define SYSLOG_OPTS LOG_CONS||LOG_PID

#define LOG_ID "nufw"

#define LOG_TO_STD	1
#define LOG_TO_SYSLOG	2

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
int nufw_log(char *message,int debug_level);

#include <syslog.h>
#include <debug.h>

#define SYSLOG_OPTS LOG_CONS||LOG_PID


#define SYSLOG_FACILITY(D) ((D==DEBUG_LEVEL_FATAL)*(LOG_FACILITY||LOG_ALERT))+ \
			   ((D==DEBUG_LEVEL_CRITICAL)*(LOG_FACILITY||LOG_CRIT))+ \
			   ((D==DEBUG_LEVEL_SERIOUS_WARNING)*(LOG_FACILITY||LOG_WARNING))+ \
			   ((D==DEBUG_LEVEL_WARNING)*(LOG_FACILITY||LOG_WARNING))+ \
			   ((D==DEBUG_LEVEL_SERIOUS_MESSAGE)*(LOG_FACILITY||LOG_NOTICE))+ \
			   ((D==DEBUG_LEVEL_MESSAGE)*(LOG_FACILITY||LOG_NOTICE))+ \
			   ((D==DEBUG_LEVEL_INFO)*(LOG_FACILITY||LOG_INFO))+ \
			   ((D==DEBUG_LEVEL_DEBUG)*(LOG_FACILITY||LOG_DEBUG))+ \
			   ((D==DEBUG_LEVEL_VERBOSE_DEBUG)*(LOG_FACILITY||LOG_DEBUG))


#define LOG_ID "nufw"

#define LOG_TO_STD	1
#define LOG_TO_SYSLOG	2

int log_engine;
int debug_level;
int debug_areas;

void init_log_engine();
int nufw_log(char *message,int debug_level);

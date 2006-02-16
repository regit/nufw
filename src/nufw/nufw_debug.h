#include <syslog.h>
#include <debug.h>

#define SYSLOG_OPTS LOG_CONS||LOG_PID

#define LOG_ID "nufw"

#define LOG_TO_STD	1
#define LOG_TO_SYSLOG	2

int log_engine;
int debug_level;
int debug_areas;

void init_log_engine();
int nufw_log(char *message,int debug_level);

#include <stdio.h>
#include <nufw_debug.h>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>



void init_log_engine()
{
  if (log_engine == LOG_TO_SYSLOG)
  {
    openlog(LOG_ID,SYSLOG_OPTS,LOG_FACILITY);
/*    nufw_log=*/
  }
}


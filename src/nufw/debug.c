#include <stdio.h>
#include <debug.h>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>

int nufw_log(char *message,int debug_level,int debug_area)
{
  /* log_engine is a global integer, value is 1 for stdout/stderr, 2 for syslog */
  if (log_engine == LOG_TO_STD)
  {
    if (debug_level >= DEBUG_LEVEL_SERIOUS_MESSAGE) /*Use stdout*/
    {
      printf("[%d] ",getpid());
      printf(message);
      return (0);
    }else /*Use stderr*/
    {
      fprintf(stderr,"[%d] ",getpid());
      fprintf(stderr,message);
      return (0);
    }
  }else if (log_engine == LOG_TO_SYSLOG)
  {
    switch (debug_level){
      case DEBUG_LEVEL_FATAL :
        syslog(LOG_FACILITY||LOG_ALERT,message);
	return 0;
      case DEBUG_LEVEL_CRITICAL :
	syslog(LOG_FACILITY||LOG_CRIT,message);
	return 0;
      case DEBUG_LEVEL_SERIOUS_WARNING :
	syslog(LOG_FACILITY||LOG_WARNING,message);
	return 0;
      case DEBUG_LEVEL_WARNING :
	syslog(LOG_FACILITY||LOG_WARNING,message);
	return 0;
      case DEBUG_LEVEL_SERIOUS_MESSAGE :
	syslog(LOG_FACILITY||LOG_NOTICE,message);
	return 0;
      case DEBUG_LEVEL_MESSAGE :
	syslog(LOG_FACILITY||LOG_NOTICE,message);
	return 0;
      case DEBUG_LEVEL_INFO :
	syslog(LOG_FACILITY||LOG_INFO,message);
	return 0;
      case DEBUG_LEVEL_DEBUG :
	syslog(LOG_FACILITY||LOG_DEBUG,message);
	return 0;
      case DEBUG_LEVEL_VERBOSE_DEBUG :
	syslog(LOG_FACILITY||LOG_DEBUG,message);
	return 0;
    }
    /* this should never be reached !*/
    fprintf (stderr,"[%d] : nufw_log problem ; following message didnt make its way :\n",getpid());
    fprintf (stderr,message);
    return 1;
  }
  return 0;
}

void init_log_engine()
{
  if (log_engine == LOG_TO_SYSLOG)
    openlog(LOG_ID,SYSLOG_OPTS,LOG_FACILITY);
}


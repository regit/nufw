#include <nufw.h>

void process_poll(int signum)
{
  if (log_engine == LOG_TO_SYSLOG)
      syslog(SYSLOG_FACILITY(DEBUG_LEVEL_INFO),"AUDIT : traffic statistics : %d packets received, %d accepted",pckt_rx,pckt_tx);
  else
      printf("AUDIT : traffic statistics : %d packets received, %d accepted\n",pckt_rx,pckt_tx);
}

void process_usr1(int signum)
{
  debug_level+=1;
  if (debug_level>20)
      debug_level = 20;
  if (log_engine == LOG_TO_SYSLOG)
      syslog(SYSLOG_FACILITY(DEBUG_LEVEL_INFO),"USR1 : setting debug level to %d",debug_level);
  else
      printf("USR1 : setting debug level to %d\n",debug_level);
}


void process_usr2(int signum)
{
  debug_level-=1;
  if (debug_level <0)
      debug_level = 0;
  if (log_engine == LOG_TO_SYSLOG)
      syslog(SYSLOG_FACILITY(DEBUG_LEVEL_INFO),"USR2 : setting debug level to %d",debug_level);
  else
      printf("USR2 : setting debug level to %d\n",debug_level);
}

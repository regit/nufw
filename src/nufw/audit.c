#include <nufw.h>

void process_poll(int signum)
{
  log_printf(DEBUG_LEVEL_INFO,
          "AUDIT: Traffic statistics: %d packets received - %d accepted",
          pckt_rx, pckt_tx);
}

void process_usr1(int signum)
{
  debug_level+=1;
  if (debug_level>20)
      debug_level = 20;
  log_printf(DEBUG_LEVEL_INFO, "USR1: Setting debug level to %d", debug_level);
}


void process_usr2(int signum)
{
  debug_level-=1;
  if (debug_level <0)
      debug_level = 0;
  log_printf(DEBUG_LEVEL_INFO, "USR2: Setting debug level to %d", debug_level);
}

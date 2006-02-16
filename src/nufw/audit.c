/*
 ** Copyright (C) 2002 - 2005 Eric Leblond <eric@regit.org>
 **		      Vincent Deffontaines <vincent@gryzor.com>
 **                   INL http://www.inl.fr/
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, version 2 of the License.
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

/** \file audit.c
 *  \brief Signal handlers (SIGPOLL, SIGUSR1, SIGUSR2).
 *   
 * Signal handlers:
 *   - process_poll() is called by SIGPOLL
 *   - process_usr1() is called by SIGUSR1
 *   - process_usr2() is called by SIGUSR2
 */

#include <nufw.h>

/**
 * Output traffic statistics (packets received/accepted).
 */
void process_poll(int signum)
{
  log_printf(DEBUG_LEVEL_INFO,
          "AUDIT: Traffic statistics: %d packets received - %d accepted",
          pckt_rx, pckt_tx);
}

/**
 * Increase debug verbosity.
 */
void process_usr1(int signum)
{
  debug_level+=1;
  if (debug_level>20)
      debug_level = 20;
  log_printf(DEBUG_LEVEL_INFO, "USR1: Setting debug level to %d", debug_level);
}

/**
 * Decrease debug verbosity.
 */
void process_usr2(int signum)
{
  debug_level-=1;
  if (debug_level <0)
      debug_level = 0;
  log_printf(DEBUG_LEVEL_INFO, "USR2: Setting debug level to %d", debug_level);
}

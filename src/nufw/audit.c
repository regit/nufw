/*
 ** Copyright (C) 2002-2007 INL
 ** Written by Eric Leblond <eric@regit.org>
 **            Vincent Deffontaines <vincent@gryzor.com>
 ** INL http://www.inl.fr/
 **
 ** $Id$
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

/** \file nufw/audit.c
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
 * \see pckt_rx and pckt_tx: Received and transmitted packets count.
 */
void process_poll(int signum)
{
	log_area_printf(DEBUG_AREA_MAIN,
#ifdef DEBUG_ENABLE
		DEBUG_LEVEL_SERIOUS_WARNING,
#else
		DEBUG_LEVEL_FATAL,
#endif
		"AUDIT: rx=%d tx=%d track_size=%d list=%s",
		pckt_rx, pckt_tx, packets_list.length,
		(packets_list.start ==
		 NULL) ? "empty" : "one packet or more");
}

/**
 * Increase debug verbosity.
 * \see debug_level
 */
void process_usr1(int signum)
{
	debug_level += 1;
	if (debug_level > 20)
		debug_level = 20;
	log_printf(DEBUG_LEVEL_FATAL, "USR1: Setting debug level to %d",
		   debug_level);
}

/**
 * Decrease debug verbosity.
 * \see debug_level
 */
void process_usr2(int signum)
{
	debug_level -= 1;
	if (debug_level < 0)
		debug_level = 0;
	log_printf(DEBUG_LEVEL_FATAL, "USR2: Setting debug level to %d",
		   debug_level);
}

#ifdef HAVE_LIBCONNTRACK
/**
 * Remove -M : set nufw_conntrack_uses_mark to 0
 */

void process_sys(int signum)
{
	if (handle_conntrack_event != 0) {
		handle_conntrack_event = 0;
		log_printf(DEBUG_LEVEL_INFO,
			   "SYS:   Setting handle_conntrack_event level to 0 (this cancels the -C switch)");
	} else {
	  log_printf(DEBUG_LEVEL_INFO,
		     "SYS:   doing nothing (handle_conntrack_event is already zeroed)");
	}
}

/**
 * Reset -M : set nufw_conntrack_uses_mark to 1
 */
void process_winch(int signum)
{
	if (handle_conntrack_event == 0) {
		handle_conntrack_event = 1;
		if (pthread_create(&(tls.conntrack_event_handler),
				   NULL,
				   conntrack_event_handler,
				   NULL) == EAGAIN) {
			exit(EXIT_FAILURE);
		}
		log_printf(DEBUG_LEVEL_INFO,
			   "WINCH: Setting handle_conntrack_event level to 1 (this activates the -C switch)");
	} else {
		log_printf(DEBUG_LEVEL_INFO,
			   "WINCH: doing nothing (handle_conntrack_event already set)");
	}
}
#endif


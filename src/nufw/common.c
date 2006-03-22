/* $Id: common.c,v 1.3 2003/10/21 23:06:05 regit Exp $ */

/*
**
** Written by Eric Leblond <eric@regit.org>
**	      Vincent Deffontaines <vincent@gryzor.com>
** Copyright 2002 - 2005 INL http://www.inl.fr/
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

/** \file common.c
 *  \brief Common tools to manage ::packets_list.
 *   
 * Function to add (padd()), suppress (psuppress() and psearch_and_destroy()) and clean up 
 * (clean_old_packets()) packets from packet list (::packets_list).
 */

#include "nufw.h"
#include <stdlib.h>
#include <time.h>

/* datas stuffs */

#ifdef PERF_DISPLAY_ENABLE
/**
 * Subtract the `struct timeval' values X and Y,
 * storing the result in RESULT.
 * Return 1 if the difference is negative, otherwise 0.  */

int timeval_substract (struct timeval *result,struct timeval *x,struct timeval *y)
{
    /* Perform the carry for the later subtraction by updating y. */
    if (x->tv_usec < y->tv_usec) {
        int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
        y->tv_usec -= 1000000 * nsec;
        y->tv_sec += nsec;
    }
    if (x->tv_usec - y->tv_usec > 1000000) {
        int nsec = (x->tv_usec - y->tv_usec) / 1000000;
        y->tv_usec += 1000000 * nsec;
        y->tv_sec -= nsec;
    }

    /* Compute the time remaining to wait.
     *           tv_usec is certainly positive. */
    result->tv_sec = x->tv_sec - y->tv_sec;
    result->tv_usec = x->tv_usec - y->tv_usec;

    /* Return 1 if result is negative. */
    return x->tv_sec < y->tv_sec;
}
#endif

/**
 * Close the TLS session
 */
void close_tls_session()
{
    int socket;

    if (tls.session == NULL) 
        return;

    pthread_mutex_destroy(&tls.auth_server_mutex);
    
    socket = (int)gnutls_transport_get_ptr(*tls.session);
    gnutls_bye(*tls.session, GNUTLS_SHUT_WR);
    gnutls_deinit(*tls.session);
    shutdown(socket, SHUT_RDWR);
    close(socket);
    free(tls.session);
    tls.session = NULL;
}    

/**
 * Suppress the packet current from the packet list (::packets_list).
 *
 * \param previous Packet before current
 * \param current Packet to remove
 */
void psuppress (packet_idl * previous,packet_idl * current){
  if (previous != NULL)
    previous->next=current->next;
  else
    packets_list.start=current->next;
  if (current->next == NULL) {
    packets_list.end=previous;
  }
  free(current);
  packets_list.length--;
}

/**
 * Try to add a packet to the end of ::packets_list. If we exceed max length
 * (::track_size), just drop the packet.
 *
 * \return Packet id of the new element, or 0 if list is full. 
 */
unsigned long padd (packet_idl *current){
  if (track_size <= packets_list.length ){
      log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_MESSAGE, 
              "Queue is full, dropping element");
      IPQ_SET_VERDICT(current->id,NF_DROP);
      return 0;
  }

  packets_list.length++;
  current->next=NULL;

  if (current->timestamp == 0){
    current->timestamp=time(NULL);
  } 

  if ( packets_list.end != NULL )
    packets_list.end->next=current;
  packets_list.end = current;
  if ( packets_list.start == NULL)
    packets_list.start = current;
  return current->id;
}


/* called by authsrv */

/**
 * Search an entry in packet list (::packets_list), and drop and
 * suppress old packets (using ::packet_timeout). If the packet can be found,
 * delete it and copy it's mark into nfmark.
 * 
 * \return Returns 1 and the mark (in nfmark) if the packet can be found, 0 else.
 */
int psearch_and_destroy (uint32_t packet_id,uint32_t * nfmark){
  packet_idl *current=packets_list.start,* previous=NULL;
  int timestamp=time(NULL);

  /* TODO: Do benchmarks and check if an hash-table + list (instead of just
   * list) wouldn't be faster than just a list when NuAuth is slow */
  while (current != NULL) {
    if ( current->id == packet_id){
#ifdef HAVE_LIBIPQ_MARK
      *nfmark=current->nfmark;
#endif

#ifdef PERF_DISPLAY_ENABLE
      {
	      struct timeval elapsed_time,leave_time;
              double ms;
	      gettimeofday(&leave_time,NULL);
	      timeval_substract (&elapsed_time,&leave_time,&(current->arrival_time));
              ms = (double)elapsed_time.tv_sec*1000 + (double)elapsed_time.tv_usec/1000;
	      log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_FATAL,
                      "Treatment time for connection: %.1f ms", ms);
      }
#endif


      psuppress (previous,current);
      return 1;

    /* we want to suppress first element if it is too old */
    } else if ( timestamp - current->timestamp  > packet_timeout) {
	  /* TODO : find a better place, does not satisfy me */
	  IPQ_SET_VERDICT(current->id,NF_DROP);
      debug_log_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_INFO, 
              "Dropped: %lu", current->id);
	  psuppress (previous,current);
	  current=packets_list.start;
	  previous=NULL;
	} else {
	  previous=current;
	  current=current->next;
	}
  }
  return 0;
}

/**
 * Walk in the packet list (::packets_list) and remove old packets (using ::packet_timeout limit).
 */
void clean_old_packets (){
  packet_idl *current=packets_list.start,* previous=NULL;
  int timestamp=time(NULL);

  while (current != NULL) {
    /* we want to suppress first element if it is too old */
    if ( timestamp - current->timestamp  > packet_timeout)
    {
	  IPQ_SET_VERDICT(current->id,NF_DROP);
      debug_log_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_DEBUG, 
              "Dropped: %lu", current->id);
	  psuppress (previous,current);
	  current=packets_list.start;
	  previous=NULL;
    } else {
	  current=NULL;
    }
  }
}

#ifdef GRYZOR_HACKS
int send_icmp_unreach(char *dgram){
    /* First thing we do, let's build the packet to send */
    /* sendmsg(); */
    sendto(raw_sock);
}
#endif

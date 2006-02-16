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
#include <stdlib.h>
#include <time.h>
#include <nufw.h>


/* datas stuffs */

/**
 * Remove packet current from the global packet list (see
 * ::packets_list_start). Free the packet memory.
 *
 * \param previous Packet before current
 * \param current Packet to remove
 */
void psuppress (packet_idl * previous,packet_idl * current){
  if (previous != NULL)
    previous->next=current->next;
  else
    packets_list_start=current->next;
  if (current->next == NULL) {
    packets_list_end=previous;
  }
  free(current);
  packets_list_length--;
}

/**
 * Create a packet at end of chained list. If we exceed max length 
 * (::track_size), we also suppress the first element which
 * is the older.
 *
 * \return Pointer to last element
 */
unsigned long padd (packet_idl *current){
  if (track_size < packets_list_length ){
    /* suppress first element */
    if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
      log_printf (DEBUG_LEVEL_MESSAGE, "Queue is full, dropping element");
    }
    IPQ_SET_VERDICT(current->id,NF_DROP);
    return 0;
  }

  packets_list_length++;
  current->next=NULL;

  if (current->timestamp == 0){
    current->timestamp=time(NULL);
  } 

  if ( packets_list_end != NULL )
    packets_list_end->next=current;
  packets_list_end = current;
  if ( packets_list_start == NULL)
    packets_list_start = current;
  return current->id;
}


/* called by authsrv */

/**
 * Search an entry in packet list (see ::packets_list_start), and drop and
 * delete old packets (using ::packet_timeout). If the packet can be found,
 * delete it and copy it's mark into nfmark.
 * 
 * \return Returns 1 and the mark (in nfmark) if the packet can be found, 0 else.
 */
int psearch_and_destroy (uint32_t packet_id,uint32_t * nfmark){
  packet_idl *packets_list=packets_list_start,* previous=NULL;
  int timestamp=time(NULL);

  /* TODO: Do benchmarks and check if an hash-table + list (instead of just
   * list) wouldn't be faster than just a list when NuAuth is slow */
  while (packets_list != NULL) {
    if ( packets_list->id == packet_id){
#ifdef HAVE_LIBIPQ_MARK
      *nfmark=packets_list->nfmark;
#endif
      psuppress (previous,packets_list);
      return 1;

    /* we want to suppress first element if it is too old */
    } else if ( timestamp - packets_list->timestamp  > packet_timeout) {
	  /* TODO : find a better place, does not satisfy me */
	  IPQ_SET_VERDICT(packets_list->id,NF_DROP);
#ifdef DEBUG_ENABLE
	  if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
	    log_printf ("Dropped: %lu", packets_list->id);
	  }
#endif
	  psuppress (previous,packets_list);
	  packets_list=packets_list_start;
	  previous=NULL;
	} else {
	  previous=packets_list;
	  packets_list=packets_list->next;
	}
  }
  return 0;
}

/**
 * Walk in the packet list and remove old packets (using ::packet_timeout limit).
 */
void clean_old_packets (){
  packet_idl *packets_list=packets_list_start,* previous=NULL;
  int timestamp=time(NULL);

  while (packets_list != NULL) {
    /* we want to suppress first element if it is too old */
    if ( timestamp - packets_list->timestamp  > packet_timeout)
    {
	  IPQ_SET_VERDICT(packets_list->id,NF_DROP);
#ifdef DEBUG_ENABLE
	  if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
	    log_printf (DEBUG_LEVEL_DEBUG, "Dropped: %lu", packets_list->id);
	  }
#endif
	  psuppress (previous,packets_list);
	  packets_list=packets_list_start;
	  previous=NULL;
    } else {
	  packets_list=NULL;
    }
  }
}

#ifdef GRYZOR_HACKS
int send_icmp_unreach(char *dgram){
    //First thing we do, let's build the packet to send
    //sendmsg();
    sendto(raw_sock);
}
#endif

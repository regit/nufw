/* $Id: common.c,v 1.3 2003/10/21 23:06:05 regit Exp $ */

/*
**
** Written by Eric Leblond <eric@regit.org>
**	      Vincent Deffontaines <vincent@gryzor.com>
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
#include <structure.h>
#include <debug.h>


/* datas stuffs */

int psuppress (packet_idl * previous,packet_idl * current){
  if (previous != NULL)
    previous->next=current->next;
  else
    packets_list_start=current->next;
  if (current->next == NULL) {
    packets_list_end=previous;
  }
  free(current);
  packets_list_length--;
  return 1;
}
/* create a packet at end of chained list, if we exceed max_length 
   then we also suppress the first element which is the older
   return : pointer to last element
*/
unsigned long padd (packet_idl *current){
  if (track_size < packets_list_length ){
    /* suppress first element */
    if (DEBUG_OR_NOT(DEBUG_LEVEL_MESSAGE,DEBUG_AREA_MAIN)){
      if (log_engine == LOG_TO_SYSLOG) {
        syslog(SYSLOG_FACILITY(DEBUG_LEVEL_MESSAGE),"Queue full, dropping element");
      }else {
        printf ("[%i] Queue full, dropping element\n",getpid());
      }
    }
  IPQ_SET_VERDICT(packets_list_start->id,NF_DROP);
    psuppress (NULL,packets_list_start);
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

/* search an entry, create it if not exists, suppress it if exists
   return mark if libipq is allright
*/
int psearch_and_destroy (unsigned long packet_id,unsigned long * nfmark){
  packet_idl *packets_list=packets_list_start,* previous=NULL;
  int timestamp=time(NULL);

  while (packets_list != NULL) {
    if ( packets_list->id == packet_id){
#ifdef HAVE_LIBIPQ_MARK
      *nfmark=packets_list->nfmark;
#endif
      psuppress (previous,packets_list);
      return 1;
    } else 
      /* we want to suppress first element if it is too old */
      if ( timestamp - packets_list->timestamp  > packet_timeout)
	{
	  /* TODO : find a better place, does not satisfy me */
	  IPQ_SET_VERDICT(packets_list->id,NF_DROP);
	  if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
	    if (log_engine == LOG_TO_SYSLOG) {
              syslog(SYSLOG_FACILITY(DEBUG_LEVEL_DEBUG),"dropped : %lu",packets_list->id);
            }else {
	    printf("[%i] dropped  : %lu\n",getpid(),packets_list->id);
	    }
	  }
	  psuppress (previous,packets_list);
	  packets_list=packets_list_start;
	  previous=NULL;
	}  else {
	  previous=packets_list;
	  packets_list=packets_list->next;
	}
  }
  return 0;
}

int clean_old_packets (){
  packet_idl *packets_list=packets_list_start,* previous=NULL;
  int timestamp=time(NULL);

  while (packets_list != NULL) {
    /* we want to suppress first element if it is too old */
    if ( timestamp - packets_list->timestamp  > packet_timeout)
      {
	IPQ_SET_VERDICT(packets_list->id,NF_DROP);
	if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
	  if (log_engine == LOG_TO_SYSLOG) {
            syslog(SYSLOG_FACILITY(DEBUG_LEVEL_DEBUG),"dropped : %lu",packets_list->id);
          }else {
	    printf("[%i] dropped  : %lu\n",getpid(),packets_list->id);
	  }
	}
	psuppress (previous,packets_list);
	packets_list=packets_list_start;
	previous=NULL;
      }  else {
	packets_list=NULL;
      }
  }
  return 0;
}

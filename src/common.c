/* $Id: common.c,v 1.1 2003/08/25 19:16:38 regit Exp $ */

/*
**
** Written by Eric Leblond <eric@regit.org>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
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
unsigned long padd (unsigned long packet_id,long timestamp){
  unsigned long pcktid=packet_id;
  packet_idl *current=NULL;
  if (track_size - packets_list_length == 1){
    /* suppress first element */
    if (debug){
      printf("Queue full, dropping element\n");
    }
    psuppress (NULL,packets_list_start);
  }
  current=calloc(1,sizeof( packet_idl));
  if (current == NULL){
    if (debug){ 
      printf("Can not allocate packet_id\n");
    } 
    return 0;
  }
  packets_list_length++;
  current->next=NULL;
  current->id=packet_id;
  current->timestamp=time(NULL);
  if ( packets_list_end != NULL )
    packets_list_end->next=current;
  packets_list_end = current;
  if ( packets_list_start == NULL)
    packets_list_start = current;
  return pcktid;
}


/* called by authsrv */

/* search an entry, create it if not exists, suppress it if exists*/
int psearch_and_destroy (unsigned long packet_id){
  packet_idl *packets_list=packets_list_start,* previous=NULL;
  int timestamp=time(NULL);

  while (packets_list != NULL) {
    if ( packets_list->id == packet_id){
      psuppress (previous,packets_list);
      return 1;
    } else 
      /* we want to suppress first element if it is too old */
      if ( timestamp - packets_list->timestamp  > PACKET_TIMEOUT)
	{
	  /* TODO : find a better place, does not satisfy me */
	  IPQ_SET_VERDICT(packets_list->id,NF_DROP);
	  if (debug){
	    printf("dropped  : %lu\n",packets_list->id);
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


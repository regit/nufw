/*
 ** Copyright (C) 2002-2005, Éric Leblond <eric@regit.org>
 **		       Vincent Deffontaines <vincent@gryzor.com>
 **                      INL http://www.inl.fr/
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

#include "nufw.h"



void* authsrv(void* data){
    int ret;
    char dgram[512];

    for(;;){
        ret= gnutls_record_recv(*tls.session,dgram,sizeof dgram);
        if (ret<0){
            if ( gnutls_error_is_fatal(ret) ){
                pthread_mutex_lock(tls.mutex);
                /* warn sender thread that it will need to reconnect at next access */
                tls.auth_server_running=0;
                pthread_mutex_unlock(tls.mutex);
                pthread_exit(NULL);
            }
        } else {
            auth_packet_to_decision(dgram);
        }
        memset(dgram,0,512);
    }
}


int auth_packet_to_decision(char* dgram)
{
  u_int32_t packet_id;
  int sandf;
  uint32_t nfmark;
  int res;
  switch (*dgram) {
    case 0x1:
            switch (*(dgram+1)) {
              case AUTH_ANSWER:
                      {
#ifdef WORDS_BIGENDIAN
                          packet_id=swap32(*(unsigned long *)(dgram+8));
#else
                          packet_id=*(unsigned long *)(dgram+8);
#endif
                          /* lock mutex */
                          pthread_mutex_lock(&packets_list_mutex);
                          /* search and destroy packet by packet_id */
                          sandf=psearch_and_destroy (packet_id,&nfmark);
                          pthread_mutex_unlock(&packets_list_mutex);

                          if (sandf){
                              if ( *(dgram+4) == OK ) {
                                  /* TODO : test on return */
#ifdef DEBUG_ENABLE
                                  if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
                                      if (log_engine == LOG_TO_SYSLOG) {
                                          syslog(SYSLOG_FACILITY(DEBUG_LEVEL_DEBUG),"Accepting %u",packet_id);
                                      }else {
                                          printf ("[%i] Accepting %u\n",getpid(),packet_id);
                                      }
                                  }
#endif
#if HAVE_LIBIPQ_MARK || USE_NFQUEUE
                                  if (nufw_set_mark) {
#ifdef DEBUG_ENABLE
                                      if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
                                          if (log_engine == LOG_TO_SYSLOG) {
                                              syslog(SYSLOG_FACILITY(DEBUG_LEVEL_DEBUG),"Marking packet with %d",*(u_int16_t *)(dgram+2));
                                          }else {
                                              printf("[%i] Marking packet with %d!\n",getpid(),*(u_int16_t *)(dgram+2));
                                          }
                                      }
#endif
                                      /* we put the userid mark at the end of the mark, not changing the 16 first big bits */
#ifdef WORDS_BIGENDIAN
                                      IPQ_SET_VWMARK(packet_id, NF_ACCEPT,((swap16(*(u_int16_t *)(dgram+2))) & 0xffff ) | (nfmark & 0xffff0000 )); 
#else
                                      IPQ_SET_VWMARK(packet_id, NF_ACCEPT,(*(u_int16_t *)(dgram+2) & 0xffff ) | (nfmark & 0xffff0000 )); 
#endif
                                  } else {
#endif
                                      IPQ_SET_VERDICT(packet_id, NF_ACCEPT);
                                  }

                                  pckt_tx++;
                                  return 1;
#ifdef GRYZOR_HACKS
                              }else if( *(dgram+4) == NOK_REJ){ //Packet is rejected, ie dropped and ICMP signalized
                                  if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
                                      if (log_engine == LOG_TO_SYSLOG) {
                                          syslog(SYSLOG_FACILITY(DEBUG_LEVEL_DEBUG),"Rejecting %lu",packet_id);
                                      }else{
                                          printf ("[%i] Rejecting %lu\n",getpid(),packet_id);
                                      }
                                  }
                                  IPQ_SET_VERDICT(packet_id, NF_DROP);
                                  send_icmp_unreach(dgram);
                                  return 0;
#endif
                              } else {
#ifdef DEBUG_ENABLE
                                  if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_MAIN)){
                                      if (log_engine == LOG_TO_SYSLOG) {
                                          syslog(SYSLOG_FACILITY(DEBUG_LEVEL_DEBUG),"Dropping %u",packet_id);
                                      }else{
                                          printf ("[%i] Dropping %u\n",getpid(),packet_id);
                                      }
                                  }
#endif
                                  IPQ_SET_VERDICT(packet_id, NF_DROP);
                                  return 0;
                              }
                          } else {
                              if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
                                  if (log_engine == LOG_TO_SYSLOG) {
                                      syslog(SYSLOG_FACILITY(DEBUG_LEVEL_WARNING),"Packet without a known ID : %u",packet_id);
                                  }else{
                                      printf("[%i] Packet without a known ID : %u\n",getpid(),packet_id);
                                  }
                              }
                          }
                      } 
                      break;
              case AUTH_CONN_DESTROY:
                      {
#ifdef HAVE_LIBCONNTRACK
                        struct nuv2_destroy_message* packet_hdr=(struct nuv2_destroy_message*)dgram;
                        struct nfct_tuple orig;
                        int id=0;
                        orig.src.v4=packet_hdr->src;
                        orig.dst.v4=packet_hdr->dst;
                        orig.protonum=packet_hdr->ipproto;

                        switch (packet_hdr->ipproto){
                          case IPPROTO_TCP:
                                  orig.l4src.tcp.port=packet_hdr->sport;  
                                  orig.l4dst.tcp.port=packet_hdr->dport;  
                                  break;
                          case IPPROTO_UDP:
                                  orig.l4src.udp.port=packet_hdr->sport;  
                                  orig.l4dst.udp.port=packet_hdr->dport;  
                                  break;
                          default:
                                  return 0; 
                        }
                        printf("try to delete sport=%d dport=%d\n",orig.l4src.tcp.port,orig.l4dst.tcp.port);fflush(NULL);
                        res = nfct_delete_conntrack(cth, &orig, 
                                        NFCT_DIR_ORIGINAL,
                                        id);


#else
                      if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN)){
                          if (log_engine == LOG_TO_SYSLOG) {
                              syslog(SYSLOG_FACILITY(DEBUG_LEVEL_WARNING),"Connexion destroy message not supported");
                          } else {
                              printf("[%i] Connexion destroy message not supported\n",getpid());
                          }
                      }
#endif
                      }
                      break;
              default:
                      {
                          if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN)){
                              if (log_engine == LOG_TO_SYSLOG) {
                                  syslog(SYSLOG_FACILITY(DEBUG_LEVEL_DEBUG),"Type %d for packet %lu (not for me)",*(dgram+1),*(unsigned long * )(dgram+4));
                              }else{
                                  printf("[%i] Type %d for packet %lu (not for me)\n",getpid(),*(dgram+1),*(unsigned long * )(dgram+4));
                              }
                          }
                      }
                      break;
            }
  }
  return 1;
}

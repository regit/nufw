/*
 * Copyright 2005 - INL
 *	written by Eric Leblond <regit@inl.fr>
 *	           Vincent Deffontaines <vincent@inl.fr>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "nuclient.h"
#include <sasl/saslutil.h>
#include <proto.h>
#include <jhash.h>
#include "proc.h"
#include "client.h"


/**
 * Thread waiting for nuauth message to do client tasks
 *
 * Message from nuauth :
 * - SRV_REQUIRED_PACKET : awake nu_client_thread_check
 * - SRV_REQUIRED_HELLO : send hello back to nuauth
 */

void* recv_message(void *data)
{
        NuAuth* session=(NuAuth*)data;
	int ret;
	char dgram[512];
	struct nuv2_header header;
	struct nuv2_authreq authreq;
	struct nuv2_authfield_hello hellofield;
	int message_length= sizeof(struct nuv2_header)+sizeof(struct nuv2_authfield_hello)+sizeof(struct nuv2_authreq);
	char message[sizeof(struct nuv2_header)+sizeof(struct nuv2_authfield_hello)+sizeof(struct nuv2_authreq)];
	char* pointer=NULL;

        //return NULL;
	/* fill struct */
	header.proto=PROTO_VERSION;
	header.msg_type=USER_REQUEST;
	header.option=0;
	header.length=htons(sizeof(struct nuv2_header)+sizeof(struct nuv2_authreq)+sizeof(struct nuv2_authfield_hello));

	memcpy(message,&header,sizeof(struct nuv2_header));
	authreq.packet_id=session->packet_id++;
	authreq.packet_length=sizeof(struct nuv2_authreq)+sizeof(struct nuv2_authfield_hello);

	pointer=message+sizeof(struct nuv2_header);
	memcpy(pointer,&authreq,sizeof(struct nuv2_authreq));
	pointer+=sizeof(struct nuv2_authreq);
	hellofield.type=HELLO_FIELD;
	hellofield.option=0;
	hellofield.length=htons(sizeof(struct nuv2_authfield_hello));

        pthread_cleanup_push(pthread_mutex_unlock, (void*)(&(session->check_count_mutex)));

        for (;;){
            ret= gnutls_record_recv(session->tls,dgram,sizeof dgram);
            if (ret<=0){
                if ( gnutls_error_is_fatal(ret) ){
                    ask_session_end(session);
                    return NULL;
                }
            } else {
                switch (*dgram){
                  case SRV_REQUIRED_PACKET:
                      /* wake up nu_client_real_check_tread */
                      pthread_mutex_lock(&(session->check_count_mutex));
                      session->count_msg_cond++;
                      pthread_mutex_unlock(&(session->check_count_mutex));
                      pthread_cond_signal(&(session->check_cond));
                      break;
                  case SRV_REQUIRED_HELLO:
                      hellofield.helloid = ((struct nuv2_srv_helloreq*)dgram)->helloid;
                      memcpy(pointer,&hellofield,sizeof(struct nuv2_authfield_hello));
                      /*  send it */
                      if(session->tls){
                          if( gnutls_record_send(session->tls,message,
                                      message_length
                                      )<=0){
#if DEBUG_ENABLE
                              printf("write failed at %s:%d\n",__FILE__,__LINE__);
#endif
                              ask_session_end(session);
                              return NULL;
                          }
                      }

                      break;
                  default:
                      printf("unknown message\n");
                }
            }
        }
        pthread_cleanup_pop(1);
}


/**
 * Function call by client to initiate a check
 *
 *
 * It is in charge of cleaning session as the session may be used
 * by user and we have no control of it. It has to be called for the first
 * time AFTER all forks occurs to create the working threads. This is 
 * mandatory and occurs because fork does not replicate the threads.
 * 
 * - In poll mode :
 * 	this is just a wrapper to nu_client_real_check
 * - In push mode :
 * 	It is used to send HELLO message
 * 
 * Return -1 if a problem occurs. Session is destroyed if nu_client_check return -1;
 */

int nu_client_check(NuAuth * session)
{
		pthread_mutex_lock(&(session->mutex));
                /* test is a thread has detected problem with the session */
                if (session->connected==0){
                    /* if we are here, threads are dead */
                    pthread_mutex_unlock(&(session->mutex));
                    nu_exit_clean(session);
                    return -1;
                } 
                /* test if we need to create the working thread */
                if (session->count_msg_cond == -1){ /* if set to -1 then we've just leave init */
			if (session->mode == SRV_TYPE_PUSH) {
				pthread_mutex_init(&(session->check_count_mutex),NULL);
				pthread_cond_init(&(session->check_cond),NULL);
				pthread_create(&(session->checkthread), NULL, nu_client_thread_check, session);
			}
			pthread_create(&(session->recvthread), NULL, recv_message, session);
		}
	
		pthread_mutex_unlock(&(session->mutex));
		if (session->mode == SRV_TYPE_POLL) {
			int checkreturn;
			checkreturn = nu_client_real_check(session);
			if (checkreturn == -1){
				/* kill all threads */
				ask_session_end(session);
				/* cleaning up things */
				nu_exit_clean(session);
				return -1;
			} else {
				return checkreturn;
			}
		} else {
			if ((time(NULL) - session->timestamp_last_sent) > SENT_TEST_INTERVAL){
				if (! send_hello_pckt(session)){
					/* kill all threads */
					ask_session_end(session);
					/* cleaning up things */
					nu_exit_clean(session);
					return -1;
				}
				session->timestamp_last_sent=time(NULL);
			}
		}
		return 1;
	
}

void clear_local_mutex(void* mutex)
{
        pthread_mutex_unlock(mutex);
        pthread_mutex_destroy(mutex);
}

/**
 * Function used to launch check in push mode
 *
 * This is a thread waiting to a condition to awake and launch
 * nu_client_real_check
 *
 */
void* nu_client_thread_check(void *data)
{
        NuAuth * session=(NuAuth*)data;
	pthread_mutex_t check_mutex;
	pthread_mutex_init(&check_mutex,NULL);

        pthread_cleanup_push(pthread_mutex_unlock, (void*)&(session->check_count_mutex));
        pthread_cleanup_push(clear_local_mutex, (void*)&check_mutex );
	for(;;){
		nu_client_real_check(session);
	/* Do we need to do an other check ? */
		pthread_mutex_lock(&(session->check_count_mutex));
		if (session->count_msg_cond>0){
			pthread_mutex_unlock(&(session->check_count_mutex));
		} else {
			pthread_mutex_unlock(&(session->check_count_mutex));
			/* wait for cond */
			pthread_mutex_lock(&check_mutex);
			pthread_cond_wait(&(session->check_cond), &check_mutex);
			pthread_mutex_unlock(&check_mutex);
		}
	}

        pthread_cleanup_pop(1);
        pthread_cleanup_pop(0);

        return NULL;
}

/**
 * Function that check connections table and send authentication packets
 *
 * -# read the list of connections and build a conntrack table (call to tcptable_read)
 * -# init program list (/proc/ reading) 
 * -# compare current table with old one (compare call)
 * -# free and return
 *
 * Return : Number of authenticated packets
 */
int nu_client_real_check(NuAuth * session)
{
	conntable_t *new;
	int nb_packets=0;
	if (tcptable_init (&new) == 0) panic ("tcptable_init failed");
	if (tcptable_read (session,new) == 0) panic ("tcptable_read failed");
#ifdef LINUX
	/* update cache for link between proc and socket inode */
	prg_cache_load();
#endif
	nb_packets = compare (session,session->ct, new);
	/* free link between proc and socket inode */
#ifdef LINUX
	prg_cache_clear();
#endif

	if (nb_packets < 0){
		/* error we ask client to exit */
		ask_session_end(session);
		return nb_packets;
	}
	if (tcptable_free (session->ct) == 0) panic ("tcptable_free failed");
	session->ct=new;

	return nb_packets;
}

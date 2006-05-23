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

/** \addtogroup libnuclient
 * @{
 */

typedef void (*pthread_cleanup_push_arg1_t) (void *);

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
	const size_t message_length= sizeof(struct nuv2_header)+sizeof(struct nuv2_authfield_hello)+sizeof(struct nuv2_authreq);
	char message[message_length];
	struct nuv2_header *header;
	struct nuv2_authreq *authreq;
	struct nuv2_authfield_hello *hellofield;

	/* fill struct */
    header = (struct nuv2_header *)message;
	header->proto=PROTO_VERSION;
	header->msg_type=USER_REQUEST;
	header->option=0;
	header->length=htons(message_length);

    authreq = (struct nuv2_authreq *)(header + 1);
	authreq->packet_seq = session->packet_seq++;
	authreq->packet_length = htons(sizeof(struct nuv2_authreq)+sizeof(struct nuv2_authfield_hello));

    hellofield = (struct nuv2_authfield_hello *)(authreq + 1);
	hellofield->type=HELLO_FIELD;
	hellofield->option=0;
	hellofield->length=htons(sizeof(struct nuv2_authfield_hello));

        pthread_cleanup_push((pthread_cleanup_push_arg1_t)pthread_mutex_unlock, &session->check_count_mutex);

        for (;;){
            ret= gnutls_record_recv(session->tls,dgram,sizeof dgram);
            if (ret<=0){
                if ( gnutls_error_is_fatal(ret) ){
                    ask_session_end(session);
                    return NULL;
                }
            } else {
                switch (dgram[0]){
                  case SRV_REQUIRED_PACKET:
                      /* wake up nu_client_real_check_tread */
                      pthread_mutex_lock(&(session->check_count_mutex));
                      session->count_msg_cond++;
                      pthread_mutex_unlock(&(session->check_count_mutex));
                      pthread_cond_signal(&(session->check_cond));
                      break;
                  case SRV_REQUIRED_HELLO:
                      hellofield->helloid = ((struct nuv2_srv_helloreq*)dgram)->helloid;
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
	return NULL;
}


/**
 * \ingroup nuclientAPI
 * \brief Function called by client to initiate a check
 *
 * It has to be run at regular interval :
 *  - In POLL mode, it is really doing the job. 
 *  - In PUSH mode, it is used to detect failure and send HELLO message
 *  
 * \param session A pointer to a valid ::NuAuth session
 * \param err A pointer to a allocated ::nuclient_error
 * \return -1 if a problem occurs. Session is destroyed if nu_client_check() return -1;
 *
 * \par Internal
 * It is in charge of cleaning session as the session may be used
 * by user and we have no control of it. It has to be called for the first
 * time AFTER all forks occurs to create the working threads. This is 
 * mandatory and occurs because fork does not replicate the threads.
 * 
 *  - Poll mode: this is just a wrapper to nu_client_real_check
 *  - Push mode: It is used to send HELLO message
 *
 */
int nu_client_check(NuAuth * session, nuclient_error *err)
{
		pthread_mutex_lock(&(session->mutex));
                /* test is a thread has detected problem with the session */
                if (session->connected==0){
                    /* if we are here, threads are dead */
                    pthread_mutex_unlock(&(session->mutex));
                    nu_exit_clean(session);
                    SET_ERROR(err, INTERNAL_ERROR, SESSION_NOT_CONNECTED_ERR);
                    return -1;
                } 
                /* test if we need to create the working thread */
                if (session->count_msg_cond == -1){ /* if set to -1 then we've just leave init */
			if (session->server_mode == SRV_TYPE_PUSH) {
				pthread_mutex_init(&(session->check_count_mutex),NULL);
				pthread_cond_init(&(session->check_cond),NULL);
				pthread_create(&(session->checkthread), NULL, nu_client_thread_check, session);
			}
			pthread_create(&(session->recvthread), NULL, recv_message, session);
		}
	
		pthread_mutex_unlock(&(session->mutex));
		if (session->server_mode == SRV_TYPE_POLL) {
			int checkreturn;
			checkreturn = nu_client_real_check(session, err);
			if (checkreturn == -1){
				/* kill all threads */
				ask_session_end(session);
				/* cleaning up things */
				nu_exit_clean(session);
				return -1;
			} else {
                                SET_ERROR(err, INTERNAL_ERROR, NO_ERR);
				return checkreturn;
			}
		} else {
			if ((time(NULL) - session->timestamp_last_sent) > SENT_TEST_INTERVAL){
				if (! send_hello_pckt(session)){
					/* kill all threads */
					ask_session_end(session);
					/* cleaning up things */
					nu_exit_clean(session);
                                        SET_ERROR(err, INTERNAL_ERROR, TIMEOUT_ERR);
					return -1;
				}
				session->timestamp_last_sent=time(NULL);
			}
		}
                SET_ERROR(err, INTERNAL_ERROR, NO_ERR);
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

        pthread_cleanup_push((pthread_cleanup_push_arg1_t)pthread_mutex_unlock, &session->check_count_mutex);
        pthread_cleanup_push((pthread_cleanup_push_arg1_t)clear_local_mutex, &check_mutex);
	for(;;){
		nu_client_real_check(session, NULL);
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
 * Function that check connections table and send authentication packets:
 *    - Read the list of connections and build a conntrack table 
 *      (call to tcptable_read()) ;
 *    - Initialize program list (/proc/ reading) ;
 *    - Compare current table with old one (compare call) ;
 *    - Free and return.
 *
 * \return Number of authenticated packets, or negative number on failure
 */
int nu_client_real_check(NuAuth *session, nuclient_error *err)
{
	conntable_t *new;
	int nb_packets=0;
    if (session->debug_mode)
    {
        printf("[+] Client is asked to send new connections.\n");
    }
	if (tcptable_init (&new) == 0)
        {
            SET_ERROR(err, INTERNAL_ERROR, MEMORY_ERR);
            return -1;
        }
	if (tcptable_read (session,new) == 0)
        {
            SET_ERROR(err, INTERNAL_ERROR, TCPTABLE_ERR);
            return -1;
        }
#ifdef LINUX
	/* update cache for link between proc and socket inode */
	prg_cache_load();
#endif
	nb_packets = compare (session,session->ct, new, err);
	/* free link between proc and socket inode */
#ifdef LINUX
	prg_cache_clear();
#endif

	tcptable_free (session->ct);

        /* on error, we ask client to exit */
	if (nb_packets < 0){
		ask_session_end(session);
		return nb_packets;
	}
	session->ct=new;

	return nb_packets;
}

/**
 * Function snprintf() which check buffer overflow, and always write a '\\0'
 * to the end of the buffer.
 *
 * \param buffer Buffer where characters are written
 * \param buffer_size Buffer size (in bytes), usually equals to sizeof(buffer)
 * \param format Format string (see printf() documentation)
 * \return Returns FALSE if a buffer overflow occurs, TRUE is everything goes fine.
 */
int secure_snprintf(char *buffer, unsigned int buffer_size, char *format, ...)
{
    va_list args;  
    int ret;
    va_start(args, format);
    ret = vsnprintf(buffer, buffer_size, format, args);
    va_end(args);
    buffer[buffer_size-1] = '\0';
    if (0 <= ret && ret <= ((int)buffer_size-1))
        return 1;
    else
        return 0;
}    

/** @} */

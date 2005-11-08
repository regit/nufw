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



void recv_message(NuAuth* session)
{
	int ret;
	char dgram[512];
	struct nuv2_header header;
	struct nuv2_authreq authreq;
	struct nuv2_authfield_hello hellofield;
	int message_length= sizeof(struct nuv2_header)+sizeof(struct nuv2_authfield_hello)+sizeof(struct nuv2_authreq);
	char * message=calloc(
			message_length/sizeof(char),
			sizeof(char));
	char* pointer=NULL;

	/* fill struct */
	header.proto=0x2;
	header.msg_type=USER_REQUEST;
	header.option=0;
#ifdef WORDS_BIGENDIAN
	header.length=swap16(sizeof(struct nuv2_header)++sizeof(struct nuv2_authreq)+sizeof(struct nuv2_authfield_hello));
#else
	header.length=sizeof(struct nuv2_header)+sizeof(struct nuv2_authreq)+sizeof(struct nuv2_authfield_hello);
#endif

	memcpy(message,&header,sizeof(struct nuv2_header));
	authreq.packet_id=session->packet_id++;
	authreq.packet_length=sizeof(struct nuv2_authreq)+sizeof(struct nuv2_authfield_hello);

	pointer=message+sizeof(struct nuv2_header);
	memcpy(pointer,&authreq,sizeof(struct nuv2_authreq));
	pointer+=sizeof(struct nuv2_authreq);
	hellofield.type=HELLO_FIELD;
	hellofield.option=0;
#ifdef WORDS_BIGENDIAN
	hellofield.length=swap16(sizeof(struct nuv2_authfield_hello));
#else
	hellofield.length=sizeof(struct nuv2_authfield_hello);
#endif

	for (;;){
		if (conn_on && session){
			ret= gnutls_record_recv(*session->tls,dgram,sizeof dgram);
			if (ret<0){
				if ( gnutls_error_is_fatal(ret) ){
					if (conn_on){
						nu_exit_clean(session);
					}
					return;
				}
			} else {
				switch (*dgram){
					case SRV_REQUIRED_PACKET:
						/* TODO ? introduce a delay to not DOS our own client */
						/* we act */
						nu_client_real_check(session);
						break;
					case SRV_REQUIRED_HELLO:
						hellofield.helloid = ((struct nuv2_srv_helloreq*)dgram)->helloid;
						memcpy(pointer,&hellofield,sizeof(struct nuv2_authfield_hello));
						/*  send it */
						if(session->tls){
							if( gnutls_record_send(*(session->tls),message,
										message_length
									      )<=0){
#if DEBUG_ENABLE
								printf("write failed at %s:%d\n",__FILE__,__LINE__);
#endif
								if (conn_on){
									nu_exit_clean(session);
								}
								return;
							}
						}

						break;
					default:
						printf("unknown message\n");
				}
			}
		} else {
			return;
		}

	}
}



int nu_client_check(NuAuth * session)
{
	if (conn_on == 0 ){
		errno=ECONNRESET;
		return -1;
	}

	/* TODO : use less ressource be clever */
	if (recv_started == 0){
		pthread_t recvthread;
		pthread_create(&recvthread, NULL, recv_message, session);
		recv_started =1;
	}

	if (session->mode == SRV_TYPE_POLL) {
		return	nu_client_real_check(session);
	}
	else {
		if ((time(NULL) - timestamp_last_sent) > SENT_TEST_INTERVAL){
			if (! send_hello_pckt(session)){
				nu_exit_clean(session);
			}
			timestamp_last_sent=time(NULL);
		}
	}
	return 0;
}



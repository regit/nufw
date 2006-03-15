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
#include "client.h"

#if DEBUG_ENABLE
int count;
#endif

int send_hello_pckt(NuAuth * session){
    struct nuv2_header header;

    /* fill struct */
    header.proto=PROTO_VERSION;
    header.msg_type=USER_HELLO;
    header.option=0;
    header.length=htons(sizeof(struct nuv2_header));

    /*  send it */
    if(session->tls){
        if( gnutls_record_send(session->tls,&header,sizeof(struct nuv2_header))<=0){
#if DEBUG_ENABLE
            printf("write failed at %s:%d\n",__FILE__,__LINE__);
#endif
            return 0;
        }
    }
    return 1;
}

/*
 * send_user_pckt
 */
int send_user_pckt(NuAuth * session,conn_t* carray[CONN_MAX])
{
  char datas[PACKET_SIZE];
  char *pointer=NULL;
  char *enc_appname=NULL;
  int item=0;

  session->timestamp_last_sent=time(NULL);
  memset(datas,0,sizeof datas);
  pointer=datas+sizeof(struct nuv2_header);
  switch (session->protocol){
    case PROTO_VERSION:
      {
          struct nuv2_header header;
          header.proto=PROTO_VERSION;
          header.msg_type=USER_REQUEST;
          header.option=0;
          header.length=sizeof(struct nuv2_header);

          for(item=0;((item<CONN_MAX) && carray[item]);item++){
              struct nuv2_authreq authreq;
              struct nuv2_authfield_ipv4 authfield;
              struct nuv2_authfield_app appfield;
              size_t len=0;
              /* get application name from inode */
              const char * appname = NULL;

#if DEBUG
                printf("adding one authreq\n"); 
#endif
#ifdef LINUX
              appname = prg_cache_get(carray[item]->ino);
#else
		appname="UNKNOWN";
#endif
              header.length+=sizeof(struct nuv2_authreq)+sizeof(struct nuv2_authfield_ipv4);
              authreq.packet_id=session->packet_id++;
              authreq.packet_length=sizeof(struct nuv2_authreq)+sizeof(struct nuv2_authfield_ipv4);
              authfield.type=IPV4_FIELD;
              authfield.option=0;
              authfield.length=htons(sizeof(struct nuv2_authfield_ipv4));

              authfield.src=htonl(carray[item]->lcl);
              authfield.dst=htonl(carray[item]->rmt);
              authfield.proto=carray[item]->proto;
              authfield.flags=0;
              authfield.FUSE=0;
              authfield.sport=htons(carray[item]->lclp);
              authfield.dport=htons(carray[item]->rmtp);
              /* application field  */
              appfield.type=APP_FIELD;
#if 0
              if (1) {
#endif
                  appfield.option=APP_TYPE_NAME;
                  enc_appname=calloc(128,sizeof(char));
                  if ( sasl_encode64(appname,strlen(appname),
                        enc_appname,128, &len) == SASL_BUFOVER ){
                      /* realloc */
                      enc_appname=realloc(enc_appname,len);
                      /* encode */
                      sasl_encode64(appname,strlen(appname),
                          enc_appname, len, &len);
                  }
                  appfield.length=4+len;
                  appfield.datas=enc_appname;
                  authreq.packet_length+=appfield.length;
#if 0
              } else {
                  appfield.option=APP_TYPE_SHA1;
                  enc_appname=calloc(128,sizeof(char));
                  if ( sasl_encode64(appname,strlen(appname),
                        enc_appname,128, &len) == SASL_BUFOVER ){
                      /* realloc */
                      enc_appname=realloc(enc_appname,len);
                      /* encode */
                      sasl_encode64(appname,strlen(appname),
                          enc_appname, len, &len);
                  }
                  appfield.length=4+len;
                  appfield.datas=g_strconcat(enc_appname,";",sha1_sig);
              }
#endif
              /* glue piece together on data if packet is not too long */
              header.length+=appfield.length;
              if (header.length < PACKET_SIZE){
                  appfield.length=htons(appfield.length);
                  authreq.packet_length=htons(authreq.packet_length);
                  memcpy(pointer,&authreq,sizeof(struct nuv2_authreq));
                  pointer+=sizeof(struct nuv2_authreq);
                  memcpy(pointer,&authfield,sizeof(struct nuv2_authfield_ipv4));
                  pointer+=sizeof(struct nuv2_authfield_ipv4);
                  memcpy(pointer,&appfield,4);
                  pointer+=4;
                  if ((int)len < (PACKET_SIZE + datas - pointer)){
                      memcpy(pointer,appfield.datas,len);
                  } else {
                      if (enc_appname)
                          free(enc_appname);
                      return 1;
                  }
                  pointer+=len;
              } else {
                  if (enc_appname)
                      free(enc_appname);
                  return 1;
              }
          }
          header.length=htons(header.length);
          memcpy(datas,&header,sizeof(struct nuv2_header));

      }
      break;
    default:
      return 1;
  }

  /* and send it */
  if(session->tls){
      if( gnutls_record_send(session->tls,datas,pointer-datas)<=0){
          printf("write failed\n");
          return 0;
      }
  }
  if (enc_appname)
      free(enc_appname);
  return 1;
}



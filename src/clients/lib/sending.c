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

/**
 * \addtogroup libnuclient
 * @{
 */

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


/**
 * Send connections to nuauth: between 1 and #CONN_MAX connections
 * in a big packet of format:
 *   [ nuv2_header + nuv2_authfield_ipv6 * N ]
 */
int send_user_pckt(NuAuth * session,conn_t* carray[CONN_MAX])
{
  char datas[PACKET_SIZE];
  char *pointer;
  unsigned int item;
  struct nuv2_header *header;
  struct nuv2_authreq *authreq;
  struct nuv2_authfield_ipv6 *authfield;
  struct nuv2_authfield_app *appfield;
  size_t len;
  const char *appname;
  char *app_ptr;

  session->timestamp_last_sent=time(NULL);
  memset(datas,0,sizeof datas);

  if (session->protocol != PROTO_VERSION) {
      return 1;
  }

  header = (struct nuv2_header *)datas;
  header->proto = PROTO_VERSION;
  header->msg_type = USER_REQUEST;
  header->option = 0;
  header->length = sizeof(struct nuv2_header);
  pointer = (char*)(header + 1);

  for (item=0; ((item<CONN_MAX) && carray[item] != NULL); item++)
  {
#if DEBUG
      printf("adding one authreq\n"); 
#endif
#ifdef LINUX
      /* get application name from inode */
      appname = prg_cache_get(carray[item]->inode);
#else
      appname="UNKNOWN";
#endif
      header->length+=sizeof(struct nuv2_authreq)+sizeof(struct nuv2_authfield_ipv6);
      
      authreq = (struct nuv2_authreq *)pointer;
      authreq->packet_seq = session->packet_seq++;
      authreq->packet_length = sizeof(struct nuv2_authreq)+sizeof(struct nuv2_authfield_ipv6);
     
      authfield = (struct nuv2_authfield_ipv6 *)(authreq+1);
      authfield->type = IPV6_FIELD;
      authfield->option = 0;
      authfield->src = carray[item]->ip_src;
      authfield->dst = carray[item]->ip_dst;
      authfield->proto = carray[item]->protocol;
      authfield->flags = 0;
      authfield->FUSE = 0;
      authfield->sport = htons(carray[item]->port_src);
      authfield->dport = htons(carray[item]->port_dst);

      /* application field  */
      appfield = (struct nuv2_authfield_app *)(authfield+1); 
      appfield->type=APP_FIELD;
#ifdef USE_SHA1
      appfield->option=APP_TYPE_SHA1;
#else
      appfield->option=APP_TYPE_NAME;
#endif          
      app_ptr = (char*)(appfield+1);
      sasl_encode64(appname,strlen(appname),app_ptr, PROGNAME_BASE64_WIDTH, &len);
#ifdef USE_SHA1
      *(app_ptr+len) = ';';
      len++;
      strcpy(app_ptr+len, sha1_sig);
      len += strlen(sha1_sig);
#endif
      appfield->length=sizeof(appfield)+len;
      authreq->packet_length+=appfield->length;

      /* glue piece together on data if packet is not too long */
      header->length+=appfield->length;

      assert (header->length < PACKET_SIZE);

      pointer += authreq->packet_length;

      appfield->length=htons(appfield->length);
      authreq->packet_length=htons(authreq->packet_length);
      authfield->length=htons(sizeof(struct nuv2_authfield_ipv6));
  }
  header->length=htons(header->length);
  if (session->debug_mode)
  {
      printf("[+] Send %u new connection(s) to nuauth\n", item);
  }

  /* and send it */
  if(session->tls){
      if( gnutls_record_send(session->tls,datas,pointer-datas)<=0){
          printf("write failed\n");
          return 0;
      }
  }
  return 1;
}

/** @} */

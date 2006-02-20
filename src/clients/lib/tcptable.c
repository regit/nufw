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
#include "client.h"
#include "libnuclient.h"
#include <proto.h>
#ifdef FREEBSD

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/protosw.h>

#include <netinet/tcp_fsm.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp_var.h>
#endif

/*! \file tcptable.c
  \brief TCP parsing function

  Contains the TCP parsing functions
 */

/**
 * \brief Read tcptable
 *
 * Read /proc/net/tcp and add all connections to the table if connections
 * of that type are being watched.
 */

int tcptable_read (NuAuth* session, conntable_t *ct)
{
  conn_t c;
#ifdef LINUX 
  static FILE *fp = NULL;
  static FILE *fq = NULL;
  char buf[1024];
#if DEBUG
  assert (ct != NULL);
#endif
  if ( session->mode==SRV_TYPE_PUSH){
      /* need to set check_cond */
      pthread_mutex_lock(&(session->check_count_mutex));
      session->count_msg_cond=0;
      pthread_mutex_unlock(&(session->check_count_mutex));
  }
  /* open file */
  if (fp == NULL) {
      fp = fopen ("/proc/net/tcp", "r");
      if (fp == NULL) panic ("/proc/net/tcp: %s", strerror (errno));
  }
  rewind (fp);

  if (fgets (buf, sizeof (buf), fp) == NULL)
      panic ("/proc/net/tcp: missing header");

  while (fgets (buf, sizeof (buf), fp) != NULL) {
      unsigned long st;
#ifdef USE_FILTER
      int seen = 0;
#endif
      if (sscanf (buf, "%*d: %lx:%x %lx:%x %lx %*x:%*x %*x:%*x %x %lu %*d %lu",
                  &c.lcl, &c.lclp, &c.rmt, &c.rmtp, &st, &c.retransmit, &c.uid, &c.ino) != 8)
          continue;

      if ((c.ino == 0) || (st != TCP_SYN_SENT))
          continue;

      // Check if it's the good user
      if (c.uid != session->localuserid)
          continue;
#if DEBUG
      // Check if there is a matching rule in the filters list
      printf("Packet dst = %ld (%lx)\n", c.rmt, c.rmt);
#endif
      /* Check if it's the good user */
      if (c.uid != session->localuserid)
          continue;
#ifdef USE_FILTER
      // If we're sure auth_by_default is either 0 or 1, it can be simplified.
      // (MiKael) TODO: Make sure!! :)
      if (session->auth_by_default && seen)
          continue;
      if (!session->auth_by_default && !seen)
          continue;
#endif
      c.proto=IPPROTO_TCP;
      
      c.lcl=ntohl(c.lcl);
      c.rmt=ntohl(c.rmt);
      if (tcptable_add (ct, &c) == 0)
          return 0;
  }

  /* open file */
  if (fq == NULL) {
      fq = fopen ("/proc/net/udp", "r");
      if (fq == NULL) panic ("/proc/net/udp: %s", strerror (errno));
  }
  rewind (fq);

  if (fgets (buf, sizeof (buf), fq) == NULL)
      panic ("/proc/net/udp: missing header");

  while (fgets (buf, sizeof (buf), fq) != NULL) {
      unsigned long st;
      if (sscanf (buf, "%*d: %lx:%x %lx:%x %lx %*x:%*x %*x:%*x %x %lu %*d %lu",
                  &c.lcl, &c.lclp, &c.rmt, &c.rmtp, &st, &c.retransmit, &c.uid, &c.ino) != 8)
          continue;

      if (c.ino == 0) 
          continue;

      // Check if it's the good user
      if (c.uid != session->localuserid)
          continue;

      c.lcl=ntohl(c.lcl);
      c.rmt=ntohl(c.rmt);
#if DEBUG
      // Check if there is a matching rule in the filters list
      printf("Packet dst = %ld (%lx)\n", c.rmt, c.rmt);
#endif

#if USE_FILTER
      // If we're sure auth_by_default is either 0 or 1, it can be simplified.
      // (MiKael) TODO: Make sure!! :)
      if (session->auth_by_default && seen)
          continue;
      if (!session->auth_by_default && !seen)
          continue;
#endif
      c.proto=IPPROTO_UDP;
      if (tcptable_add (ct, &c) == 0)
          return 0;
  }


#else /* LINUX */
#ifdef FREEBSD
      int istcp;
  char *buf;
  const char *mibvar;
  struct tcpcb *tp = NULL;
  struct inpcb *inp;
  struct xinpgen *xig, *oxig;
  struct xsocket *so;
  size_t len;
  int proto = IPPROTO_TCP;
#if 0
  istcp = 0;
  switch (proto) {
    case IPPROTO_TCP:
#endif
        istcp = 1;
        mibvar = "net.inet.tcp.pcblist";
#if 0
        break;
    case IPPROTO_UDP:
        mibvar = "net.inet.udp.pcblist";
        break;
  }
#endif
  len = 0;
  if (sysctlbyname(mibvar, 0, &len, 0, 0) < 0) {
      if (errno != ENOENT)
          printf("sysctl: %s", mibvar);
      return 0;
  }
  if ((buf = malloc(len)) == 0) {
      printf("malloc %lu bytes", (u_long)len);
      return 0;
  }

  if ( session->mode==SRV_TYPE_PUSH){
      /* need to set check_cond */
      pthread_mutex_lock(session->check_count_mutex);
      session->count_msg_cond=0;
      pthread_mutex_unlock(session->check_count_mutex);
  }
  /* open file */
  if (sysctlbyname(mibvar, buf, &len, 0, 0) < 0) {
      printf("sysctl: %s", mibvar);
      free(buf);
      return 0;
  }

  oxig = xig = (struct xinpgen *)buf;
  for (xig = (struct xinpgen *)((char *)xig + xig->xig_len);
          xig->xig_len > sizeof(struct xinpgen);
          xig = (struct xinpgen *)((char *)xig + xig->xig_len)) {
      if (istcp) {
          tp = &((struct xtcpcb *)xig)->xt_tp;
          inp = &((struct xtcpcb *)xig)->xt_inp;
          so = &((struct xtcpcb *)xig)->xt_socket;
      } else {
          inp = &((struct xinpcb *)xig)->xi_inp;
          so = &((struct xinpcb *)xig)->xi_socket;
      }

      /* Ignore sockets for protocols other than the desired one. */
      if (so->xso_protocol != (int)proto)
          continue;

      /* Ignore PCBs which were freed during copyout. */
      if (inp->inp_gencnt > oxig->xig_gen)
          continue;

      /* only do IPV4 for now */
      if ((inp->inp_vflag & INP_IPV4) == 0)
          continue;

      /* check SYN_SENT and get rid of NULL address */
      if ( (istcp && tp->t_state != TCPS_SYN_SENT)
              || ( inet_lnaof(inp->inp_laddr) == INADDR_ANY))
          continue;

      c.lcl = inp->inp_laddr.s_addr;
      c.lclp = inp->inp_lport;

      c.rmt = inp->inp_faddr.s_addr;
      c.rmtp = inp->inp_fport;
      c.proto=IPPROTO_TCP;

      if (tcptable_add (ct, &c) == 0){
          free(buf);
              return 0;
      }
  }
  free(buf);	

#endif
#endif
  return 1;
}







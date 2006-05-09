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
#include <jhash.h>
#ifdef FREEBSD

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/protosw.h>

#include <netinet/tcp_fsm.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp_var.h>
#endif

/**
 * \addtogroup libnuclient
 * @{
 */

/** \file tcptable.c
 * \brief TCP parsing function
 *
 *  Here are functions to get live connection table from the operating system.
 *  Main function is tcptable_read().
 */

#ifdef LINUX 
/**
 * Parse a Linux connection table (/proc/net/tcp or /proc/net/udp) and filter
 * connection: only keep session user connections in state "SYN packet sent".
 * Add connections to the our table using tcptable_add().
 */
int parse_tcptable_file(NuAuth* session, conntable_t *ct, char *filename, FILE **file, int protocol)
{
    char buf[1024];
    conn_t c;
    const char state_char = '2'; /* TCP_SYN_SENT written in hexadecimal */
    int state_pos;
    int uid_pos;
    char session_uid[20];
    int session_uid_len;
    int ret;
    char *pos;

    /* open file if it's not already opened */
    if (*file == NULL) {
        *file = fopen (filename, "r");
        if (*file == NULL) {
            printf ("Fail to open %s: %s", filename, strerror (errno));
            return 0;
        }
    }

    /* rewind to the beginning of the file */
    rewind (*file);

    /* read header */
    if (fgets (buf, sizeof (buf), *file) == NULL)
        panic ("/proc/net/tcp: missing header!");

    /* convert session user identifier to string */
    secure_snprintf(session_uid, sizeof(session_uid), "%5lu", session->localuserid);
    session_uid_len = strlen(session_uid);

    /* get state field position in header */
    pos = strstr(buf, " st ");
    if (pos == NULL)
        panic ("Can't find position of state field in /proc/net/tcp header!");
    state_pos = pos-buf+2;

    /* get user identifier position in header (it's just after 'retrnsmt' field) */
    pos = strstr(buf, " retrnsmt ");
    if (pos == NULL)
        panic ("Can't find position of user identifier field in /proc/net/tcp header!");
    uid_pos = pos - buf + strlen(" retrnsmt ");

    while (fgets (buf, sizeof (buf), *file) != NULL)
    {
#ifdef USE_FILTER
        int seen = 0;
#endif

        /* only keep connections in state "SYN packet sent" */
        if(buf[state_pos] != state_char){
            continue;
        }

        /* only keep session user connections */
        if (strncmp(buf+uid_pos, session_uid, session_uid_len) != 0) {
            continue;
        }

        /* get all fields */
        ret = sscanf (buf, 
                "%*d: %lx:%x %lx:%x %*x %*x:%*x %*x:%*x %x %lu %*d %lu",
                &c.lcl, &c.lclp, &c.rmt, &c.rmtp, &c.retransmit, &c.uid, &c.ino);
        if (ret != 7) {
            continue;
        }

        /* skip nul inodes */
        if (c.ino == 0) {
            continue;
        }

#if DEBUG
        /*  Check if there is a matching rule in the filters list */
        printf("Packet dst = %ld (%lx)\n", c.rmt, c.rmt);
#endif

#ifdef USE_FILTER
        /*  If we're sure auth_by_default is either 0 or 1, it can be simplified. */
        /*  (MiKael) TODO: Make sure!! :) */
        if (session->auth_by_default && seen)
            continue;
        if (!session->auth_by_default && !seen)
            continue;
#endif
        c.proto=protocol;
        c.lcl=ntohl(c.lcl);
        c.rmt=ntohl(c.rmt);
        tcptable_add (ct, &c);
    }
    return 1;
}
#endif

/**
 * On Linux: Parse connection table /proc/net/tcp and /proc/net/udp to get
 * connections in state "SYN sent" from session user.
 *
 * On FreeBSD: Use sysctl with "net.inet.tcp.pcblist" to get the connection 
 * table. Add connections to the our table using tcptable_add().
 */
int tcptable_read (NuAuth* session, conntable_t *ct)
{
#ifdef LINUX 
  static FILE *fp = NULL;
  static FILE *fq = NULL;
  int ok;
  
#if DEBUG
  assert (ct != NULL);
  assert (TCP_SYN_SENT == 2);
#endif
  if ( session->mode==SRV_TYPE_PUSH){
      /* need to set check_cond */
      pthread_mutex_lock(&(session->check_count_mutex));
      session->count_msg_cond=0;
      pthread_mutex_unlock(&(session->check_count_mutex));
  }

  if (!parse_tcptable_file(session, ct, "/proc/net/tcp", &fp, IPPROTO_TCP))
      return 0;
  if (!parse_tcptable_file(session, ct, "/proc/net/udp", &fq, IPPROTO_UDP))
      return 0;          
  return 1;
#elif defined(FREEBSD)
  conn_t c;
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
  /* get connection table size, and then allocate a buffer */
  len = 0;
  if (sysctlbyname(mibvar, 0, &len, 0, 0) < 0) {
      if (errno != ENOENT)
          printf("sysctl: %s", mibvar);
      return 0;
  }
  buf = malloc(len);
  if (buf == NULL) 
  {
      printf("malloc %lu bytes", (u_long)len);
      return 0;
  }

  if ( session->mode==SRV_TYPE_PUSH){
      /* need to set check_cond */
      pthread_mutex_lock(&(session->check_count_mutex));
      session->count_msg_cond=0;
      pthread_mutex_unlock(&(session->check_count_mutex));
  }
  
  /* read connection table */
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

      tcptable_add (ct, &c);
  }
  free(buf);	
  return 1;
#endif
}

/**
 * tcptable_init ()
 *
 * Initialise a connection table (hashtable).
 */
int tcptable_init (conntable_t **ct)
{
	int i;

	(* ct) = (conntable_t *) calloc(1,sizeof(conntable_t));
	assert (*ct != NULL);

	for (i = 0; i < CONNTABLE_BUCKETS; i++)
		(*ct)->buckets[i] = NULL;

	return 1;
}

/*
 * tcptable_hash ()
 *
 * Simple hash function for connections.
 */
inline int tcptable_hash (conn_t *c)
{
	return (jhash_3words(c->lcl,
				c->rmt,
				(c->rmtp | c->lclp << 16),
				32)) % CONNTABLE_BUCKETS;
}

/*
 * tcptable_add ()
 *
 * Add a connection to the connection table.
 */
void tcptable_add (conntable_t *ct, conn_t *c)
{
	conn_t *old, *newc;
	int bi;
#if DEBUG
	assert (ct != NULL);
	assert (c != NULL);
#endif

	newc = (conn_t *) calloc (1,sizeof (conn_t));
	if (!newc) {
		panic ("memory exhausted");
	}

	c->createtime=time(NULL);
	memcpy (newc, c, sizeof (conn_t));
	bi = tcptable_hash (c);
	old = ct->buckets[bi];
	ct->buckets[bi] = newc;
	ct->buckets[bi]->next = old;
}

/*
 * tcptable_find ()
 *
 * Find a connection in a table, return connection if found, NULL otherwise.
 */
conn_t* tcptable_find (conntable_t *ct, conn_t *c)
{
	conn_t *bucket;
#if DEBUG
	assert (ct != NULL);
	assert (c != NULL);
#endif
	bucket = ct->buckets[tcptable_hash (c)];
	while (bucket != NULL) {
		if ( (c->proto == bucket->proto) &&
				(c->rmt == bucket->rmt) && (c->rmtp == bucket->rmtp) &&
				(c->lcl == bucket->lcl) && (c->lclp == bucket->lclp)
		   ) {
			return bucket;
		}
		bucket = bucket->next;
	}

	return NULL;
}

/*
 * tcptable_free ()
 *
 * Free a connection table.
 */
void tcptable_free (conntable_t *ct)
{
	int i;

        if (ct == NULL)
            return;

	for (i = 0; i < CONNTABLE_BUCKETS; i++) {
		conn_t *c0, *c1;

		c0 = ct->buckets[i];
		while (c0 != NULL) {
			c1 = c0->next;
			free (c0);
			c0 = c1;
		}
		ct->buckets[i] = NULL;
	}

	/* free structure */
	free(ct);
}

/** @} */

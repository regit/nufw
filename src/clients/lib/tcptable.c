/*
 ** Copyright 2005-2007 - INL
 ** Written by Eric Leblond <regit@inl.fr>
 **            Vincent Deffontaines <vincent@inl.fr>
 ** INL http://www.inl.fr
 **
 ** $Id$
 **
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, version 3 of the License.
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
#include "libnuclient.h"
#include "proto.h"
#include "tcptable.h"
#include <inttypes.h>
#define USE_JHASH3
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

#include <nubase.h>

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
int parse_tcptable_file(nuauth_session_t * session, conntable_t * ct, char *filename,
			FILE ** file, int protocol, int use_ipv6)
{
	char buf[1024];
	conn_t c;
	const char state_char = '2';	/* TCP_SYN_SENT written in hexadecimal */
	int state_pos;
	int uid_pos;
	char session_uid[20];
	int session_uid_len;
	int ret;
	char *pos;

	/* open file if it's not already opened */
	if (*file == NULL) {
		*file = fopen(filename, "r");
		if (*file == NULL) {
			printf("Fail to open %s: %s", filename,
			       strerror(errno));
			return 0;
		}
	}

	/* rewind to the beginning of the file */
	rewind(*file);

	/* read header */
	if (fgets(buf, sizeof(buf), *file) == NULL)
		panic("%s: missing header!", filename);

	/* convert session user identifier to string */
	secure_snprintf(session_uid, sizeof(session_uid), "%5lu",
			(long)session->userid);
	session_uid_len = strlen(session_uid);

	/* get state field position in header */
	pos = strstr(buf, " st ");
	if (pos == NULL)
		panic
		    ("Can't find position of state field in /proc/net/tcp header!");
	state_pos = pos - buf + 2;

	/* get user identifier position in header (it's just after 'retrnsmt' field) */
	pos = strstr(buf, " retrnsmt ");
	if (pos == NULL)
		panic
		    ("Can't find position of user identifier field in /proc/net/tcp header!");
	uid_pos = pos - buf + strlen(" retrnsmt ");

	while (fgets(buf, sizeof(buf), *file) != NULL) {

		/* only keep connections in state "SYN packet sent" */
		if (buf[state_pos] != state_char) {
			continue;
		}

		/* only keep session user connections */
		if (strncmp(buf + uid_pos, session_uid, session_uid_len) !=
		    0) {
			continue;
		}

		/* get all fields */
		if (!use_ipv6) {
			uint32_t src, dst;
			ret = sscanf(buf,
				     "%*d: "
				     "%" SCNx32 ":%hx "
				     "%" SCNx32 ":%hx "
				     "%*x %*x:%*x %*x:%*x %x "
				     "%lu %*d %lu",
				     &src, &c.port_src,
				     &dst, &c.port_dst,
				     &c.retransmit, &c.uid,
				     &c.inode);
			if (ret != 7) {
				continue;
			}
			uint32_to_ipv6(src, &c.ip_src);
			uint32_to_ipv6(dst, &c.ip_dst);
		} else {
			char ip_src[33];
			char ip_dst[33];
			ret = sscanf(buf,
				     "%*d: "
				     "%32s"
				     ":%hx "
				     "%32s"
				     ":%hx "
				     "%*x %*x:%*x %*x:%*x %x "
				     "%lu %*d %lu",
				     ip_src,
				     &c.port_src,
				     ip_dst,
				     &c.port_dst,
				     &c.retransmit, &c.uid, &c.inode);
			if (ret != 7) {
				continue;
			}
			if (!hex2ipv6(ip_src, &c.ip_src))
				continue;
			if (!hex2ipv6(ip_dst, &c.ip_dst))
				continue;
		}

		/* skip nul inodes */
		if (c.inode == 0) {
			continue;
		}
#if DEBUG
		/*  Check if there is a matching rule in the filters list */
		printf("Packet dst = %ld (%lx)\n", c.rmt, c.rmt);
#endif

		c.protocol = protocol;
		tcptable_add(ct, &c);
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
int tcptable_read(nuauth_session_t * session, conntable_t * ct)
{
#ifdef LINUX
	static FILE *fd_tcp = NULL;
	static FILE *fd_tcp6 = NULL;
	static FILE *fd_udp = NULL;

#if DEBUG
	assert(ct != NULL);
	assert(TCP_SYN_SENT == 2);
#endif

	if (!parse_tcptable_file
	    (session, ct, "/proc/net/tcp", &fd_tcp, IPPROTO_TCP, 0))
		return 0;

	parse_tcptable_file(session, ct, "/proc/net/tcp6", &fd_tcp6,
			    IPPROTO_TCP, 1);

	if (!parse_tcptable_file
	    (session, ct, "/proc/net/udp", &fd_udp, IPPROTO_UDP, 0))
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
	if (buf == NULL) {
		printf("malloc %lu bytes", (u_long) len);
		return 0;
	}

	/* read connection table */
	if (sysctlbyname(mibvar, buf, &len, 0, 0) < 0) {
		printf("sysctl: %s", mibvar);
		free(buf);
		return 0;
	}

	oxig = xig = (struct xinpgen *) buf;
	for (xig = (struct xinpgen *) ((char *) xig + xig->xig_len);
	     xig->xig_len > sizeof(struct xinpgen);
	     xig = (struct xinpgen *) ((char *) xig + xig->xig_len)) {
		if (istcp) {
			tp = &((struct xtcpcb *) xig)->xt_tp;
			inp = &((struct xtcpcb *) xig)->xt_inp;
			so = &((struct xtcpcb *) xig)->xt_socket;
		} else {
			inp = &((struct xinpcb *) xig)->xi_inp;
			so = &((struct xinpcb *) xig)->xi_socket;
		}

		/* Ignore sockets for protocols other than the desired one. */
		if (so->xso_protocol != (int) proto)
			continue;

		/* Ignore PCBs which were freed during copyout. */
		if (inp->inp_gencnt > oxig->xig_gen)
			continue;

		/* only do IPV4 for now */
		if ((inp->inp_vflag & INP_IPV4) == 0)
			continue;

		/* check SYN_SENT and get rid of NULL address */
		if ((istcp && tp->t_state != TCPS_SYN_SENT)
		    || (inet_lnaof(inp->inp_laddr) == INADDR_ANY))
			continue;

		uint32_to_ipv6(inp->inp_laddr.s_addr, &c.ip_src);
		c.port_src = ntohs(inp->inp_lport);

		uint32_to_ipv6(inp->inp_faddr.s_addr, &c.ip_dst);
		c.port_dst = ntohs(inp->inp_fport);
		c.protocol = IPPROTO_TCP;

		tcptable_add(ct, &c);
	}
	free(buf);
	return 1;
#endif
}

/**
 * Create a connection table: allocate memory with zero bytes,
 * and init. each list with NULL pointer.
 *
 * \return Returns 0 on error (no more memory), 1 otherwise.
 */
int tcptable_init(conntable_t ** ct)
{
	int i;

	(*ct) = (conntable_t *) calloc(1, sizeof(conntable_t));
	if (*ct == NULL) {
		return 0;
	}

	for (i = 0; i < CONNTABLE_BUCKETS; i++) {
		(*ct)->buckets[i] = NULL;
	}
	return 1;
}

/**
 * Compute connection hash (index in a connection table, see ::conntable_t).
 * Hash is an integer in interval 0..(::CONNTABLE_BUCKETS-1).
 */
int tcptable_hash(conn_t * c)
{
	/** \todo Hash the whole ip address! */
#ifndef FREEBSD
	return (jhash_3words(c->ip_src.s6_addr32[3],
			     c->ip_dst.s6_addr32[3],
			     (c->port_dst | c->port_src << 16),
			     32)) % CONNTABLE_BUCKETS;
#else
	return (jhash_3words(c->ip_src.__u6_addr.__u6_addr32[3],
			     c->ip_dst.__u6_addr.__u6_addr32[3],
			     (c->port_dst | c->port_src << 16),
			     32)) % CONNTABLE_BUCKETS;
#endif
}

/**
 * Add a connection entry to a connection table.
 */
void tcptable_add(conntable_t * ct, conn_t * c)
{
	conn_t *old, *newc;
	int bi;
#if DEBUG
	assert(ct != NULL);
	assert(c != NULL);
#endif

	newc = (conn_t *) calloc(1, sizeof(conn_t));
	if (!newc) {
		panic("memory exhausted");
	}

	c->createtime = time(NULL);
	memcpy(newc, c, sizeof(conn_t));
	bi = tcptable_hash(c);
	old = ct->buckets[bi];
	ct->buckets[bi] = newc;
	ct->buckets[bi]->next = old;
}

/**
 * Find a connection in a table.
 *
 * \return The connection if found, NULL if it doesn't exist
 */
conn_t *tcptable_find(conntable_t * ct, conn_t * c)
{
	conn_t *bucket;
#if DEBUG
	assert(ct != NULL);
	assert(c != NULL);
#endif
	bucket = ct->buckets[tcptable_hash(c)];
	while (bucket != NULL) {
		if ((c->protocol == bucket->protocol)
		    && ipv6_equal(&c->ip_dst, &bucket->ip_dst)
		    && (c->port_dst == bucket->port_dst)
		    && ipv6_equal(&c->ip_src, &bucket->ip_src)
		    && (c->port_src == bucket->port_src)
		    ) {
			return bucket;
		}
		bucket = bucket->next;
	}

	return NULL;
}

/**
 * Destroy a connection table (free memory).
 */
void tcptable_free(conntable_t * ct)
{
	int i;

	if (ct == NULL)
		return;

	for (i = 0; i < CONNTABLE_BUCKETS; i++) {
		conn_t *c0, *c1;

		c0 = ct->buckets[i];
		while (c0 != NULL) {
			c1 = c0->next;
			free(c0);
			c0 = c1;
		}
		ct->buckets[i] = NULL;
	}

	/* free structure */
	free(ct);
}

/** @} */

/*
 * nutcpc.c - TCP/IP connection auth client.
 *
 * This file is based of tcpspy, a TCP/IP connection monitor.
 *
 * Copyright (c) 2000, 2001, 2002 Tim J. Robbins. 
 * All rights reserved.
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
 * $Id: nutcpc.c,v 1.1 2003/08/25 21:41:46 regit Exp $
 */

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Defaults for compile-time settings. Descriptions of these are in
 * the Makefile.
 */
#ifndef CONNTABLE_BUCKETS
#define CONNTABLE_BUCKETS 5003
#endif

static int stopped = 0, showprocs = 0;

int sck_user_request;
struct sockaddr_in adr_srv;

/*
 * This structure holds everything we need to know about a connection. We
 * use unsigned long instead of (for example) uid_t, ino_t to make hashing
 * easier.
 */
typedef struct conn {
	unsigned long lcl;
	unsigned int lclp;
	unsigned long rmt;
	unsigned int rmtp;
	unsigned long uid;
	unsigned long ino;

	char exe[PATH_MAX];
	
	struct conn *next;
} conn_t;

typedef struct conntable {
	conn_t *buckets[CONNTABLE_BUCKETS];
} conntable_t;

static int ct_init (conntable_t *ct);
static int ct_hash (conn_t *c);
static int ct_add (conntable_t *ct, conn_t *c);
static int ct_find (conntable_t *ct, conn_t *c);
static int ct_read (conntable_t *ct);
static int ct_free (conntable_t *ct);
static void huntinode (ino_t i, char *buf, size_t bufsize);
static void compare (conntable_t *old, conntable_t *new);


void panic(const char *fmt, ...){
  printf("error\n");
  exit(-1);
}

/*
 * ct_init ()
 *
 * Initialise a connection table (hashtable).
 */
static int ct_init (conntable_t *ct)
{
	int i;
	
	assert (ct != NULL);

	for (i = 0; i < CONNTABLE_BUCKETS; i++)
		ct->buckets[i] = NULL;

	return 1;
}

/*
 * ct_hash ()
 *
 * Simple hash function for connections.
 */
static int ct_hash (conn_t *c)
{
	unsigned long h;

	assert (c != NULL);

	h = c->lcl ^ c->lclp ^ c->rmt ^ c->rmtp ^ c->uid ^ c->ino;

	return h % CONNTABLE_BUCKETS;
}

/*
 * ct_add ()
 *
 * Add a connection to the connection table.
 */
static int ct_add (conntable_t *ct, conn_t *c)
{
	conn_t *old, *newc;
	int bi;
	
	assert (ct != NULL);
	assert (c != NULL);

	newc = (conn_t *) malloc (sizeof (conn_t));
	if (newc == NULL) {
	  panic ("memory exhausted");	
	}

	memcpy (newc, c, sizeof (conn_t));

	bi = ct_hash (c);
	old = ct->buckets[bi];
	ct->buckets[bi] = newc;
	ct->buckets[bi]->next = old;

	return 1;
}

/*
 * ct_find ()
 * 
 * Find a connection in a table, return nonzero if found, zero otherwise.
 */
static int ct_find (conntable_t *ct, conn_t *c)
{
	conn_t *bucket;
	
	assert (ct != NULL);
	assert (c != NULL);

	bucket = ct->buckets[ct_hash (c)];
	while (bucket != NULL) {
		if ((c->lcl == bucket->lcl) && (c->lclp == bucket->lclp) && 
			(c->rmt == bucket->rmt) && (c->rmtp == bucket->rmtp) &&
			(c->uid == bucket->uid) && (c->ino == bucket->ino)) {
			return 1;
		}
		bucket = bucket->next;
	}

	return 0;
}

/*
 * ct_read ()
 * 
 * Read /proc/net/tcp and add all connections to the table if connections
 * of that type are being watched.
 */
static int ct_read (conntable_t *ct)
{
	static FILE *fp = NULL;
	char buf[1024];
	conn_t c;
	
	assert (ct != NULL);

	if (fp == NULL) {
		fp = fopen ("/proc/net/tcp", "r");
		if (fp == NULL) panic ("/proc/net/tcp: %s", strerror (errno));
	}
	rewind (fp);

	if (fgets (buf, sizeof (buf), fp) == NULL)
		panic ("/proc/net/tcp: missing header");
	
	while (fgets (buf, sizeof (buf), fp) != NULL) {
		unsigned long st;

		if (sscanf (buf, "%*d: %lx:%x %lx:%x %lx %*x:%*x %*x:%*x %*x %lu %*d %lu", &c.lcl, &c.lclp, &c.rmt, &c.rmtp, &st, &c.uid, &c.ino) != 7) {
			continue;
		}
		if ((c.ino == 0) || (st != TCP_SYN_SENT)) continue;
		if (showprocs != 0)
			huntinode ((ino_t) c.ino, c.exe, sizeof (c.exe));

		if (ct_add (ct, &c) == 0)
			return 0;
	}

	return 1;
}

/*
 * ct_free ()
 *
 * Free a connection table.
 */
static int ct_free (conntable_t *ct)
{
	int i;

	assert (ct != NULL);

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

	return 1;
}

/*
 * huntinode ()
 *
 * Find names processes using an inode and put them in a buffer.
 */
static void huntinode (ino_t i, char *buf, size_t bufsize)
{
	DIR *procdir;
	struct dirent *procent;
	
	assert (buf != NULL);
	*buf = '\0';

	if ((procdir = opendir ("/proc")) == NULL)
		panic ("/proc: %s", strerror (errno));
	while ((procent = readdir (procdir)) != NULL) {
		char fdbuf[PATH_MAX];
		DIR *fddir;
		struct dirent *fdent;

		/*
		 * No test needed for "." and ".." since they don't begin
		 * with digits.
		 */
		if (! isdigit (*procent->d_name))
			continue;
		
		snprintf (fdbuf, sizeof (fdbuf), "/proc/%s/fd", 
				procent->d_name);
		
		/*
		 * We're don't always run as root, we may get EPERM here,
		 * ignore it.
		 */
		if ((fddir = opendir (fdbuf)) == NULL)
			continue;

		while ((fdent = readdir (fddir)) != NULL) {
			int len;
			char lnkbuf[PATH_MAX], lnktgt[PATH_MAX];
			char exebuf[PATH_MAX], exetgt[PATH_MAX];
			ino_t this_ino;
			
			if (! isdigit (*fdent->d_name))
				continue;
			snprintf (lnkbuf, sizeof (lnkbuf), "%s/%s", fdbuf, 
					fdent->d_name);
			len = readlink (lnkbuf, lnktgt, sizeof (lnktgt) - 1);
			if (len < 0)
				continue;
			lnktgt[len] = '\0';
			if (sscanf (lnktgt, "socket:[%lu]", &this_ino) != 1)
				continue;
			if (this_ino != i)
				continue;

			snprintf (exebuf, sizeof (exebuf), "/proc/%s/exe", 
					procent->d_name);
			len = readlink (exebuf, exetgt, sizeof (exetgt) - 1);
			if (len < 0)
				continue;
			exetgt[len] = '\0';

			strncpy (buf, exetgt, bufsize);
			buf[bufsize - 1] = '\0';
		}

		closedir (fddir);
	}
	closedir (procdir);
}

int debug=1;
/*
 * send_user_pckt
*/
int send_user_pckt(conn_t* c){
  char t_int8=0;
  u_int16_t t_int16=0;
  u_int32_t t_int32=0;
  u_int8_t proto_version=0x1,answer_type=0x3;
  char datas[512];
  char *pointer;

  memset(datas,0,sizeof datas);
  memcpy(datas,&proto_version,sizeof proto_version);
  pointer=datas+sizeof proto_version;
  memcpy(pointer,&answer_type,sizeof answer_type);
  pointer+=sizeof answer_type;
  /*  id user authsrv */
  t_int16=c->uid;
  memcpy(pointer,&t_int16,sizeof(u_int16_t));
  pointer+=sizeof(u_int16_t);
  /* saddr */
  t_int32=htonl(c->lcl);
  memcpy(pointer,&t_int32,sizeof(u_int32_t));
  pointer+=sizeof (u_int32_t) ;
  /* daddr */
  t_int32=htonl(c->rmt);
  memcpy(pointer,&t_int32,sizeof(u_int32_t));
  pointer+=sizeof(u_int32_t);
  /* protocol */
  t_int8=0x6;
  memcpy(pointer,&t_int8,sizeof t_int8);
  pointer+=sizeof t_int8;
  pointer+=3;
  /* sport */
  t_int16=c->lclp;
  memcpy(pointer,&t_int16,sizeof t_int16);
  pointer+=sizeof t_int16;
  /* dport */
  t_int16=c->rmtp;
  memcpy(pointer,&t_int16,sizeof t_int16);
  pointer+=sizeof t_int16;
  if (debug) {
    printf("Sending user request\n");
    fflush(stdout);
  }
  if (sendto(sck_user_request,
	     datas,
	     pointer-datas,
	     0,
	     (struct sockaddr *)&adr_srv,
	     sizeof adr_srv) < 0)
    printf ("failure when sending\n");
  if (debug){
    printf("done\n");
  }
  return 1;
}


/*
 * compare ()
 *
 * Compare the `old' and `new' tables, logging any differences.
 */
static void compare (conntable_t *old, conntable_t *new)
{
	int i;
	
	assert (old != NULL);
	assert (new != NULL);
	
	for (i = 0; i < CONNTABLE_BUCKETS; i++) {
		conn_t *bucket;

		bucket = new->buckets[i];
		while (bucket != NULL) {
			if (ct_find (old, bucket) == 0)
				send_user_pckt (bucket);
			bucket = bucket->next;
		}
	}
}

static void usage (void)
{
	fprintf (stderr, "usage: nutcpc [-dp]  [-I interval] "
			"[-U user]  [-F facility]\n");
	exit (EXIT_FAILURE);
}

int firstrule = 1;


int main (int argc, char *argv[])
{
	conntable_t old, new;
	unsigned long interval = 1000;
	int ch;
	uid_t dropuser = -1;
	gid_t dropgroup = -1, defgroup = -1;
	int debug = 0;
	

	/* create UDP stuff */
	 sck_user_request = socket (AF_INET,SOCK_DGRAM,0);
  
	 adr_srv.sin_family= AF_INET;
	 adr_srv.sin_port=htons(4130);
	 adr_srv.sin_addr.s_addr=inet_addr("192.168.1.1");
	
	/*
	 * Parse our arguments.
	 */
	opterr = 0;
	while ((ch = getopt (argc, argv, "de:I:U:u:w:i:f:F:")) != -1) {
		switch (ch) {
		case 'd':
		  debug = 1;
		  break;
		case 'I':
		  interval = atoi (optarg);
		  if (interval == 0) {
		    fprintf (stderr, "nutcpc: bad interval\n");
		    exit (EXIT_FAILURE);
		  }
		  break;
		case 'U':
				{
				struct passwd *pw;
				
				if (isdigit (*optarg)) {
					dropuser = atoi (optarg);
					pw = getpwuid (atoi (optarg));
				} else {
					if ((pw = getpwnam (optarg)) == NULL) {
						fprintf (stderr, "nutcpc: user `%s' unknown\n", optarg);
						exit (EXIT_FAILURE);
					}
					dropuser = pw->pw_uid;
				}
				
				/*
				 * Use the gid from the password file entry if
				 * possible, as a default.
				 */
				if (pw != NULL)
					defgroup = pw->pw_gid;
				else
					defgroup = (gid_t) -1;
				
				}
				break;
			case 'G':
				if (isdigit (*optarg))
					dropgroup = atoi (optarg);
				else {
					struct group *gr;

					if ((gr = getgrnam (optarg)) == NULL) {
						fprintf (stderr, "nutcpc: group `%s' unknown\n", optarg);
						exit (EXIT_FAILURE);
					}
					dropgroup = gr->gr_gid;
				}	
				break;
				case 'u': case 'w': case 'i':
				fprintf (stderr, "nutcpc: -%c option is obsolete\n", ch);
				/* fall through to usage message */
			default:
				usage();
		}
	}

	argc -= optind;
	argv += optind;

	/*
	 * Become an unprivileged user for safety purposes if requested.
	 */
	if ((dropgroup == (uid_t) -1) && (defgroup != (uid_t) -1))
		dropgroup = defgroup;
	if (dropgroup != (gid_t) -1) {
		if (setgid (dropgroup) < 0) {
			fprintf (stderr, "nutcpc: setgid: %s\n", strerror (errno));
			exit (EXIT_FAILURE);
		}
	}
	if (dropuser != (uid_t) -1) {
		if (setuid (dropuser) < 0) {
			fprintf (stderr, "nutcpc: setuid: %s\n", strerror (errno));
			exit (EXIT_FAILURE);
		}
	}

	/*
	 * Become a daemon by double-forking and detaching completely from
	 * the terminal.
	 */

	if (debug == 0) {
		pid_t p;

		/* 1st fork */
		p = fork();
		if (p < 0) {
			fprintf (stderr, "nutcpc: fork: %s\n",
					strerror (errno));
			exit (EXIT_FAILURE);
		} else if (p != 0)
			exit (0);

		/* 2nd fork */
		p = fork();
		if (p < 0) {
			fprintf (stderr, "nutcpc: fork: %s\n",
					strerror (errno));
			exit (EXIT_FAILURE);
		} else if (p != 0) {
			fprintf (stderr, "nutcpc 0.1 started (pid %d)\n", 
					(int) p);
			exit (EXIT_SUCCESS);
		}

		ioctl (STDIN_FILENO, TIOCNOTTY, NULL);
		close (STDIN_FILENO); 
		close (STDOUT_FILENO); 
		close (STDERR_FILENO);
		setpgid (0, 0);
		chdir ("/");
	} else
		fprintf (stderr, "nutcpc 0.1 started (debug)\n");

	/*
	 * Initialisation's done, start watching for connections.
	 */

	if (debug == 0)


	if (ct_init (&old) == 0) panic ("ct_init failed");
	if (ct_read (&old) == 0) panic ("ct_read failed");
	
	while (stopped == 0) {
		struct timeval tv1, tv2;
		static double elapsed = 0.0;
		static int slow_warn = 0;

		gettimeofday (&tv1, NULL);

		if (ct_init (&new) == 0) panic ("ct_init failed");
		if (ct_read (&new) == 0) panic ("ct_read failed");
		compare (&old, &new);
		if (ct_free (&old) == 0) panic ("ct_free failed");
		memcpy (&old, &new, sizeof (conntable_t));

		gettimeofday (&tv2, NULL);

		/*
		 * If the time taken to poll the currently open connections is longer than
		 * the time between checks, emit a warning message.
		 */
		elapsed += (double) ((tv2.tv_sec - tv1.tv_sec) * 1000000 + (tv2.tv_usec - tv1.tv_usec));
		elapsed /= 2;
		if ((elapsed > (double)(interval * 1000)) && (slow_warn == 0)) {
			slow_warn = 1;
		}

		usleep (interval * 100);
	}

	if (ct_free (&old) == 0) panic ("ct_free failed");
	closelog ();

	return EXIT_SUCCESS;
}

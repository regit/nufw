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
 * $Id: nutcpc.c,v 1.12 2004/03/18 01:16:17 regit Exp $
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
#define _GNU_SOURCE
#define __USE_GNU
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <termios.h>
#include <time.h>
#define _XOPEN_SOURCE
#include <unistd.h>
#include <crypt.h>
#include <sys/stat.h>
#include <fcntl.h>

/*
 * Defaults for compile-time settings. Descriptions of these are in
 * the Makefile.
 */
#ifndef CONNTABLE_BUCKETS
#define CONNTABLE_BUCKETS 5003
#endif
#define NUAUTH_IP "192.168.1.1"
static int stopped = 0;

int sck_user_request;
unsigned long userid;
uid_t localuserid;

struct sockaddr_in adr_srv;
char *password;
unsigned long packet_id;
struct termios orig;


int tcp_on;

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
static void compare (conntable_t *old, conntable_t *new);


void panic(const char *fmt, ...){
    printf("error\n");
    exit(-1);
}

void exit_clean(){
    printf ( "Exiting as requested\n");
  /* Restore terminal (can be superflu). */
  (void) tcsetattr (fileno (stdin), TCSAFLUSH, &orig);
    exit(0);
}

  ssize_t
my_getpass (char **lineptr, size_t *n)
{
  struct termios  new;
  int nread;

  /* Turn echoing off and fail if we can't. */
  if (tcgetattr (fileno (stdin), &orig) != 0)
      return -1;
  new = orig;
  new.c_lflag &= ~ECHO;
  if (tcsetattr (fileno (stdin), TCSAFLUSH, &new) != 0)
      return -1;

  /* Read the password. */
  nread = getline (lineptr, n, stdin);

  /* Restore terminal. */
  (void) tcsetattr (fileno (stdin), TCSAFLUSH, &orig);

  return nread;
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
      /* Check if it's the good user */
      if (c.uid != localuserid) {
          continue;
      }
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
 * send_user_pckt
 */
int send_user_pckt(conn_t* c){
    char t_int8=0;
    u_int16_t t_int16=0;
    u_int32_t t_int32=0;
    u_int8_t proto_version=0x1,answer_type=0x3;
    char datas[512];
    char md5datas[512];
    char *pointer;
    int debug=1;
    struct in_addr oneip;
    char onaip[16];
    char* md5sigs;
    u_int32_t  timestamp=time(NULL);
    unsigned long seed[2];
    char salt[] = "$1$........";
    const char *const seedchars = 
      "./0123456789ABCDEFGHIJKLMNOPQRST"
      "UVWXYZabcdefghijklmnopqrstuvwxyz";
    int i;




    memset(datas,0,sizeof datas);
    memcpy(datas,&proto_version,sizeof proto_version);
    pointer=datas+sizeof proto_version;
    memcpy(pointer,&answer_type,sizeof answer_type);
    pointer+=sizeof answer_type;
    /*  id user authsrv */
    t_int16=userid;
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
    memcpy(pointer,&timestamp,sizeof timestamp);
    pointer+=sizeof timestamp;
    memcpy(pointer,&packet_id,sizeof packet_id);
    pointer+=sizeof packet_id;

    /* construct the md5sum */
    /* first md5 datas */
    oneip.s_addr=(c->lcl);
    strncpy(onaip,inet_ntoa(oneip),16);
    oneip.s_addr=(c->rmt);
    snprintf(md5datas,512,
        "%s%u%s%u%lu%ld%s",
        onaip,
        c->lclp,
        inet_ntoa(oneip),
        c->rmtp,
        (unsigned long int) timestamp,
        packet_id,
        password);

    packet_id++;
    /* then the salt */
    /* Generate a (not very) random seed.  
       You should do it better than this... */
    seed[0] = time(NULL);
    seed[1] = getpid() ^ (seed[0] >> 14 & 0x30000);

    /* Turn it into printable characters from `seedchars'. */
    for (i = 0; i < 8; i++)
        salt[3+i] = seedchars[(seed[i/5] >> (i%5)*6) & 0x3f];

    /* next crypt */
    md5sigs=crypt(md5datas,salt);
    /* complete message */
    memcpy(pointer,md5sigs,35);
    pointer+=35;

    /* and send it */

    if (debug) {
        printf("Sending user request ");
        oneip.s_addr=(c->lcl);
        printf("%s:%u->",inet_ntoa(oneip),c->lclp);
        oneip.s_addr=(c->rmt);
        printf("%s:%u ...",inet_ntoa(oneip),c->rmtp);
        printf("%d %s ....",strlen(md5sigs),md5sigs);
        fflush(stdout);
    }

    if (tcp_on) {
	write(sck_user_request,datas,pointer-datas);
    if (debug){
        printf("%d sent\n",pointer-datas);
    }
    } else {
    if (sendto(sck_user_request,
          datas,
          pointer-datas,
          0,
          (struct sockaddr *)&adr_srv,
          sizeof adr_srv) < 0)
        printf (" failure when sending\n");
    }
    if (debug){
        printf(" done\n");
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
      "[-U userid ]  [-u local_id] [-H nuauth_srv]\n");
  exit (EXIT_FAILURE);
}

int firstrule = 1;


int main (int argc, char *argv[])
{
  conntable_t old, new;
  unsigned long interval = 100;
  int ch;
  char srv_addr[512]=NUAUTH_IP;
  int debug = 0;
  int random_file;
  char random_seed;
  char id_is_set=0;
  struct sigaction action;
  int password_size;

  tcp_on=0;
  /*
   * Parse our arguments.
   */
  opterr = 0;
  while ((ch = getopt (argc, argv, "du:H:I:U:T")) != -1) {
      switch (ch) {
        case 'H':
          strncpy(srv_addr,optarg,512);
          break;
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
          sscanf(optarg,"%lu",&userid);
          break;
        case 'u':
          sscanf(optarg,"%u",&localuserid);
          id_is_set=1;
          break;
	case 'T':
	  tcp_on=1;
	  break;
        default:
          usage();
      }
  }

  /* signal management */
  action.sa_handler = exit_clean;
  sigemptyset( & (action.sa_mask));
  action.sa_flags = 0;
  if ( sigaction( SIGINT, & action , NULL ) != 0) {
      printf("Error\n");
      exit(1);
  }
  if ( sigaction( SIGTERM, & action , NULL ) != 0) {
      printf("Error\n");
      exit(1);
  }
  /* initiate packet number */
  packet_id=0;
  /* read password */
  password=NULL;
  password=(char *)calloc(32,sizeof( char));
  printf("Enter passphrase : ");
  my_getpass(&password,&password_size);
  if (strlen(password)<password_size) {
        password[strlen(password)-1]=0;
  }
  /* init random */
  random_file =  open("/dev/random",O_RDONLY);
  if ( read(random_file,&random_seed, 1) == 1){
      srandom(random_seed);
  }

  adr_srv.sin_family= AF_INET;
  adr_srv.sin_port=htons(4130);
  adr_srv.sin_addr.s_addr=inet_addr(srv_addr);
  /* create socket stuff */
  if (tcp_on) {
  	sck_user_request = socket (AF_INET,SOCK_STREAM,0);
	/* connect */
	if (sck_user_request == -1)
		exit(-1);
	connect(sck_user_request,&adr_srv,(int)sizeof(adr_srv)); 
  } else {
  	sck_user_request = socket (AF_INET,SOCK_DGRAM,0);
  }


  /* TODO get user local id */
  if (! id_is_set)
      localuserid=getuid();

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

      usleep (interval * 1000);
  }

  if (ct_free (&old) == 0) panic ("ct_free failed");
  closelog ();

  return EXIT_SUCCESS;
}

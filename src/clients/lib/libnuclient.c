/*
 * libnuclient - TCP/IP connection auth client library.
 *
 * Copyright 2004 - INL
 * 	written by Eric Leblond <eric.leblond@inl.fr>
 *
 * Idea taken from tcpspy, a TCP/IP connection monitor.
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
 * $Id: libnuclient.c,v 1.18 2004/03/28 17:58:19 regit Exp $
 */
#include "nuclient.h"

static int ct_init (conntable_t **ct);
static int ct_hash (conn_t *c);
static int ct_add (conntable_t *ct, conn_t *c);
static int ct_find (conntable_t *ct, conn_t *c);
static int ct_read (NuAuth * session,conntable_t *ct);
static int ct_free (conntable_t *ct);
static int compare (NuAuth *session,conntable_t *old, conntable_t *new);



static void panic(const char *fmt, ...){
	printf("error\n");
	exit(-1);
}

static void nu_exit_clean(NuAuth * session){
	/* if we are in ssl mode, shutdown SSL */
	if (session->ssl)
		SSL_shutdown(session->ssl);
}


/*
 * ct_init ()
 *
 * Initialise a connection table (hashtable).
 */
static int ct_init (conntable_t **ct)
{
	int i;

	(* ct) = (conntable_t *) calloc(1,sizeof(conntable_t));
	assert (*ct != NULL);

	for (i = 0; i < CONNTABLE_BUCKETS; i++)
		(*ct)->buckets[i] = NULL;

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
static int ct_read (NuAuth* session,conntable_t *ct)
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
		if (c.uid != session->localuserid) {
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

	/* free structure */
	free(ct);

	return 1;
}


/*
 * send_user_pckt
 */
static int send_user_pckt(NuAuth * session,conn_t* c){
	char t_int8=0;
	u_int16_t t_int16=0;
	u_int32_t t_int32=0;
	u_int8_t proto_version=0x1,answer_type=0x3;
	char datas[512];
	char md5datas[512];
	char *pointer;
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
	if (session->protocol == 1){
		memset(datas,0,sizeof datas);
		memcpy(datas,&(session->protocol),sizeof session->protocol);
		pointer=datas+sizeof proto_version;
		memcpy(pointer,&answer_type,sizeof answer_type);
		pointer+=sizeof answer_type;
		/*  id user authsrv */
		t_int16=session->userid;
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
		memcpy(pointer,&(session->packet_id),sizeof (session->packet_id));
		pointer+=sizeof (session->packet_id);

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
				session->packet_id,
				session->password);

		session->packet_id++;
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
		if (session->ssl){
			if( ! SSL_write(session->ssl,datas,pointer-datas)){
				printf("write failed\n");
				exit(0);
			}
		} else {
			if (sendto(session->socket,
						datas,
						pointer-datas,
						0,
						(struct sockaddr *)(& session->adr_srv),
						sizeof (session->adr_srv)) < 0)
				printf (" failure when sending\n");
		}
	}
	return 1;
}


/*
 * compare ()
 *
 * Compare the `old' and `new' tables, logging any differences.
 */
static int compare (NuAuth * session,conntable_t *old, conntable_t *new)
{
	int i;

	assert (old != NULL);
	assert (new != NULL);

	for (i = 0; i < CONNTABLE_BUCKETS; i++) {
		conn_t *bucket;

		bucket = new->buckets[i];
		while (bucket != NULL) {
			if (ct_find (old, bucket) == 0)
				send_user_pckt (session,bucket);
			bucket = bucket->next;
		}
	}
	return 0;
}

NuAuth* nu_client_init(char *username,unsigned long userid,char * password, char * hostname, unsigned int port,char protocol,char ssl_on)
{
	int random_file;
	char random_seed;
	int s_server_session_id_context=1;
	BIO *sbio;
	SSL_CTX* ctx;
	NuAuth * session;

	session=(NuAuth*) calloc(1,sizeof(NuAuth));

	/* initiate session */
	session->ssl=NULL;
	session->protocol = protocol;
	switch (protocol){
		case 1:
			session->username=NULL;
			session->userid=userid;
			break;
		case 2:
			session->username=strdup(username);
			session->userid=0;
			break;
		default:
			return NULL;
	}

	if (! password)
		return NULL;
	session->password=strdup(password);
	/* initiate packet number */
	session->packet_id=0;

	/* init random */
	random_file =  open("/dev/random",O_RDONLY);
	if ( read(random_file,&random_seed, 1) == 1){
		srandom(random_seed);
	}

	(session->adr_srv).sin_family= AF_INET;
	(session->adr_srv).sin_port=htons(port);
	(session->adr_srv).sin_addr.s_addr=inet_addr(hostname);
	if ( 	(session->adr_srv).sin_addr.s_addr == INADDR_NONE) {
		return NULL;
	}
	/* create socket stuff */
	if (ssl_on){
		char keyfile[256]; 
		/* compute patch keyfile */
		snprintf(keyfile,255,"%s/.nufw/" KEYFILE,getenv("HOME"));
		/* test if key exists */
		if (access(keyfile,R_OK)){
			printf("Can not open keyfile : %s\n",keyfile);
			return NULL;
		}
		/* Build our SSL context*/
		ctx=initialize_ctx(keyfile,PASSWORD);

		SSL_CTX_set_session_id_context(ctx,
				(void*)&s_server_session_id_context,
				sizeof s_server_session_id_context); 

		session->socket = socket (AF_INET,SOCK_STREAM,0);
		/* connect */
		if (session->socket <= 0)
			return NULL;
		connect(session->socket,(struct sockaddr *)(&session->adr_srv),sizeof(session->adr_srv)); 


		/* Connect the SSL socket */
		session->ssl=SSL_new(ctx);
		sbio=BIO_new_socket(session->socket,BIO_NOCLOSE);
		SSL_set_bio(session->ssl,sbio,sbio);
		if(SSL_connect(session->ssl)<=0)
			berr_exit("SSL connect error");
	} else {
		session->socket = socket (AF_INET,SOCK_DGRAM,0);
	}


	/* TODO get user local id */
	session->localuserid=getuid();

	/*
	 * Initialisation's done, start watching for connections.
	 */

	/* alloc ct */
	if (ct_init (&(session->ct)) == 0) panic ("ct_init failed");
	if (ct_read (session,session->ct) == 0) panic ("ct_read failed");
	return session;
}

int	nu_client_check(NuAuth * session){
	conntable_t *new;
	int nb_packets=0;

	if (ct_init (&new) == 0) panic ("ct_init failed");
	if (ct_read (session,new) == 0) panic ("ct_read failed");
	nb_packets = compare (session,session->ct, new);
	if (ct_free (session->ct) == 0) panic ("ct_free failed");
	session->ct=new;

	return nb_packets;
}

void nu_client_free(NuAuth *session){
	if (ct_free (session->ct) == 0) panic ("ct_free failed");
	nu_exit_clean(session);
}

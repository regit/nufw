/*
 * libnuclient - TCP/IP connection auth client library.
 *
 * Copyright 2004,2005 - INL
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

#define USE_PROTOCOL_1 0

#include "nuclient.h"
#include <sasl/saslutil.h>
#include <proto.h>
#include <jhash.h>
#include "proc.h"

#define DH_BITS 1024
#define PACKET_SIZE 1482
#define REQUEST_CERT 0

//#include <stdlib.h>
#include <sys/utsname.h>


static int tcptable_init (conntable_t **ct);
static int tcptable_hash (conn_t *c);
static int tcptable_add (conntable_t *ct, conn_t *c);
static int tcptable_find (conntable_t *ct, conn_t *c);
static int tcptable_read (NuAuth * session,conntable_t *ct);
static int tcptable_free (conntable_t *ct);
static int compare (NuAuth *session,conntable_t *old, conntable_t *new);

static int nu_client_real_check(NuAuth * session);

/* TODO : be clever ;-) */
int track_size;
int track_place;
int conn_on;
int recv_started;

/* callbacks we support */
int nu_getrealm(void *context __attribute__((unused)), int id,
		const char **availrealms __attribute__((unused)),
		const char **result) 
{
	// NuAuth * session = (NuAuth*)context;

	if(id != SASL_CB_GETREALM) {
		printf("nu_getrealm not looking for realm");
		return EXIT_FAILURE;
	}
	if(!result) return SASL_BADPARAM;
	*result = "NuPik";
	return SASL_OK;
}


int nu_get_usersecret(sasl_conn_t *conn __attribute__((unused)),
		void *context __attribute__((unused)), int id,
		sasl_secret_t **psecret) 
{
	NuAuth* session=(NuAuth *)context;
	if ((session->password == NULL) && session->passwd_callback) {
		session->password=(session->passwd_callback)();
	}
	if(id != SASL_CB_PASS) {
		printf("getsecret not looking for pass");
		return EXIT_FAILURE;
	}
	if(!psecret) return SASL_BADPARAM;
	if (! session->password){
		*psecret = (char*)calloc(1,sizeof(sasl_secret_t) );
		(*psecret)->len = 0;
	} else {
		*psecret = (char*)calloc(sizeof(sasl_secret_t) + strlen(session->password),sizeof(char));
		(*psecret)->len = strlen(session->password);
	}
	strcpy((*psecret)->data, session->password);

	return SASL_OK;
}

static int nu_get_userdatas(void *context __attribute__((unused)),
		int id,
		const char **result,
		unsigned *len)
{
	NuAuth* session=(NuAuth *)context;
	/* paranoia check */
	if (! result)
		return SASL_BADPARAM;

	switch (id) {
		case SASL_CB_USER:
			if ((session->username == NULL) && session->username_callback) {
				printf("get username\n");
				session->username=session->username_callback();
			}

			if (session->protocol == 2)
				*result=session->username;
			else { 
				char number[12];
				snprintf(number,12,"%lu",session->userid);
				*result=strdup(number);
			}
			break;
		case SASL_CB_AUTHNAME:
			if ((session->username == NULL) && session->username_callback) {
				session->username=session->username_callback();
			}
			if (session->protocol == 2)
				*result=session->username;
			else { 
				char number[12];
				snprintf(number,12,"%lu",session->userid);
				*result=strdup(number);
			}

			break;
		default:
			return SASL_BADPARAM;
	}

	if (len) *len = strlen(*result);

	return SASL_OK;
}

static void panic(const char *fmt, ...)
{
	printf("error\n");
	exit(-1);
}

static void nu_exit_clean(NuAuth * session)
{
	conn_on=0;
	if (session){
		if (session->tls){
			gnutls_bye(*(session->tls),GNUTLS_SHUT_RDWR);
			gnutls_deinit(*(session->tls));
			free(session->tls);
		}
		if (session->socket>0){
			shutdown(session->socket,SHUT_RDWR);
			session->socket=0;
		}
		if (session->username){
			free(session->username);
		}
		if (session->password){
			free(session->password);
		}
		free(session);
	}
	gnutls_global_deinit();	
}

static void recv_message(NuAuth* session){
	int ret;
	char dgram[512];
	for (;;){
		if (conn_on && session){
			ret= gnutls_record_recv(*session->tls,dgram,sizeof dgram);
			if (ret<0){
				if ( gnutls_error_is_fatal(ret) ){
					nu_exit_clean(session);
					conn_on=0;
					return;
				}
			} else {
				if( *dgram==SRV_REQUIRED_PACKET ){
					/* TODO ? introduce a delay to not DOS our own client */
					/* we act */
					nu_client_real_check(session);
				} else {
					//	printf("unknown message\n");
				}
			}
		} else {
			return;
		}

	}
}

/*
 * tcptable_init ()
 *
 * Initialise a connection table (hashtable).
 */
static int tcptable_init (conntable_t **ct)
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
static inline int tcptable_hash (conn_t *c)
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
static int tcptable_add (conntable_t *ct, conn_t *c)
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

	memcpy (newc, c, sizeof (conn_t));

	bi = tcptable_hash (c);
	old = ct->buckets[bi];
	ct->buckets[bi] = newc;
	ct->buckets[bi]->next = old;

	return 1;
}

/*
 * tcptable_find ()
 * 
 * Find a connection in a table, return nonzero if found, zero otherwise.
 */
static int tcptable_find (conntable_t *ct, conn_t *c)
{
	conn_t *bucket;
#if DEBUG
	assert (ct != NULL);
	assert (c != NULL);
#endif
	bucket = ct->buckets[tcptable_hash (c)];
	while (bucket != NULL) {
		if (
				(c->rmt == bucket->rmt) && (c->rmtp == bucket->rmtp) &&
				(c->lcl == bucket->lcl) && (c->lclp == bucket->lclp) 
		   ) {
			return 1;
		}
		bucket = bucket->next;
	}

	return 0;
}

/*
 * tcptable_read ()
 * 
 * Read /proc/net/tcp and add all connections to the table if connections
 * of that type are being watched.
 */
static int tcptable_read (NuAuth* session, conntable_t *ct)
{
	static FILE *fp = NULL;
	char buf[1024];
	conn_t c;
#if DEBUG
	assert (ct != NULL);
#endif

	if (fp == NULL) {
		fp = fopen ("/proc/net/tcp", "r");
		if (fp == NULL) panic ("/proc/net/tcp: %s", strerror (errno));
	}
	rewind (fp);

	if (fgets (buf, sizeof (buf), fp) == NULL)
		panic ("/proc/net/tcp: missing header");

	while (fgets (buf, sizeof (buf), fp) != NULL) {
		unsigned long st;
		int seen = 0;
		if (sscanf (buf, "%*d: %lx:%x %lx:%x %lx %*x:%*x %*x:%*x %*x %lu %*d %lu",
					&c.lcl, &c.lclp, &c.rmt, &c.rmtp, &st, &c.uid, &c.ino) != 7)
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
		if ((c.ino == 0) || (st != TCP_SYN_SENT))
			continue;
		/* Check if it's the good user */
		if (c.uid != session->localuserid)
			continue;
		// If we're sure auth_by_default is either 0 or 1, it can be simplified.
		// (MiKael) TODO: Make sure!! :)
		if (session->auth_by_default && seen)
			continue;
		if (!session->auth_by_default && !seen)
			continue;
		if (tcptable_add (ct, &c) == 0)
			return 0;
	}

	return 1;
}

/*
 * tcptable_free ()
 *
 * Free a connection table.
 */
static int tcptable_free (conntable_t *ct)
{
	int i;
#if DEBUG
	assert (ct != NULL);
#endif

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

int mysasl_negotiate(gnutls_session session, sasl_conn_t *conn)
{
	char buf[8192];
	const char *data;
	const char *chosenmech;
	//sasl_interatcptable_t *client_interact = NULL;
	int len;
	int r;
	char * mech;

	memset(buf,0,sizeof buf);
	/* get the capability list */
	len = gnutls_record_recv(session, buf, sizeof buf);
	if (len < 0)
		return EXIT_FAILURE;
#if MECH_CHOICE
	if (mech) {
		/* make sure that 'mech' appears in 'buf' */
		if (!strstr(buf, mech)) {
			printf("server doesn't offer mandatory mech '%s'\n", mech);
			return EXIT_FAILURE;
		}
	} else {
#endif
		mech = buf;
#if MECH_CHOICE
	}
#endif 

	r = sasl_client_start(conn, mech, NULL, &data, &len, &chosenmech);
	//r = sasl_client_start(conn, mech, &client_interact, &data, &len, &chosenmech);
	if (r != SASL_OK && r != SASL_CONTINUE) {
		printf("starting SASL negotiation");
		printf("\n%s\n", sasl_errdetail(conn));
		return EXIT_FAILURE;
	}


	/* we send up to 3 strings;
	   the mechanism chosen, the presence of initial response,
	   and optionally the initial response */
	gnutls_record_send(session, chosenmech, strlen(chosenmech));
	if(data) {
		gnutls_record_send(session, "Y", 1);
		gnutls_record_send(session, data, len);
	} else {
		gnutls_record_send(session, "N", 1);
	}

	r=SASL_CONTINUE;
	for (;;) {

		memset(buf,0,sizeof buf);
		len = gnutls_record_recv(session, buf, 1);
		if (len < 0){
			return EXIT_FAILURE;
		}
		switch (*buf) {
			case 'O':
				return SASL_OK;
			case 'N':
				return EXIT_FAILURE;
			case 'C': /* continue authentication */
				break;
			default:
				return EXIT_FAILURE;
		}
		memset(buf,0,sizeof buf);
		len = gnutls_record_recv(session, buf, sizeof buf);

		if (len < 0){
			return EXIT_FAILURE;
		}
		r = sasl_client_step(conn, buf, len, NULL, &data, &len);
		if (r != SASL_OK && r != SASL_CONTINUE) {
			if (r == SASL_INTERACT){
				return EXIT_FAILURE;
			}
			printf("error performing SASL negotiation");
			printf("\n%s\n", sasl_errdetail(conn));
			return EXIT_FAILURE;
		}

		if (data ) {
			if (!len) len++;
			gnutls_record_send(session, data, len);
		} else {
			gnutls_record_send(session, "", 1);
		}
	}
	return EXIT_FAILURE;
}


/*
 * send_user_pckt
 */
static int send_user_pckt(NuAuth * session,conn_t* c)
{
	char datas[PACKET_SIZE];
	/* TODO : look if we don't override datas */
	char *pointer=NULL;
	char *enc_appname=NULL;

	memset(datas,0,sizeof datas);
	switch (session->protocol){
		case 2:
			{
				struct nuv2_header header;
				struct nuv2_authreq authreq;
				struct nuv2_authfield_ipv4 authfield;
				struct nuv2_authfield_app appfield;
				int len=0;
				/* get application name from inode */
				const char * appname = prg_cache_get(c->ino); 
				header.proto=0x2;
				header.msg_type=USER_REQUEST;
				header.option=0;
				header.length=sizeof(struct nuv2_header)+sizeof(struct nuv2_authreq)+sizeof(struct nuv2_authfield_ipv4);
				authreq.packet_id=session->packet_id++;
				authreq.packet_length=sizeof(struct nuv2_authreq)+sizeof(struct nuv2_authfield_ipv4);
				authfield.type=IPV4_FIELD;
				authfield.option=0;
				authfield.length=sizeof(struct nuv2_authfield_ipv4);
				authfield.src=htonl(c->lcl);
				authfield.dst=htonl(c->rmt);
				authfield.proto=6;
				authfield.flags=0;
				authfield.FUSE=0;
				authfield.sport=c->lclp;
				authfield.dport=c->rmtp;
				/* application field  */
				appfield.type=APP_FIELD;
				if (1) { 
					appfield.option=APP_TYPE_NAME;
					enc_appname=calloc(128,sizeof(char));
					if ( sasl_encode64(appname,strlen(appname),
								enc_appname,128 ,&len) == SASL_BUFOVER ){
						/* realloc */
						enc_appname=realloc(enc_appname,len);
						/* encode */
						sasl_encode64(appname,strlen(appname),
								enc_appname, len ,&len);
					}
					appfield.length=4+len;
					appfield.datas=enc_appname;
					authreq.packet_length+=appfield.length;
				} else {
#if 0
					appfield.option=APP_TYPE_SHA1;
					enc_appname=calloc(128,sizeof(char));
					if ( sasl_encode64(appname,strlen(appname),
								enc_appname,128 ,&len) == SASL_BUFOVER ){
						/* realloc */
						enc_appname=realloc(enc_appname,len);
						/* encode */
						sasl_encode64(appname,strlen(appname),
								enc_appname, len ,&len);
					}
					appfield.length=4+len;
					appfield.datas=g_strconcat(enc_appname,";",sha1_sig);
#endif
				}
				/* glue piece together on data if packet is not too long */
				header.length+=appfield.length;
				if (header.length < PACKET_SIZE){
					pointer=datas;
					memcpy(pointer,&header,sizeof(struct nuv2_header));
					pointer+=sizeof(struct nuv2_header);
					memcpy(pointer,&authreq,sizeof(struct nuv2_authreq));
					pointer+=sizeof(struct nuv2_authreq);
					memcpy(pointer,&authfield,sizeof(struct nuv2_authfield_ipv4));
					pointer+=sizeof(struct nuv2_authfield_ipv4);
					memcpy(pointer,&appfield,4);
					pointer+=4;
					if (len < (PACKET_SIZE + datas - pointer)){
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
			break;
		default:
			return 1;
	}

	/* and send it */
	if(session->tls){
		if( gnutls_record_send(*(session->tls),datas,pointer-datas)<=0){
			printf("write failed\n");
			return 0;
		}
	} 
	if (enc_appname)
		free(enc_appname);
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
			if (tcptable_find (old, bucket) == 0)
				if (send_user_pckt (session,bucket) != 1){
					/* error sending */
					return -1;
				}
			bucket = bucket->next;
		}
	}
	return 0;
}

int nu_client_error(NuAuth * session)
{
	if (session)
		return session->error;
	else
		return ERROR_UNKNOWN ;
}

static gnutls_dh_params dh_params;

static int generate_dh_params(void) {

	/* Generate Diffie Hellman parameters - for use with DHE
	 * kx algorithms. These should be discarded and regenerated
	 * once a day, once a week or once a month. Depending on the
	 * security requirements.
	 */
	gnutls_dh_params_init( &dh_params);
	gnutls_dh_params_generate2( dh_params, DH_BITS);

	return 0;
}

NuAuth* nu_client_init(char *username, unsigned long userid, char *password,
		const char *hostname, unsigned int port, char protocol, char ssl_on)
{
	int random_file;
	char random_seed;
	gnutls_certificate_credentials xcred;
	conntable_t *new;
	int ret;
#if 0
	const int cert_type_priority[2] = { GNUTLS_CRT_X509,  0 };
#endif
	//const int cert_type_priority[3] = { GNUTLS_CRT_X509, GNUTLS_CRT_OPENPGP, 0 };
	struct hostent *host;
	NuAuth * session;

	session=(NuAuth*) calloc(1,sizeof(NuAuth));

	sasl_callback_t callbacks[] = {
		{ SASL_CB_GETREALM, &nu_getrealm, session }, 
		{ SASL_CB_USER, &nu_get_userdatas, session }, 
		{ SASL_CB_AUTHNAME, &nu_get_userdatas, session } , 
		{ SASL_CB_PASS, &nu_get_usersecret, session },
		{ SASL_CB_LIST_END, NULL, NULL }
	};

	/* initiate session */
	session->auth_by_default = 1;
	session->tls=NULL;
	session->protocol = protocol;
	switch (protocol){
		case 1:
			session->username=NULL;
			session->userid=userid;
			break;
		case 2:
			if (!username){
				nu_exit_clean(session);
				return NULL;
			}
			session->username=strdup(username);
			session->userid=0;
			ssl_on=1;
			break;
		default:
			nu_exit_clean(session);
			return NULL;
	}

	if (! password){
		nu_exit_clean(session);
		return NULL;
	}
	session->password=strdup(password);
	/* initiate packet number */
	session->packet_id=0;

	/* init random */
	random_file =  open("/dev/random",O_RDONLY);
	if ( read(random_file,&random_seed, 1) == 1){
		srandom(random_seed);
	}

	host = gethostbyname(hostname);
	if (host == NULL)
	{
		fprintf(stderr, "*** An error occured when resolving the provided hostname\n");

		nu_exit_clean(session);
		return NULL;
	}

	(session->adr_srv).sin_family= AF_INET;
	(session->adr_srv).sin_port=htons(port);
	(session->adr_srv).sin_addr=*(struct in_addr *)host->h_addr_list[0];
	if (	(session->adr_srv).sin_addr.s_addr == INADDR_NONE) {

		nu_exit_clean(session);
		return NULL;
	}
	/* create socket stuff */
	if (ssl_on){
		char keyfile[256]; 
		char certfile[256]; 
		sasl_conn_t *conn;
		/* compute patch keyfile */
		snprintf(keyfile,255,"%s/.nufw/key.pem",getenv("HOME"));
		snprintf(certfile,255,"%s/.nufw/cert.pem",getenv("HOME"));

		/* test if key exists */
		if (access(keyfile,R_OK)){
                    /* Added by gryzor after getting confused with weird
                     * messages, when no cert is present*/
                        printf("\nSorry, cannot read key file %s\n",keyfile);
			keyfile[0]=0;
		}
		/* test if key exists */
		if (access(certfile,R_OK)){
                    /* Added by gryzor after getting confused with weird
                     * messages, when no cert is present*/
                        printf("\nSorry, cannot read key file %s\n",keyfile);
			certfile[0]=0;
		}



		gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
		gnutls_global_init();
		session->tls=(gnutls_session *)calloc(1,sizeof(gnutls_session));
		/* X509 stuff */
		gnutls_certificate_allocate_credentials(&xcred);
		/* sets the trusted cas file
		*/
		gnutls_certificate_set_x509_trust_file(xcred, certfile, GNUTLS_X509_FMT_PEM);

		if ( certfile[0] && keyfile[0]){
		ret = gnutls_certificate_set_x509_key_file(xcred, certfile, keyfile, GNUTLS_X509_FMT_PEM);
		if (ret <0){
			printf("problem with X509 file : %s\n",gnutls_strerror(ret));
		}
		}

		generate_dh_params();
		gnutls_certificate_set_dh_params( xcred, dh_params);


		/* Initialize TLS session 
		*/
		session->tls=(gnutls_session*)calloc(1,sizeof(gnutls_session));
		gnutls_init(session->tls, GNUTLS_CLIENT);

		gnutls_set_default_priority(*(session->tls));
#if 0
		gnutls_certificate_type_set_priority(*(session->tls), cert_type_priority);
#endif
		/* put the x509 credentials to the current session */
		gnutls_credentials_set(*(session->tls), GNUTLS_CRD_CERTIFICATE, xcred);



		session->socket = socket (AF_INET,SOCK_STREAM,0);
		/* connect */
		if (session->socket <= 0){
			nu_exit_clean(session);
			errno=EADDRNOTAVAIL;	
			return NULL;
		}

		if ( connect(session->socket,(struct sockaddr *)(&session->adr_srv),sizeof(session->adr_srv)) == -1){
			nu_exit_clean(session);
			errno=ENOTCONN;
			return NULL;
		}

		gnutls_transport_set_ptr( *(session->tls), (gnutls_transport_ptr)session->socket);

		/* Perform the TLS handshake
		*/
		ret = gnutls_handshake( *(session->tls));
		if (ret < 0) {
			gnutls_perror(ret);
			nu_exit_clean(session);
			errno=ECONNRESET;
			return NULL;
		} 
		/* certificate verification */
		ret = gnutls_certificate_verify_peers(*(session->tls));
		if (ret <0){
			printf("Certificate verification failed : %s",gnutls_strerror(ret));
			return NULL;
		} else {
			printf("Server Certificat OK\n");
		}


		/* SASL time */

		/* initialize the sasl library */
		ret = sasl_client_init(callbacks);
		if (ret != SASL_OK) {
			nu_exit_clean(session);
			errno=EAGAIN;
			return NULL;
		}

		/* client new connection */
		//   ret = sasl_client_new(service, host, localaddr, remoteaddr, NULL, 0, &conn);
		ret = sasl_client_new("NuFW", "myserver", NULL, NULL, NULL, 0, &conn);
		if (ret != SASL_OK) {
			printf("Failed allocating connection state");
			nu_exit_clean(session);
			errno=EAGAIN;
			return NULL;
		}

		/* set external properties here
		   sasl_setprop(conn, SASL_SSF_EXTERNAL, &extprops); */
		/* set username taken from console */

		sasl_setprop(conn, SASL_AUTH_EXTERNAL,username);

		/* FIXME */
		{
			sasl_ssf_t extssf = 0;
			sasl_setprop(conn,SASL_SSF_EXTERNAL,&extssf);
		}


		/* set required security properties here
		   sasl_setprop(conn, SASL_SEC_PROPS, &secprops); */

		ret = mysasl_negotiate(*(session->tls), conn);
		sasl_done();
		if (ret != SASL_OK) {
			nu_exit_clean(session);
			errno=EACCES;
			return NULL;
		} else {
			/* announce our OS */
			struct utsname info;
			char *oses;
			int stringlen;
			int actuallen;
                        int osfield_length;
			char* enc_oses;
			char * pointer, *buf;
			struct nuv2_authfield osfield;
			/* get info */
			uname(&info);
			/* build packet */
			stringlen=strlen(info.sysname)+strlen(info.release)+strlen(info.version)+3;
			oses=alloca(stringlen);
			enc_oses=calloc(4*stringlen,sizeof( char));
			snprintf(oses,stringlen,"%s;%s;%s",info.sysname, info.release, info.version);
			if (sasl_encode64(oses,strlen(oses),enc_oses,4*stringlen,&actuallen) == SASL_BUFOVER){
				enc_oses=realloc(enc_oses,actuallen);
				sasl_encode64(oses,strlen(oses),enc_oses,actuallen,&actuallen);
			}
			osfield.type=OS_FIELD;
			osfield.option=OS_SRV;
                        osfield_length=4+actuallen;
			osfield.length=htons(osfield_length);
			buf=alloca(osfield_length);
			pointer = buf ;
			memcpy(buf,&osfield,sizeof osfield);
			pointer+=sizeof osfield;
			memcpy(pointer,enc_oses,actuallen);
			free(enc_oses);
			gnutls_record_send(*(session->tls),buf,osfield_length);

			/* wait for message of server about mode */
			if (gnutls_record_recv(*(session->tls),buf,osfield_length)<=0){
				/* TODO : houston we've got a problem */
			} else {
				if (*buf == SRV_TYPE) {
					session->mode=*(buf+1);
				} else {
					session->mode=SRV_TYPE_POLL;
				}	
			}

		}


	} else {
		session->socket = socket (AF_INET,SOCK_DGRAM,0);
	}

	session->localuserid=getuid();


	/*
	 * Initialisation's done, start watching for connections.
	 */
	/* alloc ct */
	if (tcptable_init (&new) == 0) panic ("tcptable_init failed");
	session->ct=new;
	/* set init variable */	
	conn_on =1;
	recv_started=0;
	return session;
}

static int nu_client_real_check(NuAuth * session)
{
	conntable_t *new;
	int nb_packets=0;
	if (tcptable_init (&new) == 0) panic ("tcptable_init failed");
	if (tcptable_read (session,new) == 0) panic ("tcptable_read failed");
	/* update cache for link between proc and socket inode */
	prg_cache_load();
	nb_packets = compare (session,session->ct, new);
	/* TODO : free link between proc and socket inode */
	prg_cache_clear();

	if (nb_packets < 0){
		/* error we ask client to exit */
		nu_exit_clean(session);
		return nb_packets;
	}
	if (tcptable_free (session->ct) == 0) panic ("tcptable_free failed");
	session->ct=new;

	return nb_packets;
}


int nu_client_check(NuAuth * session)
{
	//	conntable_t *new;
	int nb_packets=0;
	//char buf[512];

	if (conn_on == 0 ){
		errno=ECONNRESET;
		return -1;
	}

	/* TODO : use less ressource be clever */
	if (recv_started == 0){
		pthread_t recvthread;
		pthread_create(&recvthread,NULL ,recv_message,session );
		recv_started =1;
	}

	if (session->mode == SRV_TYPE_POLL) {
		return	nu_client_real_check(session);
	}	
	return nb_packets;
}

void nu_client_free(NuAuth *session)
{
	if (tcptable_free (session->ct) == 0) panic ("tcptable_free failed");
	nu_exit_clean(session);
}

NuAuth* nu_client_init2(
		const char *hostname, unsigned int port,
		char* keyfile, char* certfile,
		void* username_callback,void * passwd_callback, void* tlscred_callback
		)
{
	int random_file;
	char random_seed;
	gnutls_certificate_credentials xcred;
	conntable_t *new;
	int ret;
	const int cert_type_priority[3] = { GNUTLS_CRT_X509,  0 };
	struct hostent *host;
	/* create socket stuff */
	sasl_conn_t *conn;
	NuAuth * session;

	session=(NuAuth*) calloc(1,sizeof(NuAuth));
	session->username_callback=username_callback;
	session->passwd_callback=passwd_callback;
	session->tls_passwd_callback=tlscred_callback;

	sasl_callback_t callbacks[] = {
		{ SASL_CB_GETREALM, &nu_getrealm, session }, 
		{ SASL_CB_USER, &nu_get_userdatas, session }, 
		{ SASL_CB_AUTHNAME, &nu_get_userdatas, session } , 
		{ SASL_CB_PASS, &nu_get_usersecret, session },
		{ SASL_CB_LIST_END, NULL, NULL }
	};



	/* initiate session */
	session->auth_by_default = 1;
	session->tls=NULL;
	session->protocol = 2;
	/* initiate packet number */
	session->packet_id=0;

	/* init random */
	random_file =  open("/dev/random",O_RDONLY);
	if ( read(random_file,&random_seed, 1) == 1){
		srandom(random_seed);
	}

	host = gethostbyname(hostname);
	if (host == NULL)
	{
		fprintf(stderr, "*** An error occured when resolving the provided hostname\n");

		nu_exit_clean(session);
		return NULL;
	}

	(session->adr_srv).sin_family= AF_INET;
	(session->adr_srv).sin_port=htons(port);
	(session->adr_srv).sin_addr=*(struct in_addr *)host->h_addr_list[0];
	if (	(session->adr_srv).sin_addr.s_addr == INADDR_NONE) {

		nu_exit_clean(session);
		return NULL;
	}
	/* compute patch keyfile */
	if (! keyfile){
		keyfile=calloc(256,1);
		snprintf(keyfile,255,"%s/.nufw/key.pem",getenv("HOME"));
	}
	/* test if key exists */
	if (access(keyfile,R_OK)){
            keyfile=NULL;
#if REQUEST_CERT
		errno=EBADF;
		return NULL;
#endif
	}

	if (! certfile){
		certfile=calloc(256,1);
		snprintf(certfile,255,"%s/.nufw/cert.pem",getenv("HOME"));
	}
	/* test if cert exists */
	if (access(certfile,R_OK)){
                certfile=NULL;
#if REQUEST_CERT
		errno=EBADF;
		return NULL;
#endif
	}

	gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
	gnutls_global_init();
	session->tls=(gnutls_session *)calloc(1,sizeof(gnutls_session));
	/* X509 stuff */
	gnutls_certificate_allocate_credentials(&xcred);
	/* sets the trusted cas file
	*/
#if REQUEST_CERT
	gnutls_certificate_set_x509_trust_file(xcred, certfile, GNUTLS_X509_FMT_PEM);
#endif
        if (certfile && keyfile){
            ret = gnutls_certificate_set_x509_key_file(xcred, certfile, keyfile, GNUTLS_X509_FMT_PEM);
            if (ret <0){
                printf("problem with keyfile : %s\n",gnutls_strerror(ret));
            }
        }
	generate_dh_params();
	gnutls_certificate_set_dh_params( xcred, dh_params);


	/* Initialize TLS session 
	*/
	session->tls=(gnutls_session*)calloc(1,sizeof(gnutls_session));
	gnutls_init(session->tls, GNUTLS_CLIENT);

	gnutls_set_default_priority(*(session->tls));
	gnutls_certificate_type_set_priority(*(session->tls), cert_type_priority);
	/* put the x509 credentials to the current session */
	gnutls_credentials_set(*(session->tls), GNUTLS_CRD_CERTIFICATE, xcred);

	session->socket = socket (AF_INET,SOCK_STREAM,0);
	/* connect */
	if (session->socket <= 0){
		nu_exit_clean(session);
		errno=EADDRNOTAVAIL;	
		return NULL;
	}

	if ( connect(session->socket,(struct sockaddr *)(&session->adr_srv),sizeof(session->adr_srv)) == -1){
		nu_exit_clean(session);
		errno=ENOTCONN;
		return NULL;
	}

	gnutls_transport_set_ptr( *(session->tls), (gnutls_transport_ptr)session->socket);

	/* Perform the TLS handshake
	*/
	ret = gnutls_handshake( *(session->tls));
	if (ret < 0) {
		gnutls_perror(ret);
		nu_exit_clean(session);
		errno=ECONNRESET;
		return NULL;
	} 
	/* certificate verification */
	ret = gnutls_certificate_verify_peers(*(session->tls));
	if (ret <0){
		printf("Certificate verification failed : %s",gnutls_strerror(ret));
		return NULL;
	} else {
		printf("Server Certificat OK\n");
	}


	/* SASL time */

	/* initialize the sasl library */
	ret = sasl_client_init(callbacks);
	if (ret != SASL_OK) {
		nu_exit_clean(session);
		errno=EAGAIN;
		return NULL;
	}

	/* client new connection */
	//   ret = sasl_client_new(service, host, localaddr, remoteaddr, NULL, 0, &conn);
	ret = sasl_client_new("NuFW", "myserver", NULL, NULL, NULL, 0, &conn);
	if (ret != SASL_OK) {
		printf("Failed allocating connection state");
		nu_exit_clean(session);
		errno=EAGAIN;
		return NULL;
	}

	/* set external properties here
	   sasl_setprop(conn, SASL_SSF_EXTERNAL, &extprops); */
	/* set username taken from console */

	if (! session->username){
		if (session->username_callback){
			session->username=session->username_callback();	
		} else {
			printf("can't call username callback\n");
		}
	}
	sasl_setprop(conn, SASL_AUTH_EXTERNAL,session->username);

	{
		sasl_ssf_t extssf = 0;
		sasl_setprop(conn,SASL_SSF_EXTERNAL,&extssf);
	}


	/* set required security properties here
	   sasl_setprop(conn, SASL_SEC_PROPS, &secprops); */

	ret = mysasl_negotiate(*(session->tls), conn);
	sasl_done();
	if (ret != SASL_OK) {
		nu_exit_clean(session);
		errno=EACCES;
		return NULL;
	} else {
		/* announce our OS */
		struct utsname info;
		char *oses;
		int stringlen;
		int actuallen;
		char* enc_oses;
		char * pointer, *buf;
		struct nuv2_authfield osfield;
		/* get info */
		uname(&info);
		/* build packet */
		stringlen=strlen(info.sysname)+strlen(info.release)+strlen(info.version)+3;
		oses=alloca(stringlen);
		enc_oses=calloc(4*stringlen,sizeof(char));
		snprintf(oses,stringlen,"%s;%s;%s",info.sysname, info.release, info.version);
		if (sasl_encode64(oses,strlen(oses),enc_oses,4*stringlen,&actuallen) == SASL_BUFOVER){
			enc_oses=realloc(enc_oses,actuallen);
			sasl_encode64(oses,strlen(oses),enc_oses,actuallen,&actuallen);
		}
		osfield.type=OS_FIELD;
		osfield.option=OS_SRV;
		osfield.length=4+actuallen;
		buf=alloca(osfield.length);
		pointer = buf ;
		memcpy(buf,&osfield,sizeof osfield);
		pointer+=sizeof osfield;
		memcpy(pointer,enc_oses,actuallen);
		free(enc_oses);
		gnutls_record_send(*(session->tls),buf,osfield.length);

		/* wait for message of server about mode */
		if (gnutls_record_recv(*(session->tls),buf,osfield.length)<=0){
			nu_exit_clean(session);
			errno=EACCES;
			return NULL;
		} else {
			if (*buf == SRV_TYPE) {
				session->mode=*(buf+1);
			} else {
				session->mode=SRV_TYPE_POLL;
			}	
		}

	}

	session->localuserid=getuid();

	/*
	 * Initialisation's done, start watching for connections.
	 */
	/* alloc ct */
	if (tcptable_init (&new) == 0) panic ("tcptable_init failed");
	session->ct=new;
	/* set init variable */	
	conn_on =1;
	recv_started=0;
	return session;

}

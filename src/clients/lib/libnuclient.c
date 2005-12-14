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

/*! \file libnuclient.c
  \brief Main file for libnuclient

  It contains all the exported functions
  */



#include "nuclient.h"
#include <sasl/saslutil.h>
#include <proto.h>
#include <jhash.h>
#include "client.h"


char * locale_to_utf8(char* inbuf);


#define DH_BITS 1024
#define REQUEST_CERT 0

//#include <stdlib.h>
#include <sys/utsname.h>


static int tcptable_hash (conn_t *c);
static conn_t * tcptable_find (conntable_t *ct, conn_t *c);

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
#if USE_UTF8
		char *givenpass=session->passwd_callback();
		session->password=locale_to_utf8(givenpass);
		if (! session->password){
			free(givenpass);
			return EXIT_FAILURE;
		}
		free(givenpass);
#else
		session->password=(session->passwd_callback)();
#endif
	}
	if(id != SASL_CB_PASS) {
		printf("getsecret not looking for pass");
		return EXIT_FAILURE;
	}
	if(!psecret) return SASL_BADPARAM;
	if (! session->password){
		*psecret = (sasl_secret_t*)calloc(1,sizeof(sasl_secret_t) );
		(*psecret)->len = 0;
		(*psecret)->data[0] = 0;
	} else {
		*psecret = (sasl_secret_t*)calloc(sizeof(sasl_secret_t) + strlen(session->password)+1,sizeof(char));
		(*psecret)->len = strlen(session->password);
		strncpy((char*)(*psecret)->data, session->password, (*psecret)->len +1 );
	}

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
#if USE_UTF8
				char *givenuser=session->username_callback();
				session->username=locale_to_utf8(givenuser);
				free(givenuser);
				if (! session->username){
					return EXIT_FAILURE;
				}


#else
				session->password=(session->username_callback)();
#endif
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
#if USE_UTF8
				char *givenuser=session->username_callback();
				session->username=locale_to_utf8(givenuser);
				free(givenuser);
				if (! session->username){
					return EXIT_FAILURE;
				}
#else
				session->password=(session->username_callback)();
#endif

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

void panic(const char *fmt, ...)
{
	printf("error\n");
	exit(-1);
}

void nu_exit_clean(NuAuth * session)
{
	/* lock mutex to avoid multiple call */
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
		pthread_mutex_destroy(session->mutex);
		free(session);
		session=NULL;
	}
	sasl_done();
	gnutls_global_deinit();
}
/*
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
int tcptable_add (conntable_t *ct, conn_t *c)
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

	return 1;
}

/*
 * tcptable_find ()
 *
 * Find a connection in a table, return connection if found, NULL otherwise.
 */
static conn_t* tcptable_find (conntable_t *ct, conn_t *c)
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
int tcptable_free (conntable_t *ct)
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
	size_t len;
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

static int add_packet_to_send(NuAuth * session,conn_t** auth,int *count_p,conn_t *bucket )
{
	int count=*count_p;
	if (count < CONN_MAX-1){
		auth[count]=bucket;
		(*count_p)++;
	} else {
		int i;
		auth[count]=bucket;
		if (send_user_pckt (session,auth) != 1){
			/* error sending */
#if DEBUG
			printf("error when sending\n");
#endif

			return -1;
		}
		for(i=0;i<CONN_MAX;i++){
			auth[i]=NULL;
		}
		*count_p=0;
	}
	return 1;
}

/**
 * Compare connection tables and send packets 
 *
 * Compare the `old' and `new' tables, sending packet to nuauth 
 * if differences are found.
 *
 * Return -1 if error (then disconnect is needed) or the number of 
 * authenticated packets if it has succeed
 */
int compare (NuAuth * session,conntable_t *old, conntable_t *new)
{
	int i;
	int count=0;
	conn_t* auth[CONN_MAX];
	int nb_packets=0;

	assert (old != NULL);
	assert (new != NULL);

	for (i = 0; i < CONNTABLE_BUCKETS; i++) {
		conn_t *bucket;
		conn_t *same_bucket;

		bucket = new->buckets[i];
		while (bucket != NULL) {
			same_bucket = tcptable_find (old, bucket) ;
			if (same_bucket == NULL){
#if DEBUG
				printf("sending new\n");
#endif
				if (add_packet_to_send(session,auth,&count,bucket) ==-1){
					/* problem when sending we exit */	      
					return -1;
				}
				nb_packets++;
			} else {
				/* compare values of retransmit */
				if (bucket->retransmit > same_bucket->retransmit) {
#if DEBUG
					printf("sending retransmit\n");
#endif
					if (add_packet_to_send(session,auth,&count,bucket) == -1){
						/* problem when sending we exit */	      
						return -1;

					}
					nb_packets++;
				}

				/* solve timeout issue on UDP */
				if (bucket->proto == IPPROTO_UDP){
					/* send an auth packet if netfilter timeout may have been reached */
					if (same_bucket->createtime<time(NULL)-UDP_TIMEOUT){
#if DEBUG
						printf("working on timeout issue\n");
#endif
						if (add_packet_to_send(session,auth,&count,bucket)){
							return -1;
						}
						nb_packets++;
					} else {
						bucket->createtime=same_bucket->createtime;
					}
				}
			}
			bucket = bucket->next;
		}
	}
	if(count>0){
		if (count<CONN_MAX){
			auth[count]=NULL;
		}
		if (send_user_pckt (session,auth) != 1){
			/* error sending */
			return -1;
		}
	}
	return nb_packets;
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

void nu_client_free(NuAuth *session)
{
	pthread_mutex_lock(session->mutex);
	if (tcptable_free (session->ct) == 0) panic ("tcptable_free failed");
        /* kill all threads */
        ask_session_end(session);
        /* all threads are dead, we are the one who can access to it */
	pthread_mutex_unlock(session->mutex);
        /* destroy session */
	nu_exit_clean(session);
}

/**
 * Initialisation of nufw authentication session
 *
 */
NuAuth* nu_client_init2(
		const char *hostname, unsigned int port,
		char* keyfile, char* certfile,
		void* username_callback,void * passwd_callback, void* tlscred_callback
		)
{
	gnutls_certificate_credentials xcred;
	conntable_t *new;
	int ret;
	int option_value;
	const int cert_type_priority[3] = { GNUTLS_CRT_X509,  0 };
	struct hostent *host;
	/* create socket stuff */
	sasl_conn_t *conn;
	NuAuth * session;
	struct sigaction no_action;

	session=(NuAuth*) calloc(1,sizeof(NuAuth));
	session->username_callback=username_callback;
	session->passwd_callback=passwd_callback;
	session->tls_passwd_callback=tlscred_callback;
	session->mutex=calloc(1,sizeof(pthread_mutex_t));
	pthread_mutex_init(session->mutex,NULL);

	sasl_callback_t callbacks[] = {
		{ SASL_CB_GETREALM, &nu_getrealm, session },
		{ SASL_CB_USER, &nu_get_userdatas, session },
		{ SASL_CB_AUTHNAME, &nu_get_userdatas, session },
		{ SASL_CB_PASS, &nu_get_usersecret, session },
		{ SASL_CB_LIST_END, NULL, NULL }
	};



	/* initiate session */
	session->auth_by_default = 1;
	session->tls=NULL;
	session->protocol = 2;
	/* initiate packet number */
	session->packet_id=0;

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

	no_action.sa_handler = SIG_IGN;
	sigemptyset( & (no_action.sa_mask));
	no_action.sa_flags = 0;
	if ( sigaction( SIGPIPE, & no_action, NULL ) != 0) {
		printf("Error setting \n");
		exit(1);
	}


	session->socket = socket (AF_INET,SOCK_STREAM,0);
	/* connect */
	if (session->socket <= 0){
		nu_exit_clean(session);
		errno=EADDRNOTAVAIL;
		return NULL;
	}
	option_value=1;
	setsockopt (
			session->socket,
			SOL_SOCKET,
			SO_KEEPALIVE,
			&option_value,
			sizeof(option_value));


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
		size_t stringlen;
		size_t actuallen;
		char* enc_oses;
		char * pointer, *buf;
		int osfield_length;
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
		osfield_length=osfield.length;
#ifdef WORDS_BIGENDIAN
		osfield.length=swap16(osfield.length);
#endif
		pointer = buf ;
		memcpy(buf,&osfield,sizeof osfield);
		pointer+=sizeof osfield;
		memcpy(pointer,enc_oses,actuallen);
		free(enc_oses);
		gnutls_record_send(*(session->tls),buf,osfield_length);

		/* wait for message of server about mode */
		if (gnutls_record_recv(*(session->tls),buf,osfield_length)<=0){
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
	session->connected =1;
	session->timestamp_last_sent=time(NULL);
	session->recvthread=NULL;
	return session;
}

void ask_session_end(NuAuth* session)
{
	pthread_t self_thread=pthread_self();
	/* we kill thread thus lock will be lost if another thread reach this point */
	pthread_mutex_lock(session->mutex);
	if(! pthread_equal(*(session->recvthread),self_thread)){
		/* destroy thread */
		pthread_cancel(*(session->recvthread));
	}
	if (session->mode == SRV_TYPE_PUSH) {
		if(! pthread_equal(*(session->checkthread),self_thread)){
			pthread_cancel(*(session->checkthread));
		}
	}
	session->connected=0;
	pthread_mutex_unlock(session->mutex);
	pthread_exit(NULL);
}


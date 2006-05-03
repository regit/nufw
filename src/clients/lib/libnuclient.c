/*
 * libnuclient - TCP/IP connection auth client library.
 *
 * Copyright 2004-2006 - INL
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

/**
 * \defgroup libnuclient Libnuclient
 * @{
 */

/*! \file libnuclient.c
  \brief Main file for libnuclient

  It contains all the exported functions
  */


#include "nuclient.h"
#include <sasl/saslutil.h>
#include <stdarg.h> /* va_list, va_start, ... */
#include <proto.h>
#include "client.h"
#include "security.h"

#ifndef GCRY_THREAD
#define GCRY_THREAD 1
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif

#define DH_BITS 1024
#define REQUEST_CERT 0

#include <sys/utsname.h>

/* callbacks we support */
int nu_getrealm(void *context __attribute__((unused)), int id,
		const char **availrealms __attribute__((unused)),
		const char **result)
{
	if(id != SASL_CB_GETREALM) {
		printf("nu_getrealm not looking for realm");
		return EXIT_FAILURE;
	}
	if(!result) return SASL_BADPARAM;
	*result = "NuPik";
	return SASL_OK;
}

/**
 * SASL callback used to get username and password
 *
 * \return SASL_OK if ok, EXIT_FAILURE on error
 */
int nu_get_usersecret(sasl_conn_t *conn __attribute__((unused)),
		void *context __attribute__((unused)), int id,
		sasl_secret_t **psecret)
{
	NuAuth* session=(NuAuth *)context;
	if ((session->password == NULL) && session->passwd_callback) {
#if USE_UTF8
                char *utf8pass;
#endif
		char *givenpass=session->passwd_callback();
		if (!givenpass){
			return EXIT_FAILURE;
		}
#if USE_UTF8
                utf8pass = locale_to_utf8(givenpass);
		free(givenpass);
                givenpass = utf8pass;
		if (!givenpass){
			return EXIT_FAILURE;
		}
#endif
                session->password = givenpass;
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
		SECURE_STRNCPY((char*)(*psecret)->data, session->password, (*psecret)->len +1 );
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
		case SASL_CB_AUTHNAME:
			if ((session->username == NULL) && session->username_callback) {
#if USE_UTF8
                                char *utf8name;
#endif
				char *givenuser=session->username_callback();
#if USE_UTF8
				utf8name = locale_to_utf8(givenuser);
				free(givenuser);
                                givenuser = utf8name;
				if (givenuser == NULL){
					return EXIT_FAILURE;
				}
#endif
				session->username=givenuser;
			}

			*result=session->username;
			break;
		default:
			return SASL_BADPARAM;
	}

	if (len) *len = strlen(*result);

	return SASL_OK;
}

/**
 * Display an error message, prefixed by "Fatal error: ", and then exit the
 * program. If filename is not NULL and line different than zero, also prefix
 * the message with them.
 *
 * Example: "checks.c:45:Fatal error: Message ..."
 */
void do_panic(const char *filename, unsigned long line, const char *fmt, ...)
{
    va_list args;  
    va_start(args, fmt);
    printf("\n");
    if (filename != NULL && line != 0) {
        printf("%s:%lu:", filename, line);
    }
    printf("Fatal error: ");
    vprintf(fmt, args);            
    printf("\n");
    fflush(stdout);
    exit(EXIT_FAILURE);
    va_end(args);
}

void nu_exit_clean(NuAuth * session)
{
        gnutls_certificate_free_keys(session->cred);
        gnutls_certificate_free_credentials(session->cred);
	gnutls_deinit(session->tls);
	if(session->ct){
		tcptable_free (session->ct);
	}
	if (session->socket>0){
		shutdown(session->socket,SHUT_WR);
		close(session->socket);
		session->socket=0;
	}
	if (session->username){
		free(session->username);
	}
	if (session->password){
		free(session->password);
	}
	if (session->mode == SRV_TYPE_PUSH){
		pthread_mutex_destroy(&(session->check_count_mutex));
		pthread_cond_destroy(&(session->check_cond));
	}
	pthread_mutex_destroy(&(session->mutex));
	free(session);
}

int mysasl_negotiate(gnutls_session session, sasl_conn_t *conn, nuclient_error *err)
{
	char buf[8192];
	const char *data;
	const char *chosenmech;
	int len;
	int r, ret;

	memset(buf,0,sizeof buf);
	/* get the capability list */
	len = gnutls_record_recv(session, buf, sizeof buf);
	if (len < 0)
        {
                SET_ERROR(err, GNUTLS_ERROR, len);
		return EXIT_FAILURE;
        }

	r = sasl_client_start(conn, buf, NULL, &data, (unsigned int *)&len, &chosenmech);
	if (r != SASL_OK && r != SASL_CONTINUE) {
		printf("starting SASL negotiation");
		printf("\n%s\n", sasl_errdetail(conn));
                SET_ERROR(err, SASL_ERROR, r);
		return EXIT_FAILURE;
	}


	/* we send up to 3 strings;
	   the mechanism chosen, the presence of initial response,
	   and optionally the initial response */
	ret = gnutls_record_send(session, chosenmech, strlen(chosenmech));
        if (ret < 0)
        {
            printf("gnutls_record send problem 1 : %s\n",gnutls_strerror(ret));
            SET_ERROR(err,GNUTLS_ERROR, ret);
            return EXIT_FAILURE;
        }
	if(data) {
		ret = gnutls_record_send(session, "Y", 1);
                if (ret < 0)
                {
                  printf("gnutls_record send problem Y : %s\n",gnutls_strerror(ret));
                  SET_ERROR(err,GNUTLS_ERROR, ret);
                  return EXIT_FAILURE;
                }
		ret = gnutls_record_send(session, data, len);
                if (ret < 0)
                {
                  printf("gnutls_record send problem Y1 : %s\n",gnutls_strerror(ret));
                  SET_ERROR(err,GNUTLS_ERROR, ret);
                  return EXIT_FAILURE;
                }
	} else {
		ret = gnutls_record_send(session, "N", 1);
                if (ret < 0)
                {
                  printf("gnutls_record send problem N : %s\n",gnutls_strerror(ret));
                  SET_ERROR(err,GNUTLS_ERROR, ret);
                  return EXIT_FAILURE;
                }
	}

	r=SASL_CONTINUE;
	for (;;) {

		memset(buf,0,sizeof buf);
		len = gnutls_record_recv(session, buf, 1);
		if (len < 0){
			return EXIT_FAILURE;
                        SET_ERROR(err,GNUTLS_ERROR, len);
                        return EXIT_FAILURE;
		}
		switch (buf[0]) {
			case 'O':
				return SASL_OK;
                                break;
			case 'N':
                                SET_ERROR(err,INTERNAL_ERROR,BAD_CREDENTIALS_ERR);
				return SASL_BADAUTH;
                                break;
			case 'C': /* continue authentication */
				break;
			default:
                                SET_ERROR(err,INTERNAL_ERROR,UNKNOWN_ERR);
				return EXIT_FAILURE;
                                break;
		}
		
		memset(buf,0,sizeof buf);
		len = gnutls_record_recv(session, buf, sizeof buf);
		if (len < 0){
                        SET_ERROR(err,GNUTLS_ERROR,len);
			return EXIT_FAILURE;
		}
		r = sasl_client_step(conn, buf, len, NULL, &data, (unsigned int *)&len);
		if (r != SASL_OK && r != SASL_CONTINUE) {
                        SET_ERROR(err,SASL_ERROR,r);
			if (r == SASL_INTERACT){
				return EXIT_FAILURE;
			}
			printf("error performing SASL negotiation");
			printf("\n%s\n", sasl_errdetail(conn));
			return EXIT_FAILURE;
		}

		if (data ) {
			if (!len) len++;
			ret = gnutls_record_send(session, data, len);
                        if (ret < 0)
                        {
                          printf("gnutls_record_send problem 2 : %s\n",gnutls_strerror(ret));
                          SET_ERROR(err,SASL_ERROR,ret);
                          return EXIT_FAILURE;
                        }
		} else {
			ret = gnutls_record_send(session, "", 1);
                        if (ret < 0)
                        {
                          printf("gnutls_record_send problem 3 : %s\n",gnutls_strerror(ret));
                          SET_ERROR(err,SASL_ERROR,ret);
                          return EXIT_FAILURE;
                        }
		}
	}
        SET_ERROR(err,INTERNAL_ERROR,UNKNOWN_ERR);
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
int compare (NuAuth * session,conntable_t *old, conntable_t *new, nuclient_error *err)
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
			} 
#ifdef LINUX
			else {
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
#endif /* LINUX */
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

static gnutls_dh_params dh_params;

static int generate_dh_params(void)
{
        int ret;

	/* Generate Diffie Hellman parameters - for use with DHE
	 * kx algorithms. These should be discarded and regenerated
	 * once a day, once a week or once a month. Depending on the
	 * security requirements.
	 */
	ret = gnutls_dh_params_init( &dh_params);
        if (ret < 0)
        {
            printf("Error in dh parameters init : %s\n",gnutls_strerror(ret));
        }
	ret = gnutls_dh_params_generate2( dh_params, DH_BITS);
        if (ret < 0)
        {
            printf("Error in dh params generation : %s\n",gnutls_strerror(ret));
        }

	return 0;
}

/**
 * Destroy an client session: free all memory
 */
void nu_client_free(NuAuth *session, nuclient_error *err)
{
        /* kill all threads */
        ask_session_end(session);
        /* all threads are dead, we are the one who can access to it */
        /* destroy session */
	nu_exit_clean(session);
        SET_ERROR(err, INTERNAL_ERROR, NO_ERR);
}

/**
 * Global initialisation
 *
 * Warning: to be called once.
 */
void nu_client_global_init(nuclient_error *err)
{

        int ret;

	gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
	ret = gnutls_global_init();
        if (ret != 0)
        {
		SET_ERROR(err, GNUTLS_ERROR, ret);
		return;
/*            printf("gnutls init failing : %s\n",gnutls_strerror(ret)); */
        }

	/* initialize the sasl library */
	ret = sasl_client_init(NULL);

        if (ret != SASL_OK) {
            SET_ERROR(err, SASL_ERROR, ret);
            if (err != NULL)
            {
                err->family=INTERNAL_ERROR;
                err->error=NO_ERR;
            }
            return;
/*            exit(0);*/
	}
}

/**
 * Global de init 
 *
 * Warning: To be called once, when leaving.
 */
void nu_client_global_deinit(nuclient_error *err)
{
        sasl_done();
        gnutls_dh_params_deinit(dh_params);
        gnutls_global_deinit();
        SET_ERROR(err, INTERNAL_ERROR, NO_ERR);
}

/**
 * Create the operating system packet and send it to nuauth.
 * Packet is in format ::nuv2_authfield.
 */
int send_os(NuAuth * session, nuclient_error *err)
{
	/* announce our OS */
	struct utsname info;
	struct nuv2_authfield osfield;
	char *oses;
	char *enc_oses;
	char *pointer;
	char *buf;
	size_t stringlen;
	size_t actuallen;
	int osfield_length;
	int ret;

	/* get info */
	uname(&info);
	/* build packet */
	stringlen=strlen(info.sysname)+strlen(info.release)+strlen(info.version)+3;
	oses=alloca(stringlen);
	enc_oses=calloc(4*stringlen,sizeof(char));
	(void)secure_snprintf(oses,stringlen,"%s;%s;%s",info.sysname, info.release, info.version);
	if (sasl_encode64(oses,strlen(oses),enc_oses,4*stringlen,&actuallen) == SASL_BUFOVER){
		enc_oses=realloc(enc_oses,actuallen);
		sasl_encode64(oses,strlen(oses),enc_oses,actuallen,&actuallen);
	}
	osfield.type=OS_FIELD;
	osfield.option=OS_SRV;
	osfield.length=4+actuallen;
	buf=alloca(osfield.length);
	osfield_length=osfield.length;
	osfield.length=htons(osfield.length);
	pointer = buf ;
	memcpy(buf,&osfield,sizeof osfield);
	pointer+=sizeof osfield;
	memcpy(pointer,enc_oses,actuallen);
	free(enc_oses);
	ret = gnutls_record_send(session->tls,buf,osfield_length);
	if (ret < 0)
	{
		printf("Error sending tls data : %s",gnutls_strerror(ret));
	}

	/* wait for message of server about mode */
	if (gnutls_record_recv(session->tls,buf,osfield_length)<=0){
		errno=EACCES;
		SET_ERROR(err, GNUTLS_ERROR, ret);
		return 0;
	} else {
		if (*buf == SRV_TYPE) {
			session->mode=*(buf+1);
		} else {
			session->mode=SRV_TYPE_POLL;
		}
	}
	return 1;
}

/**
 * Initialiaze TLS:
 *    - Set key filename (and test if the file does exist)
 *    - Set certificate filename (and test if the file does exist)
 *    - Allocate x509 credentials
 *    - Set trust file of credentials (if needed)
 *    - Set certificate (if key and cert. are present)
 *    - Generate Diffie Hellman params
 *    - Init. TLS session
 */
int init_tls_cert(NuAuth * session, nuclient_error *err,
		char* keyfile, char* certfile)
{
	char certstring[256];
	char keystring[256];
	const int cert_type_priority[3] = { GNUTLS_CRT_X509,  0 };
	char *home = getenv("HOME");
        int ok;
	int ret;

	/* compute patch keyfile */
	if (keyfile == NULL && home != NULL)
	{
		ok = secure_snprintf(keystring, sizeof(keystring),
				"%s/.nufw/key.pem", home);
		if (ok) keyfile = keystring;
	}
	
	/* test if key file exists */
	if (access(keyfile,R_OK) != 0)
	{
		keyfile=NULL;
#if REQUEST_CERT
                SET_ERROR(err, INTERNAL_ERROR, FILE_ACCESS_ERR);
		errno=EBADF;
		return 0;
#endif
	}

	if (certfile == NULL && home != NULL)
	{
		ok = secure_snprintf(certstring, sizeof(certstring),
				"%s/.nufw/cert.pem", home);
		if (ok) certfile = certstring;
	}
	/* test if cert exists */
	if (access(certfile,R_OK) != 0)
	{
		certfile=NULL;
#if REQUEST_CERT
                SET_ERROR(err, INTERNAL_ERROR, FILE_ACCESS_ERR);
		errno=EBADF;
		return 0;
#endif
	}

	/* X509 stuff */
	ret = gnutls_certificate_allocate_credentials(&(session->cred));
        if (ret != 0)
        {
            SET_ERROR(err, GNUTLS_ERROR, ret);
            return 0;
            /*printf("problem allocating gnutls credentials : %s\n",gnutls_strerror(ret));*/
        }

	/* sets the trusted cas file */
#if REQUEST_CERT
	ret = gnutls_certificate_set_x509_trust_file(session->cred, certfile, GNUTLS_X509_FMT_PEM);
        if (ret < 0)
        {
            SET_ERROR(err, GNUTLS_ERROR, ret);
            return 0;
            /*printf("problem setting x509 trust file : %s\n",gnutls_strerror(ret));*/
        }
#endif
	if (certfile && keyfile){
		ret = gnutls_certificate_set_x509_key_file(session->cred, certfile, keyfile, GNUTLS_X509_FMT_PEM);
		if (ret <0){
                  SET_ERROR(err, GNUTLS_ERROR, ret);
                  return 0;
			/*printf("problem with keyfile : %s\n",gnutls_strerror(ret));*/
		}
	}

	/* set Diffie Hellman params */
	generate_dh_params();
	gnutls_certificate_set_dh_params( session->cred, dh_params);

	/* Initialize TLS session */
	ret = gnutls_init(&(session->tls), GNUTLS_CLIENT);
        if (ret != 0)
        {
            SET_ERROR(err, GNUTLS_ERROR, ret);
            return 0;
            /*printf("gnutls init error : %s\n",gnutls_strerror(ret));*/
        }

	ret = gnutls_set_default_priority(session->tls);
        if (ret < 0)
        {
            SET_ERROR(err, GNUTLS_ERROR, ret);
            return 0;
            /*printf("error setting tls default priority : %s\n",gnutls_strerror(ret));*/
        }

	ret = gnutls_certificate_type_set_priority(session->tls, cert_type_priority);
        if (ret < 0)
        {
            SET_ERROR(err, GNUTLS_ERROR, ret);
            return 0;
            /*printf("error setting tls cert type priority : %s\n",gnutls_strerror(ret));*/
        }
	/* put the x509 credentials to the current session */
	ret = gnutls_credentials_set(session->tls, GNUTLS_CRD_CERTIFICATE, session->cred);
        if (ret < 0)
        {
            SET_ERROR(err, GNUTLS_ERROR, ret);
            return 0;
            /*printf("error setting tls credentials : %s\n",gnutls_strerror(ret));*/
        }

	return 1;
}

/**
 * Initialiaze SASL: create an client, set properties 
 * and then call mysasl_negotiate()
 */
int init_sasl(NuAuth * session, nuclient_error *err)
{
	int ret;
	sasl_conn_t *conn;
	sasl_ssf_t extssf = 0;

	/* SASL time */
	sasl_callback_t callbacks[] = {
		{ SASL_CB_GETREALM, &nu_getrealm, session },
		{ SASL_CB_USER, &nu_get_userdatas, session },
		{ SASL_CB_AUTHNAME, &nu_get_userdatas, session },
		{ SASL_CB_PASS, &nu_get_usersecret, session },
		{ SASL_CB_LIST_END, NULL, NULL }
	};

	/* client new connection */
	ret = sasl_client_new("NuFW", "myserver", NULL, NULL, callbacks, 0, &conn);
	if (ret != SASL_OK) {
		printf("Failed allocating connection state");
		errno=EAGAIN;
        SET_ERROR(err, SASL_ERROR, ret);
		return 0;
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
	sasl_setprop(conn,SASL_SSF_EXTERNAL,&extssf);
	ret = sasl_setprop(conn, SASL_AUTH_EXTERNAL,session->username);
	if (ret != SASL_OK) {
		errno=EACCES;
        SET_ERROR(err, SASL_ERROR, ret);
		return 0;
        }


	/* set required security properties here
	   sasl_setprop(conn, SASL_SEC_PROPS, &secprops); */

	ret = mysasl_negotiate(session->tls, conn,err);
	if (ret != SASL_OK) {
		errno=EACCES;
/*        SET_ERROR(err, SASL_ERROR, ret); */
		return 0;
	}

	return 1;
}

/**
 * Create a socket to nuauth, and try to connect. The function also set 
 * SIGPIPE handler: ignore these signals.
 */
int init_socket(NuAuth * session, nuclient_error *err)
{
	int option_value;
	struct sigaction no_action;

	/* ignore SIGPIPE */
	no_action.sa_handler = SIG_IGN;
	sigemptyset( & (no_action.sa_mask));
	no_action.sa_flags = 0;
	(void)sigaction( SIGPIPE, & no_action, NULL);

	/* create socket to nuauth */
	session->socket = socket (AF_INET,SOCK_STREAM,0);
	if (session->socket <= 0){
		errno=EADDRNOTAVAIL;
                SET_ERROR(err, INTERNAL_ERROR, CANT_CONNECT_ERR);
		return 0;
	}
	option_value=1;
	setsockopt (
			session->socket,
			SOL_SOCKET,
			SO_KEEPALIVE,
			&option_value,
			sizeof(option_value));

	/* connect to nuauth */
	if ( connect(session->socket,(struct sockaddr *)(&session->adr_srv),sizeof(session->adr_srv)) == -1){
		errno=ENOTCONN;
                SET_ERROR(err, INTERNAL_ERROR, CANT_CONNECT_ERR);
		return 0;
	}

	return 1;
}

/**
 * Do the TLS handshake and check server certificate
 */
int tls_handshake(NuAuth * session, nuclient_error *err)
{
	int ret;

	gnutls_transport_set_ptr( session->tls, (gnutls_transport_ptr)session->socket);

	/* Perform the TLS handshake */
	ret = gnutls_handshake( session->tls);
	if (ret < 0) {
		gnutls_perror(ret);
		errno=ECONNRESET;
		SET_ERROR(err, GNUTLS_ERROR, ret);
		return 0;
	}
	/* certificate verification */
	ret = gnutls_certificate_verify_peers(session->tls);
	if (ret <0){
		printf("Certificate verification failed : %s\n",gnutls_strerror(ret));
		SET_ERROR(err, GNUTLS_ERROR, ret);
		return 0;
	} else {
		printf("Server Certificate OK\n");
	}
	return 1;
}

/**
 * Set host address: convert hostname string to IPv4 address
 */
int set_host(NuAuth * session, nuclient_error *err,
		const char *hostname, unsigned int port)
{
	struct hostent *host = gethostbyname(hostname);
	if (host == NULL)
	{
/*		fprintf(stderr, "*** An error occured when resolving the provided hostname\n");*/
                SET_ERROR(err, INTERNAL_ERROR, DNS_RESOLUTION_ERR);
		return 0;
	}

	(session->adr_srv).sin_family = AF_INET;
	(session->adr_srv).sin_port = htons(port);
	(session->adr_srv).sin_addr = *(struct in_addr *)host->h_addr_list[0];
	if ((session->adr_srv).sin_addr.s_addr == INADDR_NONE) {

                SET_ERROR(err, INTERNAL_ERROR, NO_ADDR_ERR);
		return 0;
	}
	
	return 1;
}

/**
 * Initialisation of nufw authentication session: set basic fields and then
 * call:
 *    - set_host() ;
 *    - init_tls_cert() ;
 *    - init_socket() ;
 *    - tls_handshake() ;
 *    - init_sasl() ;
 *    - send_os().
 *
 * If everything is ok, create the connection table using tcptable_init(). 
 */
NuAuth* nu_client_init2(
		const char *hostname, unsigned int port,
		char* keyfile, char* certfile,
		void* username_callback,void * passwd_callback, 
                void* tlscred_callback, nuclient_error *err
		)
{
	conntable_t *new;
	NuAuth * session;

	/* First reset error */
        SET_ERROR(err, INTERNAL_ERROR, NO_ERR);

	/* Allocate a new session */
	session=(NuAuth*) calloc(1,sizeof(NuAuth));
	if (session == NULL) {
		SET_ERROR(err, INTERNAL_ERROR, MEMORY_ERR);
		return NULL;
	}

	/* Set basic fields */
	session->localuserid = getuid();
	session->connected = 1;
        session->count_msg_cond = -1;
	session->auth_by_default = 1;
	session->packet_id = 0;
	session->tls=NULL;
	session->ct = NULL;
	session->protocol = PROTO_VERSION;
	session->username_callback = username_callback;
	session->passwd_callback = passwd_callback;
	session->tls_passwd_callback = tlscred_callback;
	session->timestamp_last_sent = time(NULL);

	/* create session mutex */
	pthread_mutex_init(&(session->mutex),NULL);

	/* set field about host */
	if (!set_host(session, err, hostname, port)) {
		nu_exit_clean(session);
		return NULL;
	}

	/* set fields about TLS and certificates */
	if (!init_tls_cert(session, err, keyfile, certfile)) {
		nu_exit_clean(session);
		return NULL;
	}

	if (!init_socket(session, err)) {
		nu_exit_clean(session);
		return NULL;
	}

	if (!tls_handshake(session, err)) {
		nu_exit_clean(session);
		return NULL;
	}

	if (!init_sasl(session, err)) {
		nu_exit_clean(session);
		return NULL;
	}
	
	if (!send_os(session, err)) {
		nu_exit_clean(session);
		return NULL;
	}

	if (tcptable_init (&new) == 0) panic ("tcptable_init failed");
	session->ct = new;
	return session;
}

void ask_session_end(NuAuth* session)
{
	pthread_t self_thread=pthread_self();
	/* we kill thread thus lock will be lost if another thread reach this point */

	if (session){ /* sanity check */
		if (session->connected == 0){
			return;
		}
		pthread_mutex_lock(&(session->mutex));
		session->connected=0;
		gnutls_bye(session->tls,GNUTLS_SHUT_WR);
		if(! pthread_equal(session->recvthread,self_thread)){
			/* destroy thread */
			pthread_cancel(session->recvthread);
			pthread_join(session->recvthread,NULL);
		}
		if (session->mode == SRV_TYPE_PUSH) {
			if(! pthread_equal(session->checkthread,self_thread)){
				pthread_cancel(session->checkthread);
				pthread_join(session->checkthread,NULL);
			}
		}
		pthread_mutex_unlock(&(session->mutex));
		if (pthread_equal(session->recvthread,self_thread) ||
				((session->mode == SRV_TYPE_PUSH) && pthread_equal(session->checkthread,self_thread))
		   ) {
			pthread_exit(NULL);
		}
	}
}

/**
 * Allocate a structure to store client error
 */
int nuclient_error_init(nuclient_error **err)
{
      if (*err != NULL)
          return -1;
      *err=malloc(sizeof(nuclient_error));
      return 0;
}

/**
 * Destroy an error (free memory)
 */
void nuclient_error_destroy(nuclient_error *err)
{
    if (err!=NULL)
      free(err);
}

/**
 * Convert an error to an human readable string
 */
const char* nuclient_strerror (nuclient_error *err)
{
  if (err==NULL)
      return "Error structure was not initialised";
  switch (err->family){
    case GNUTLS_ERROR:
      return gnutls_strerror(err->error);
      break;
    case SASL_ERROR:
      return sasl_errstring(err->error,NULL,NULL);
      break;
    case INTERNAL_ERROR:
      switch (err->error){
        case NOERR: return "No error";
        case SESSION_NOT_CONNECTED_ERR:  return "Session not connected";
        case TIMEOUT_ERR:      return "Connection timeout";
        case DNS_RESOLUTION_ERR: return "DNS resolution error";
        case NO_ADDR_ERR:      return "Address not recognized";
        case FILE_ACCESS_ERR:  return "File access error";
        case CANT_CONNECT_ERR: return "Connection failed";
        case MEMORY_ERR:       return "No more memory";
        case TCPTABLE_ERR:     return "Unable to read connection table";
        case SEND_ERR:         return "Unable to send packet to nuauth";
        case BAD_CREDENTIALS_ERR: return "Bad credentials";
/*        case UNKNOWN_ERR:       return "Unknown error";*/
        default: return "Unknown internal error code";
      }
    break;
    default:
      return "Unkown family error";
  }
}

/** @} */

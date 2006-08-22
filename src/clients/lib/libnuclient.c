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

/** 
 * Use gcry_malloc_secure() to disallow a memory page 
 * to be moved to the swap
 */
#define USE_GCRYPT_MALLOC_SECURE

#define NULL_THREAD 0

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

#ifndef NUCLIENT_WITHOUT_DIFFIE_HELLMAN
#  define DH_BITS 1024
#endif

#define REQUEST_CERT 0
static const int cert_type_priority[3] = { GNUTLS_CRT_X509,  0 };

#include <sys/utsname.h>

/* callbacks we support */
int nu_getrealm(void *context __attribute__((unused)), int id,
        const char **availrealms __attribute__((unused)),
        const char **result)
{
    if(id != SASL_CB_GETREALM) {
#if DEBUG    
        printf("nu_getrealm not looking for realm");
#endif        
        return EXIT_FAILURE;
    }
    if(!result) return SASL_BADPARAM;
    *result = "nufw";
    return SASL_OK;
}

/**
 * SASL callback used to get password
 *
 * \return SASL_OK if ok, EXIT_FAILURE on error
 */
int nu_get_usersecret(sasl_conn_t *conn __attribute__((unused)),
        void *context __attribute__((unused)), int id,
        sasl_secret_t **psecret)
{
    size_t len;
    NuAuth* session=(NuAuth *)context;
    if(id != SASL_CB_PASS) {
        if (session->verbose)
            printf("getsecret not looking for pass");
        return EXIT_FAILURE;
    }
    if (session->password == NULL) {
        return EXIT_FAILURE;
    }
    if(!psecret) return SASL_BADPARAM;

    len = strlen(session->password);
    *psecret = (sasl_secret_t*)calloc(sizeof(sasl_secret_t) + len+1, sizeof(char));
    (*psecret)->len = len;
    SECURE_STRNCPY((char*)(*psecret)->data, session->password, len+1);
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
            if (session->username == NULL) {
                return EXIT_FAILURE;
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
    if(session->ct){
        tcptable_free (session->ct);
    }
    if (session->socket>0){
        shutdown(session->socket,SHUT_WR);
        close(session->socket);
        session->socket=0;
    }

#ifdef USE_GCRYPT_MALLOC_SECURE
    gcry_free(session->username);
    gcry_free(session->password);
#else
    free(session->username);
    free(session->password);
#endif

    gnutls_certificate_free_keys(session->cred);
    gnutls_certificate_free_credentials(session->cred);
    if (session->diffie_hellman) {
        gnutls_dh_params_deinit(session->dh_params);
    }
    gnutls_deinit(session->tls);

    pthread_cond_destroy(&(session->check_cond));
    pthread_mutex_destroy(&(session->check_count_mutex));
    pthread_mutex_destroy(&(session->mutex));
    free(session);
}


static int samp_send(gnutls_session session, const char *buffer,
	  unsigned length, nuclient_error *err)
{
  char *buf;
  unsigned len, alloclen;
  int result;

  alloclen = ((length / 3) + 1) * 4 + 4;
  buf = malloc(alloclen);
  if (buf == NULL) {
    SET_ERROR(err, INTERNAL_ERROR, MEMORY_ERR);
    return 0;
  }

  result = sasl_encode64(buffer, length, buf+3, alloclen, &len);
  if (result != SASL_OK){
      SET_ERROR(err, SASL_ERROR, result);
      free(buf);
      return 0;
  }

  memcpy(buf,"C: ",3);
  
  result = gnutls_record_send(session, buf, len+3);
  free(buf);
  if (result < 0) {
    SET_ERROR(err, GNUTLS_ERROR, result);
    return 0;
  }
  return 1;
}



static unsigned samp_recv(gnutls_session session, char* buf,int bufsize, nuclient_error *err)
{
  unsigned len;
  int result;
  int tls_len;
  
  tls_len = gnutls_record_recv(session, buf, bufsize);
  if (tls_len<=0){
      SET_ERROR(err, GNUTLS_ERROR, tls_len);
      return 0;
  }

  result = sasl_decode64(buf+3, (unsigned) strlen(buf+3), buf,
			 bufsize, &len);
  if (result != SASL_OK){
      SET_ERROR(err, SASL_ERROR, result);
    return 0;
  }
  buf[len] = '\0';
  return len;
}



int mysasl_negotiate(NuAuth* user_session, sasl_conn_t *conn, nuclient_error *err)
{
    char buf[8192];
    const char *data;
    const char *chosenmech;
    unsigned len;
    int result;
    gnutls_session session = user_session->tls;

    memset(buf,0,sizeof buf);
    /* get the capability list */
    len = samp_recv(session, buf, 8192, err);
    if (len == 0) {
        return SASL_FAIL;
    }

    result = sasl_client_start(conn,
            buf,
            NULL,
            &data, 
            &len,
            &chosenmech);
    
    printf("Using mechanism %s\n", chosenmech);
    if (result != SASL_OK && result != SASL_CONTINUE) {
        if (user_session->verbose) {
            printf("Error starting SASL negotiation");
            printf("\n%s\n", sasl_errdetail(conn));
        }
        SET_ERROR(err, SASL_ERROR, result);
        return SASL_FAIL;
    }

    strcpy(buf, chosenmech);
    if (data) {
        if (8192 - strlen(buf) - 1 < len){
            return SASL_FAIL;
        }
        memcpy(buf + strlen(buf) + 1, data, len);
        len += (unsigned) strlen(buf) + 1;
        data = NULL;
    } else {
        len = (unsigned) strlen(buf);
    }

    if (!samp_send(session,buf, len, err)) {
        return SASL_FAIL;
    }

    while (result == SASL_CONTINUE) {
        if (user_session->verbose) {
            printf("Waiting for server reply...\n");
        }
	memset(buf,0,sizeof(buf));
        len = samp_recv(session, buf, sizeof(buf), err);
        if (len < 0) {
            printf("server problem, recv fail...\n");
            return SASL_FAIL;
        }
        result = sasl_client_step(conn, buf, len, NULL, &data, &len);
        if (result != SASL_OK && result != SASL_CONTINUE){
            if (user_session->verbose)
                printf("Performing SASL negotiation\n");
            SET_ERROR(err, SASL_ERROR, result);
        }
        if (data && len) {
            if (user_session->verbose)
                puts("Sending response...\n");
            if (!samp_send(session,data, len, err)) {
                return SASL_FAIL;
            }
        } else if (result != SASL_OK) {
            if (!samp_send(session,"", 0, err)) {
                return SASL_FAIL;
	    }
	}
    }

    if (result != SASL_OK){
	    if (user_session->verbose)
		    puts("Authentication failed...");
	    return SASL_FAIL;
    } else {
	    if (user_session->verbose)
		    puts("Authentication started...\n");
    }

    return SASL_OK;
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
 * \brief Compare connection tables and send packets 
 *
 * Compare the `old' and `new' tables, sending packet to nuauth 
 * if differences are found.
 *
 * \return -1 if error (then disconnect is needed) or the number of 
 * authenticated packets if it has succeeded
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
                if (bucket->protocol == IPPROTO_UDP){
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

/**
 * \defgroup nuclientAPI API of libnuclient
 * \brief The high level API of libnuclient can be used to build a NuFW client
 *
 * A client needs to call a few functions in the correct order to be able to authenticate:
 *  - nu_client_global_init(): To be called once at program start
 *  - nu_client_new(): start user session
 *  - nu_client_setup_tls(): (optionnal) setup TLS key/certificate files
 *  - nu_client_connect(): try to connect to nuauth server
 *  - nu_client_check(): do a check, it has to be run at regular interval
 *  - nu_client_delete(): free a user session
 *  - nu_client_global_deinit(): To be called once at program end
 *
 * On error, don't forget to delete session with nu_client_delete()
 */

/**
 * \ingroup nuclientAPI
 * \brief Destroy a client session: free all used memory
 *
 * This destroy a session and free all related structures.
 *
 * \param session A ::NuAuth session to be cleaned
 */
void nu_client_delete(NuAuth *session)
{
    /* kill all threads */
    ask_session_end(session);
    /* all threads are dead, we are the one who can access to it */
    /* destroy session */
    nu_exit_clean(session);
}

/**
 * \ingroup nuclientAPI
 * \brief global initialisation function
 *
 * This function inits all library needed to initiate a connection to a nuauth server
 *
 * \param err A pointer to a ::nuclient_error which contains at exit the error
 *
 * \warning To be called only once.
 */
int nu_client_global_init(nuclient_error *err)
{
    int ret;

    gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
    ret = gnutls_global_init();
    if (ret != 0)
    {
        SET_ERROR(err, GNUTLS_ERROR, ret);
        return 0;
    }

    /* initialize the sasl library */
    ret = sasl_client_init(NULL);
    if (ret != SASL_OK) {
        SET_ERROR(err, SASL_ERROR, ret);
        return 0;
    }

    return 1;
}

/**
 * \ingroup nuclientAPI
 * \brief  Global de init function 
 *
 * \warning To be called once, when leaving.
 */
void nu_client_global_deinit()
{
    sasl_done();
    gnutls_global_deinit();
}

/**
 * Create the operating system packet and send it to nuauth.
 * Packet is in format ::nuv2_authfield.
 *
 * \param session Pointer to client session
 * \param err Pointer to a nuclient_error: which contains the error
 */
int send_os(NuAuth * session, nuclient_error *err)
{
    /* announce our OS */
    struct utsname info;
    struct nuv4_authfield osfield;
    char *oses;
    char *enc_oses;
    char *pointer;
    char *buf;
    unsigned stringlen;
    unsigned actuallen;
    int osfield_length;
    int ret;

    /* read OS informations */
    uname(&info);

    /* encode OS informations in base64 */
    stringlen = strlen(info.sysname) + 1 
        + strlen(info.release) + 1 + strlen(info.version) + 1;
#ifdef LINUX
    oses=alloca(stringlen);
#else 
    oses=calloc(stringlen,sizeof(char));
#endif
    enc_oses = calloc(4*stringlen, sizeof(char));
    (void)secure_snprintf(oses, stringlen,
                          "%s;%s;%s",
                          info.sysname, info.release, info.version);
    if (sasl_encode64(oses, strlen(oses), enc_oses, 4*stringlen, &actuallen) == SASL_BUFOVER){
        enc_oses=realloc(enc_oses, actuallen);
        sasl_encode64(oses, strlen(oses), enc_oses, actuallen, &actuallen);
    }

#ifndef LINUX
    free(oses);
#endif

    /* build packet header */
    osfield.type = OS_FIELD;
    osfield.option = OS_SRV;
    osfield.length = sizeof(osfield) + actuallen;

    /* add packet body */
#ifdef LINUX
    buf=alloca(osfield.length); 
#else
    buf=calloc(osfield.length,sizeof(char));
#endif
    osfield_length = osfield.length;
    osfield.length = htons(osfield.length);
    pointer = buf ;
    memcpy(buf, &osfield, sizeof osfield);
    pointer += sizeof osfield;
    memcpy(pointer, enc_oses, actuallen);
    free(enc_oses);

    /* Send OS field over network */
    ret = gnutls_record_send(session->tls,buf,osfield_length);
    if (ret < 0)
    {
        if (session->verbose)
            printf("Error sending tls data: %s",gnutls_strerror(ret));
        SET_ERROR(err, GNUTLS_ERROR, ret);
        return 0;
    }

    /* wait for message of server about mode */
    if (gnutls_record_recv(session->tls,buf,osfield_length)<=0){
        errno=EACCES;
        SET_ERROR(err, GNUTLS_ERROR, ret);
#ifndef LINUX
        free(buf);
#endif
        return 0;
    }
#ifndef LINUX
    free(buf);
#endif

    if (buf[0] == SRV_TYPE) {
        session->server_mode = buf[1];
    } else {
        session->server_mode = SRV_TYPE_POLL;
    }
    return 1;
}

/**
 * Initialize TLS:
 *    - Set key filename (and test if the file does exist)
 *    - Set certificate filename (and test if the file does exist)
 *    - Set trust file of credentials (if needed)
 *    - Set certificate (if key and cert. are present)
 *    - Init. TLS session
 *
 * \param session Pointer to client session
 * \param keyfile Complete path to a key file stored in PEM format (can be NULL)
 * \param certfile Complete path to a certificate file stored in PEM format (can be NULL)
 * \param cafile Complete path to a certificate authority file stored in PEM format (can be NULL)
 * \param tls_passwd Certificate password string
 * \param err Pointer to a nuclient_error: which contains the error
 * \return Returns 0 on error (error description in err), 1 otherwise
 */
int nu_client_setup_tls(NuAuth * session,
        char* keyfile, char* certfile, char* cafile, char *tls_password,
        nuclient_error *err)
{
    char certstring[256];
    char keystring[256];
    char *home = getenv("HOME");
    int ok;
    int ret;
    
    session->tls_password = tls_password;

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

    /* sets the trusted cas file */
#if REQUEST_CERT
    ret = gnutls_certificate_set_x509_trust_file(session->cred, certfile, GNUTLS_X509_FMT_PEM);
    if (ret < 0)
    {
        SET_ERROR(err, GNUTLS_ERROR, ret);
        return 0;
    }
#endif
    if (certfile != NULL && keyfile != NULL)
    {
        ret = gnutls_certificate_set_x509_key_file(session->cred, certfile, keyfile, GNUTLS_X509_FMT_PEM);
        if (ret <0){
            SET_ERROR(err, GNUTLS_ERROR, ret);
            return 0;
        }
    }

    /* put the x509 credentials to the current session */
    ret = gnutls_credentials_set(session->tls, GNUTLS_CRD_CERTIFICATE, session->cred);
    if (ret < 0)
    {
        SET_ERROR(err, GNUTLS_ERROR, ret);
        return 0;
    }
    session->need_set_cred = 0;
    return 1;
}

/**
 * Initialiaze SASL: create an client, set properties 
 * and then call mysasl_negotiate()
 *
 * \param session Pointer to client session
 * \param err Pointer to a nuclient_error: which contains the error
 */
int init_sasl(NuAuth* session, nuclient_error *err)
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

    /*
     * gnutls_record_send(session->tls,PROTO_STRING " " PROTO_VERSION,
    				strlen(PROTO_STRING " " PROTO_VERSION));
				*/

    gnutls_record_send(session->tls,"PROTO 4",strlen("PROTO 4"));

    /* set external properties here
       sasl_setprop(conn, SASL_SSF_EXTERNAL, &extprops); */
    /* set username taken from console */

    /* client new connection */
    ret = sasl_client_new("nuauth", "", NULL, NULL, callbacks, 0, &conn);
    if (ret != SASL_OK) {
        if (session->verbose)
            printf("Failed allocating connection state");
        errno=EAGAIN;
        SET_ERROR(err, SASL_ERROR, ret);
        return 0;
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

    ret = mysasl_negotiate(session, conn,err);
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
 *
 * \param session Pointer to client session
 * \param hostname String containing hostname of nuauth server (default: #NUAUTH_IP)
 * \param service Port number (or string) on which nuauth server is listening (default: #USERPCKT_PORT)
 * \param err Pointer to a nuclient_error: which contains the error
 */
int init_socket(NuAuth * session, 
        const char *hostname, const char *service,
        nuclient_error *err)
{
    int option_value;
    struct sigaction no_action;
    int ecode;
    struct addrinfo *res;
    struct addrinfo hints = {
        0,
        PF_UNSPEC,
        SOCK_STREAM,
        0,
        0,
        NULL,
        NULL,
        NULL
    };

    /* get address informations */
    ecode = getaddrinfo(hostname, service, &hints, &res);
    if (ecode != 0)
    {
        if (session->verbose) {
            fprintf(stderr, "Fail to create host address: %s\n",
                    gai_strerror(ecode));
            fprintf(stderr, "(host=\"%s\", service=\"%s\")\n",
                    hostname, service);
        }
        SET_ERROR(err, INTERNAL_ERROR, DNS_RESOLUTION_ERR);
        return 0;
    }

    /* ignore SIGPIPE */
    no_action.sa_handler = SIG_IGN;
    sigemptyset( & (no_action.sa_mask));
    no_action.sa_flags = 0;
    (void)sigaction( SIGPIPE, & no_action, NULL);

    /* create socket to nuauth */
    session->socket = socket (res->ai_family, res->ai_socktype, res->ai_protocol);
    if (session->socket <= 0){
        errno=EADDRNOTAVAIL;
        freeaddrinfo(res);
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
    if ( connect(session->socket, res->ai_addr, res->ai_addrlen) == -1){
        errno=ENOTCONN;
        SET_ERROR(err, INTERNAL_ERROR, CANT_CONNECT_ERR);
        freeaddrinfo(res);
        return 0;
    }
    freeaddrinfo(res);
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
    ret = 0;
    do
    {
        ret = gnutls_handshake(session->tls);
    } while (ret < 0 && !gnutls_error_is_fatal(ret));
    
    if (ret < 0)
    {
        gnutls_perror(ret);
        errno=ECONNRESET;
        SET_ERROR(err, GNUTLS_ERROR, ret);
        return 0;
    }

    /* certificate verification */
    ret = gnutls_certificate_verify_peers(session->tls);
    if (ret < 0) {
        if (session->verbose) {
            printf("Certificate verification failed: %s\n",gnutls_strerror(ret));
        }
        SET_ERROR(err, GNUTLS_ERROR, ret);
        return 0;
    }

    if (session->verbose)
        printf("Server Certificate OK\n");
    return 1;
}

#ifdef USE_GCRYPT_MALLOC_SECURE
/**
 * Make a secure copy of a string:
 * - allocate memory using gcry_calloc_secure(): disallow the memory page
 *   to be copy on swap ;
 * - wipe out old string (fill with zero) ;
 * - free old string.
 *
 * Wipe out and free memory in every case (error or not).
 *
 * New allocated memory have to be freed using gcry_free() and not free().
 *
 * \return Fresh copy of the string, or NULL if fails.
 */
static char* secure_str_copy(const char *orig)
{
    size_t len = strlen(orig);
    char *new = gcry_calloc_secure(len+1, sizeof(char));
    if (new != NULL) {
        SECURE_STRNCPY(new, orig, len+1);
    }
    return new;
}
#endif

/**
 * \ingroup nuclientAPI
 * \brief Init connection to nuauth server
 *
 * \param username User name string
 * \param password Password string
 * \param diffie_hellman If equals to 1, use Diffie Hellman for key exchange
 * (very secure but initialization is slower)
 * \param err Pointer to a nuclient_error: which contains the error
 * \return A pointer to a valid ::NuAuth structure or NULL if init has failed
 * 
 * \par Internal
 * Initialisation of nufw authentication session:
 *    - set basic fields and then ;
 *    - allocate x509 credentials ;
 *    - generate Diffie Hellman params.
 *
 * If everything is ok, create the connection table using tcptable_init(). 
 */
NuAuth* nu_client_new(
        const char* username,
        const char* password, 
        unsigned char diffie_hellman,
        nuclient_error *err)
{
    conntable_t *new;
    NuAuth * session;
    int ret;
    
    if (username == NULL || password == NULL) {
        SET_ERROR(err, INTERNAL_ERROR, BAD_CREDENTIALS_ERR);
        return NULL;
    }

    /* First reset error */
    SET_ERROR(err, INTERNAL_ERROR, NO_ERR);

    /* Allocate a new session */
    session=(NuAuth*) calloc(1,sizeof(NuAuth));
    if (session == NULL) {
        SET_ERROR(err, INTERNAL_ERROR, MEMORY_ERR);
        return NULL;
    }
    
    /* Set basic fields */
    session->userid = getuid();
    session->connected = 0;
    session->diffie_hellman = diffie_hellman;
    session->count_msg_cond = -1;
    session->auth_by_default = 1;
    session->packet_seq = 0;
    session->checkthread = NULL_THREAD;
    session->recvthread = NULL_THREAD;
    session->tls=NULL;
    session->ct = NULL;
#ifdef USE_GCRYPT_MALLOC_SECURE
    session->username = secure_str_copy(username);
    session->password = secure_str_copy(password);
    if (session->username == NULL || session->password == NULL) {
        SET_ERROR(err, INTERNAL_ERROR, MEMORY_ERR);
        return NULL;
    }
#else    
    session->username = strdup(username);
    session->password = strdup(password);
#endif    
    session->tls_password = NULL;
    session->debug_mode = 0;
    session->verbose = 1;
    session->timestamp_last_sent = time(NULL);
    session->need_set_cred = 1;

    /* create session mutex */
    pthread_mutex_init(&(session->mutex),NULL);
    pthread_mutex_init(&(session->check_count_mutex),NULL);
    pthread_cond_init(&(session->check_cond),NULL);

    if (tcptable_init (&new) == 0) {
        SET_ERROR(err, INTERNAL_ERROR, MEMORY_ERR);
        nu_exit_clean(session);
        return NULL;
    }
    session->ct = new;

    /* X509 stuff */
    ret = gnutls_certificate_allocate_credentials(&(session->cred));
    if (ret != 0)
    {
        SET_ERROR(err, GNUTLS_ERROR, ret);
        nu_exit_clean(session);
        return NULL;
    }

    if (session->diffie_hellman) {
        /* allocate diffie hellman parameters */
        ret = gnutls_dh_params_init(&session->dh_params);
        if (ret < 0) {
            SET_ERROR(err, GNUTLS_ERROR, ret);
            nu_exit_clean(session);
            return NULL;
        }

        /* Generate Diffie Hellman parameters - for use with DHE
         * kx algorithms. These should be discarded and regenerated
         * once a day, once a week or once a month. Depending on the
         * security requirements.
         */
        ret = gnutls_dh_params_generate2(session->dh_params, DH_BITS);
        if (ret < 0) {
            SET_ERROR(err, GNUTLS_ERROR, ret);
            nu_exit_clean(session);
            return NULL;
        }

        gnutls_certificate_set_dh_params( session->cred, session->dh_params);
    }

    /* Initialize TLS session */
    ret = gnutls_init(&session->tls, GNUTLS_CLIENT);
    if (ret != 0)
    {
        SET_ERROR(err, GNUTLS_ERROR, ret);
        nu_exit_clean(session);
        return NULL;
    }

    ret = gnutls_set_default_priority(session->tls);
    if (ret < 0)
    {
        SET_ERROR(err, GNUTLS_ERROR, ret);
        nu_exit_clean(session);
        return NULL;
    }

    ret = gnutls_certificate_type_set_priority(session->tls, cert_type_priority);
    if (ret < 0)
    {
        SET_ERROR(err, GNUTLS_ERROR, ret);
        nu_exit_clean(session);
        return NULL;
    }
    return session;
}

/**
 * Reset a session: close the connection and reset attributes. So the session
 * can be used as nu_client_connect() input.
 */
void nu_client_reset(NuAuth *session)
{
    /* close TLS conneciton */
    ask_session_end(session);

    /* delete old TLS session and create a new TLS session */
    gnutls_deinit(session->tls);
    gnutls_init(&session->tls, GNUTLS_CLIENT);
    gnutls_set_default_priority(session->tls);
    gnutls_certificate_type_set_priority(session->tls, cert_type_priority);
    session->need_set_cred = 1;

    /* close socket */
    if (session->socket>0)
    {
        shutdown(session->socket,SHUT_WR);
        close(session->socket);
    }

    /* reset fields */
    session->connected = 0;
    session->count_msg_cond = -1;
    session->timestamp_last_sent = time(NULL);
    session->socket = -1;
    session->checkthread = 0;
    session->recvthread = 0;
}

/**
 * Try to connect to nuauth server:
 *    - init_socket(): create socket to server ;
 *    - tls_handshake(): TLS handshake ;
 *    - init_sasl(): authentification with SASL ;
 *    - send_os(): send OS field.
 *
 * \param session Pointer to client session
 * \param hostname String containing hostname of nuauth server (default: #NUAUTH_IP)
 * \param service Port number (or string) on which nuauth server is listening (default: #USERPCKT_PORT)
 * \param err Pointer to a nuclient_error: which contains the error
 * \return Returns 0 on error (error description in err), 1 otherwise
 */
int nu_client_connect(NuAuth* session, 
        const char *hostname, const char *service, nuclient_error *err)
{
    if (session->need_set_cred)
    {
        /* put the x509 credentials to the current session */
        int ret = gnutls_credentials_set(session->tls, GNUTLS_CRD_CERTIFICATE, session->cred);
        if (ret < 0)
        {
            SET_ERROR(err, GNUTLS_ERROR, ret);
            return 0;
        }
        session->need_set_cred = 0;
    }

    /* set field about host */
    if (!init_socket(session, hostname, service, err)) {
        return 0;
    }

    if (!tls_handshake(session, err)) {
        return 0;
    }

    if (!init_sasl(session, err)) {
        return 0;
    }

    if (!send_os(session, err)) {
        return 0;
    }
    session->connected = 1;
    return 1;
}

/**
 * Enable or disabled debug mode
 * 
 * \param session Pointer to client session
 * \param enabled Enable debug if different than zero (1), disable otherwise
 */
void nu_client_set_debug(NuAuth* session, unsigned char enabled)
{
    session->debug_mode = enabled;
}


/**
 * Enable or disabled verbose mode
 * 
 * \param session Pointer to client session
 * \param enabled Enable verbose mode if different than zero (1), disable otherwise
 */
void nu_client_set_verbose(NuAuth* session, unsigned char enabled)
{
    session->verbose = enabled;
}

void ask_session_end(NuAuth* session)
{
    pthread_t self_thread=pthread_self();
    /* we kill thread thus lock will be lost if another thread reach this point */
    
    /* sanity checks */
    if (session == NULL) {
        return;
    }
    if (session->connected == 0){
        return;
    }

    pthread_mutex_lock(&(session->mutex));
    session->connected=0;
    gnutls_bye(session->tls,GNUTLS_SHUT_WR);
    if (session->recvthread != NULL_THREAD && !pthread_equal(session->recvthread,self_thread)) {
        /* destroy thread */
        pthread_cancel(session->recvthread);
        pthread_join(session->recvthread,NULL);
    }
    if (session->server_mode == SRV_TYPE_PUSH) {
        if(session->checkthread != NULL_THREAD && !pthread_equal(session->checkthread,self_thread)){
            pthread_cancel(session->checkthread);
            pthread_join(session->checkthread,NULL);
        }
    }
    pthread_mutex_unlock(&(session->mutex));
    if (pthread_equal(session->recvthread,self_thread) ||
            ((session->server_mode == SRV_TYPE_PUSH) && pthread_equal(session->checkthread,self_thread))
       ) {
        pthread_exit(NULL);
    }
}

/**
 * \ingroup nuclientAPI
 * \brief Allocate a structure to store client error
 */
int nu_client_error_init(nuclient_error **err)
{
    if (*err != NULL)
        return -1;
    *err=malloc(sizeof(nuclient_error));
    if (*err == NULL)
        return -1;
    return 0;
}

/**
 * \ingroup nuclientAPI
 * \brief Destroy an error (free memory)
 */
void nu_client_error_destroy(nuclient_error *err)
{
    if (err!=NULL)
        free(err);
}

/**
 * \ingroup nuclientAPI
 * \brief Convert an error to an human readable string
 */
const char* nu_client_strerror (nuclient_error *err)
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
                case NO_ERR: return "No error";
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
            return "Unknown family error";
    }
}

/** @} */

/* $Id: main.c,v 1.21 2004/02/10 16:09:15 regit Exp $ */

/*
 ** Copyright (C) 2002 - 2005 Eric Leblond <eric@regit.org>
 **		      Vincent Deffontaines <vincent@gryzor.com>
 **                   INL http://www.inl.fr/
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, version 2 of the License.
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

#include "nufw.h"
#include <linux/netfilter.h>
#include <unistd.h>
#include <pthread.h>
#include <netdb.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <sys/types.h>


#define NUFW_PID_FILE  LOCAL_STATE_DIR "/run/nufw.pid"

void nufw_cleanup( int signal ) {
    /* destroy netlink handle */
    ipq_destroy_handle(hndl);
    /* destroy pid file */
    unlink(NUFW_PID_FILE);
    /* exit */
    exit(0);
}

int main(int argc,char * argv[]){
    pthread_t pckt_server,auth_server;
    struct hostent *authreq_srv, *listenaddr_srv;
    /* option */
    char * options_list = "UDhVvmc:k:a:l:L:d:p:t:T:";
    int option,daemonize = 0;
    int value;
    unsigned int ident_srv;
    char* version=PACKAGE_VERSION;
    pid_t pidf;

    struct sigaction act;

    /* initialize variables */

    log_engine = LOG_TO_STD; /* default is to send debug messages to stdout + stderr */
    authreq_port = AUTHREQ_PORT;
    authsrv_port = AUTHSRV_PORT;
    packet_timeout = PACKET_TIMEOUT;
    track_size = TRACK_SIZE;
    id_srv = ID_SERVER;
    nufw_use_tls=1;
    cert_file=NULL;
    key_file=NULL;
    ca_file=NULL;
    strncpy(authreq_addr,AUTHREQ_ADDR,HOSTNAME_SIZE);
    strncpy(listen_addr,LISTEN_ADDR,HOSTNAME_SIZE);
    debug=DEBUG; /* this shall disapear */
    debug_level=0;
    debug_areas=DEFAULT_DEBUG_AREAS;

    /*parse options */
    while((option = getopt ( argc, argv, options_list)) != -1 ){
        switch (option){
          case 'k' :
            key_file=strdup(optarg);
            if (key_file == NULL){
                fprintf(stderr, "Couldn't malloc! Exiting");
                exit(1);
            }
            break;
          case 'c' :
            cert_file=strdup(optarg);
            if (cert_file == NULL){
                fprintf(stderr, "Couldn't malloc! Exiting");
                exit(1);
            }
            break;
        case 'a' :
            ca_file=strdup(optarg);
            if (ca_file == NULL){
                fprintf(stderr, "Couldn't malloc! Exiting");
                exit(1);
            }
            break;
          case 'V' :
            fprintf (stdout, "%s (version %s)\n",PACKAGE_NAME,version);
            return 1;
          case 'D' :
            daemonize = 1;
            break;
          case 'v' :
            /*fprintf (stdout, "Debug should be On\n");*/
            debug_level+=1;
            break;
            /* port we listen for auth answer */
          case 'l' :
            sscanf(optarg,"%d",&value);
            printf("Listening on UDP port %d\n",value);
            authsrv_port=value;
            break;
            /* Listening adress */
          case 'L' :
            strncpy(listen_addr,optarg,HOSTNAME_SIZE);
            printf("Listening on address %s\n",listen_addr);
            break;
            /* destination port */
          case 'p' :
            sscanf(optarg,"%d",&value);
            printf("Auth requests sent to port %d\n",value);
            authreq_port=value;
            break;
            /* destination IP */
          case 'd' :
            strncpy(authreq_addr,optarg,HOSTNAME_SIZE);
            printf("Sending Auth request to %s\n",authreq_addr);
            break;
            /* packet timeout */
          case 't' :
            sscanf(optarg,"%d",&packet_timeout);
            break;
            /* max size of packet list */
          case 'T' :
            sscanf(optarg,"%d",&track_size);
            break;
          case 'I' :
            sscanf(optarg,"%ud",&ident_srv);
            id_srv=ident_srv;
            break;
          case 'm':
            nufw_set_mark=1;
            break;
	  case 'U':
            nufw_use_tls=0;
            break;
          case 'h' :
            fprintf (stdout ,"%s [-hVv[v[v[v[v[v[v[v[v[v]]]]]]]]]] [-l local_port] [-L local_addr] [-d remote_addr] [-p remote_port]  [-t packet_timeout] [-T track_size]\n\
\t-h : display this help and exit\n\
\t-V : display version and exit\n\
\t-D : daemonize\n\
\t-k : use specified file as key file\n\
\t-c : use specified file as cert file\n\
\t-a : use specified file as ca file (strict checking is done if selected) (default: none)\n\
\t-U : use UDP unencrypted communication with nuauth server\n\
\t-v : increase debug level (+1 for each 'v') (max useful number : 10)\n\
\t-m : mark packet with userid\n\
\t-l : specify listening UDP port (default : 4129)\n\
\t-L : specify listening address (default : 127.0.0.1)\n\
\t-d : remote address we send auth requests to (adress of the nuauth server) (default : 127.0.0.1)\n\
\t-p : remote port we send auth requests to (UDP port nuauth server listens on) (default : 4128)\n\
\t-t : timeout to forget about packets when they don't match (default : 15 s)\n\
\t-T : track size (default : 1000)\n",PACKAGE_TARNAME);

            return 1;
        }
    }
    if (getuid())
    {
        printf("nufw must be run as root! Sorry\n");
        return 1;
    }

    /* Daemon code */
    if (daemonize == 1) {
        int i;
        struct sigaction action;
        FILE* pf;

        if (access (NUFW_PID_FILE, R_OK) == 0) {
            /* Check if the existing process is still alive. */
            pid_t pidv;

            pf = fopen (NUFW_PID_FILE, "r");
            if (pf != NULL &&
                fscanf (pf, "%d", &pidv) == 1 &&
                kill (pidv, 0) == 0 ) {
                fclose (pf);
                printf ("pid file exists. Is nufw already running? Aborting!\n");
                exit(-1);
            }

            if (pf != NULL)
                fclose (pf);
        }

        if ((pidf = fork()) < 0){
            syslog(SYSLOG_FACILITY(DEBUG_LEVEL_FATAL),"Unable to fork. Aborting\n");
            exit (-1);
        } else {
            /* parent */
            if (pidf > 0) {
                if ((pf = fopen (NUFW_PID_FILE, "w")) != NULL) {
                    fprintf (pf, "%d\n", (int)pidf);
                    fclose (pf);
                } else {
                    printf ("Dying, can not create PID file : " NUFW_PID_FILE "\n"); 
                    exit(-1);
                }
                exit(0);
            }
        }

        chdir("/");

        setsid();

        for (i = 0; i < FOPEN_MAX ; i++){
            close(i);
        }
        /* intercept SIGTERM */
        action.sa_handler = nufw_cleanup;
        sigemptyset( & (action.sa_mask));
        action.sa_flags = 0;
        if ( sigaction(SIGTERM, & action , NULL ) != 0) {
            printf("Error %d \n",errno);
            exit(1);
        }

        /* set log engine */
        log_engine = LOG_TO_SYSLOG;
    }

    signal(SIGPIPE,SIG_IGN);

    init_log_engine();
    /* create socket for sending auth request */
    sck_auth_request = socket (AF_INET,SOCK_DGRAM,0);

    if (sck_auth_request == -1)
        if (DEBUG_OR_NOT(DEBUG_LEVEL_CRITICAL,DEBUG_AREA_MAIN)){
            if (log_engine == LOG_TO_SYSLOG){
                syslog(SYSLOG_FACILITY(DEBUG_LEVEL_CRITICAL),"socket()");
            }else{
                printf("[%d] socket()",getpid());
            }
        }

#ifdef GRYZOR_HACKS
    /* create socket for sending ICMP messages */
    raw_sock = socket(PF_INET, SOCK_RAW, 1);
    if (raw_sock == -1)
        if (DEBUG_OR_NOT(DEBUG_LEVEL_CRITICAL,DEBUG_AREA_MAIN)){
            if (log_engine == LOG_TO_SYSLOG){
                syslog(SYSLOG_FACILITY(DEBUG_LEVEL_CRITICAL),"socket() on raw_sock");
            }else{
                printf("[%d] socket() on raw_sock",getpid());
            }
        }
#endif


    memset(&adr_srv,0,sizeof adr_srv);

    adr_srv.sin_family= AF_INET;
    adr_srv.sin_port=htons(authreq_port);
    /* hostname conversion */
    authreq_srv=gethostbyname(authreq_addr);
    adr_srv.sin_addr=*(struct in_addr *)authreq_srv->h_addr;

    if (adr_srv.sin_addr.s_addr == INADDR_NONE )
        if (DEBUG_OR_NOT(DEBUG_LEVEL_CRITICAL,DEBUG_AREA_MAIN)){
            if (log_engine == LOG_TO_SYSLOG){
                syslog(SYSLOG_FACILITY(DEBUG_LEVEL_CRITICAL),"Bad Address in configuration for adr_srv");
            }else{
                printf("[%d] Bad Address in configuration for adr_srv",getpid());
            }
        }
    if (nufw_use_tls == 0){
        memset(&list_srv,0,sizeof list_srv);
        listenaddr_srv=gethostbyname(listen_addr);
        list_srv.sin_addr=*(struct in_addr *)listenaddr_srv->h_addr;

        if (list_srv.sin_addr.s_addr == INADDR_NONE )
            if (DEBUG_OR_NOT(DEBUG_LEVEL_CRITICAL,DEBUG_AREA_MAIN)){
                if (log_engine == LOG_TO_SYSLOG){
                    syslog(SYSLOG_FACILITY(DEBUG_LEVEL_CRITICAL),"Bad Listening Address in configuration");
                }else{
                    printf("[%d] Bad Listening Address in configuration",getpid());
                }
            }
        list_srv.sin_addr.s_addr = INADDR_ANY;
    }
    packets_list_start=NULL;
    packets_list_end=NULL;
    packets_list_length=0;
    /* initialize mutex */
    pthread_mutex_init(&packets_list_mutex ,NULL);

    /* init netlink connection */
    hndl = ipq_create_handle(0,PF_INET);
    if (hndl)
        ipq_set_mode(hndl, IPQ_COPY_PACKET,BUFSIZ);  
    else {
        if (DEBUG_OR_NOT(DEBUG_LEVEL_CRITICAL,DEBUG_AREA_MAIN)){
            if (log_engine == LOG_TO_SYSLOG){
                syslog(SYSLOG_FACILITY(DEBUG_LEVEL_CRITICAL),"Could not create ipq handle");
            }else{
                printf("[%d] Could not create ipq handle\n",getpid());
            }
        }
    }

    if (nufw_use_tls){
        tls.session=NULL;
        tls.active=0;

        gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
        gnutls_global_init();
    }
    /* create thread for packet server */
    if (pthread_create(&pckt_server,NULL,packetsrv,NULL) == EAGAIN){
        exit(1);
    }
    /* create thread for auth server */
    if (pthread_create(&auth_server,NULL,authsrv,NULL) == EAGAIN){
        exit(1);
    }

    act.sa_handler = &process_usr1;
    act.sa_restorer = NULL;
    act.sa_flags = SIGUSR1;
    if (sigaction(SIGUSR1,&act,NULL) == -1)
    {
        printf("Could not set signal USR1");
        exit(1);
    }

    act.sa_handler = &process_usr2;
    act.sa_restorer = NULL;
    act.sa_flags = SIGUSR2;
    if (sigaction(SIGUSR2,&act,NULL) == -1)
    {
        printf("Could not set signal USR2");
        exit(1);
    }

    act.sa_handler = &process_poll;
    act.sa_restorer = NULL;
    act.sa_flags = SIGPOLL;
    if (sigaction(SIGPOLL,&act,NULL) == -1)
    {
        printf("Could not set signal POLL");
        exit(1);
    }

    /* control stuff */
    pckt_tx=pckt_rx=0;
    for(;;){
        pthread_mutex_lock(&packets_list_mutex);
        clean_old_packets ();
        pthread_mutex_unlock(&packets_list_mutex);
        if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN)){
            if (log_engine == LOG_TO_SYSLOG){
                syslog(SYSLOG_FACILITY(DEBUG_LEVEL_INFO),"rx : %d, tx : %d, track_size : %d, start_list : %p",pckt_rx,pckt_tx,packets_list_length,packets_list_start);
            }else{
                printf("[%i] rx : %d, tx : %d, track_size : %d, start_list : %p\n",getpid(),pckt_rx,pckt_tx,packets_list_length,packets_list_start);
            }
        }

        sleep(5);	
    }
}

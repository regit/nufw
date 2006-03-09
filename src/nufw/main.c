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

/** \file main.c
 *  \brief Function main() 
 *   
 * See function main().
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

GCRY_THREAD_OPTION_PTHREAD_IMPL;

/*! Name of pid file prefixed by LOCAL_STATE_DIR (variable defined 
 * during compilation/installation) */
#define NUFW_PID_FILE  LOCAL_STATE_DIR "/run/nufw.pid"

/**
 * Cleanup before leaving:
 *   - Destroy netfilter queue/handler
 *   - Close conntrack
 *   - Unlink pid file
 *   - Call exit(EXIT_SUCCESS)
 */
void nufw_cleanup( int signal ) {
    /* destroy netlink handle */
#if USE_NFQUEUE
        nfq_destroy_queue(hndl);
        nfq_unbind_pf(h, AF_INET);
#else
    ipq_destroy_handle(hndl);
#endif
#ifdef HAVE_LIBCONNTRACK
    nfct_close(cth);
#endif
    /* destroy pid file */
    unlink(NUFW_PID_FILE);
    exit(EXIT_SUCCESS);
}

/**
 * Main function of NuFW:
 *   - Initialize variables
 *   - Parse command line options
 *   - Dameonize it if nequired
 *   - Initialize log engine (see init_log_engine()).
 *   - Initialiaze mutex
 *   - Create TLS tunnel
 *   - Install signal handlers:
 *      - Ignore SIGPIPE
 *      - SIGTERM quit the program (see nufw_cleanup())
 *      - SIGUSR1 increase debug verbosity (see process_usr1())
 *      - SIGUSR2 decrease debug verbosity (see process_usr2())
 *      - SIGPOLL display statistics (see process_poll())
 *   - Open conntrack
 *   - Create packet server thread: packetsrv()
 *   - Run main loop 
 *
 * When NuFW is running, main loop and two threads (packetsrv() and 
 * authsrv()) and  are running.
 * 
 * The most interresting things are done in the packet server (thread
 * packetsrv()). The main loop just clean up old packets and display
 * statistics. 
 */
int main(int argc,char * argv[]){
    pthread_t pckt_server;
    struct hostent *authreq_srv;
    /* option */
#if USE_NFQUEUE
    char * options_list = "DhVvmq:c:k:a:n:d:p:t:T:C";
#else
    char * options_list = "DhVvmc:k:a:n:d:p:t:T:";
#endif
    int option,daemonize = 0;
    int value;
    char* version=PACKAGE_VERSION;
    pid_t pidf;

    struct sigaction act;

    /* initialize variables */

    log_engine = LOG_TO_STD; /* default is to send debug messages to stdout + stderr */
    authreq_port = AUTHREQ_PORT;
    packet_timeout = PACKET_TIMEOUT;
    track_size = TRACK_SIZE;
    cert_file=NULL;
    key_file=NULL;
    ca_file=NULL;
    nuauth_cert_dn=NULL;
    SECURE_STRNCPY(authreq_addr, AUTHREQ_ADDR, sizeof authreq_addr);
    debug_level=0;
    debug_areas=DEFAULT_DEBUG_AREAS;
#if USE_NFQUEUE
    nfqueue_num=DEFAULT_NFQUEUE;
#if HAVE_LIBCONNTRACK
    handle_conntrack_event=CONNTRACK_HANDLE_DEFAULT;
#endif
#endif
    nufw_set_mark = 0;
    
    /*parse options */
    while((option = getopt ( argc, argv, options_list)) != -1 ){
        switch (option){
          case 'k' :
            key_file=strdup(optarg);
            if (key_file == NULL){
                fprintf(stderr, "Couldn't malloc! Exiting");
                exit(EXIT_FAILURE);
            }
            break;
          case 'c' :
            cert_file=strdup(optarg);
            if (cert_file == NULL){
                fprintf(stderr, "Couldn't malloc! Exiting");
                exit(EXIT_FAILURE);
            }
            break;
          case 'a' :
            ca_file=strdup(optarg);
            if (ca_file == NULL){
                fprintf(stderr, "Couldn't malloc! Exiting");
                exit(EXIT_FAILURE);
            }
            break;
          case 'n' :
            nuauth_cert_dn=strdup(optarg);
            if (nuauth_cert_dn == NULL){
                fprintf(stderr, "Couldn't malloc! Exiting");
                exit(EXIT_FAILURE);
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
          case 'p' :
            sscanf(optarg,"%d",&value);
            printf("Auth requests sent to port %d\n",value);
            authreq_port=value;
            break;
            /* destination IP */
          case 'd' :
            SECURE_STRNCPY(authreq_addr, optarg, sizeof authreq_addr);
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
          case 'm':
            nufw_set_mark=1;
            break;
#if USE_NFQUEUE
          case 'q':
            sscanf(optarg,"%hu",&nfqueue_num);
            break;
          case 'C':
#if HAVE_LIBCONNTRACK
                handle_conntrack_event=1;
#endif
            break;
#endif
          case 'h' :
            fprintf (stdout ,"%s [-hVcCv[v[v[v[v[v[v[v[v[v]]]]]]]]]] [-d remote_addr] [-p remote_port]  [-t packet_timeout] [-T track_size]\n\
\t-h : display this help and exit\n\
\t-V : display version and exit\n\
\t-D : daemonize\n\
\t-k : use specified file as key file\n\
\t-c : use specified file as cert file\n\
\t-a : use specified file as ca file (strict checking is done if selected) (default: none)\n\
\t-n : use specified string as the needed DN of nuauth (inforce certificate checking) (default: none)\n\
\t-v : increase debug level (+1 for each 'v') (max useful number : 10)\n\
\t-m : mark packet with userid (needed for connection expiration)\n"
#ifdef HAVE_LIBCONNTRACK
"\t-C : listen to conntrack events (needed for connection expiration)\n"
#endif
"\t-d : remote address we send auth requests to (adress of the nuauth server) (default : 127.0.0.1)\n\
\t-p : remote port we send auth requests to (TCP port nuauth server listens on) (default : 4128)\n"
#if USE_NFQUEUE
		"\t-q : use nfqueue number (default : 0)\n"
#endif
                "\t-t : timeout to forget about packets when they don't match (default : 15 s)\n\
\t-T : track size (default : 1000)\n",PACKAGE_TARNAME);

            exit(EXIT_SUCCESS);
        }
    }
   
    if (getuid())
    {
        printf("nufw must be run as root! Sorry\n");
        exit (EXIT_FAILURE);
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
                exit(EXIT_FAILURE);
            }

            if (pf != NULL)
                fclose (pf);
        }

        if ((pidf = fork()) < 0){
            log_printf (DEBUG_LEVEL_FATAL, "Unable to fork. Aborting!");
            exit (-1);
        } else {
            /* parent */
            if (pidf > 0) {
                if ((pf = fopen (NUFW_PID_FILE, "w")) != NULL) {
                    fprintf (pf, "%d\n", (int)pidf);
                    fclose (pf);
                } else {
                    printf ("Dying, can not create PID file : " NUFW_PID_FILE "\n"); 
                    exit(EXIT_FAILURE);
                }
                exit(EXIT_SUCCESS);
            }
        }

        chdir("/");

        setsid();

        for (i = 0; i < FOPEN_MAX ; i++){
            close(i);
        }
        /* intercept SIGTERM */
    	memset(&action,0,sizeof(action));
        action.sa_handler = nufw_cleanup;
        sigemptyset( & (action.sa_mask));
        action.sa_flags = 0;
        if ( sigaction(SIGTERM, & action , NULL ) != 0) {
            printf("Error %d \n",errno);
            exit(EXIT_FAILURE);
        }

        /* set log engine */
        log_engine = LOG_TO_SYSLOG;
    }

    signal(SIGPIPE,SIG_IGN);

    init_log_engine();

#ifdef GRYZOR_HACKS
    /* create socket for sending ICMP messages */
    raw_sock = socket(PF_INET, SOCK_RAW, 1);
    if (raw_sock == -1)
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL, 
                "socket() on raw_sock creation failure!");
#endif

    /* Create address adr_srv */
    memset(&adr_srv,0,sizeof adr_srv);
    adr_srv.sin_family = AF_INET;
    adr_srv.sin_port = htons(authreq_port);
    /* hostname conversion */
    authreq_srv=gethostbyname(authreq_addr);
    if (authreq_srv == NULL) {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL, 
                "Can not resolve NuAuth hostname \"%s\"!", authreq_addr);
        exit(EXIT_FAILURE);
    }
    adr_srv.sin_addr=*(struct in_addr *)authreq_srv->h_addr;
    if (adr_srv.sin_addr.s_addr == INADDR_NONE ) {
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_CRITICAL, 
                "Bad Address in configuration for adr_srv");
    }
    
    packets_list.start=NULL;
    packets_list.end=NULL;
    packets_list.length=0;
    /* initialize mutex */
    pthread_mutex_init(&packets_list.mutex ,NULL);

    tls.session=NULL;
    tls.auth_server_running=1;
    tls.mutex=(pthread_mutex_t*)calloc(1,sizeof(pthread_mutex_t));
    pthread_mutex_init(tls.mutex,NULL);
    gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
    gnutls_global_init();
    
    memset(&act,0,sizeof(act));
    act.sa_handler = &process_usr1;
    act.sa_flags = SIGUSR1;
    if (sigaction(SIGUSR1,&act,NULL) == -1)
    {
        printf("Could not set signal USR1");
        exit(EXIT_FAILURE);
    }

    memset(&act,0,sizeof(act));
    act.sa_handler = &process_usr2;
    act.sa_flags = SIGUSR2;
    if (sigaction(SIGUSR2,&act,NULL) == -1)
    {
        printf("Could not set signal USR2");
        exit(EXIT_FAILURE);
    }

    memset(&act,0,sizeof(act));
    act.sa_handler = &process_poll;
    act.sa_flags = SIGPOLL;
    if (sigaction(SIGPOLL,&act,NULL) == -1)
    {
        printf("Could not set signal POLL");
        exit(EXIT_FAILURE);
    }

#ifdef HAVE_LIBCONNTRACK
    cth = nfct_open(CONNTRACK, 0);
#endif

    /* create packet server thread */
    if (pthread_create(&pckt_server,NULL,packetsrv,NULL) == EAGAIN){
        exit(EXIT_FAILURE);
    }

    /* control stuff */
    pckt_tx=pckt_rx=0;
    for(;;){
        pthread_mutex_lock(&packets_list.mutex);
        clean_old_packets ();
        pthread_mutex_unlock(&packets_list.mutex);
        log_area_printf (DEBUG_AREA_MAIN, DEBUG_LEVEL_INFO, 
                "rx : %d, tx : %d, track_size : %d, start_list : %p",
                pckt_rx, pckt_tx, packets_list.length, packets_list.start);
        sleep(5);	
    }
}



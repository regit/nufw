/* $Id: main.c,v 1.16 2003/11/07 19:08:11 regit Exp $ */

/*
 ** Copyright (C) 2002 Eric Leblond <eric@regit.org>
 **		      Vincent Deffontaines <vincent@gryzor.com>
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



#include <linux/netfilter.h>
#include <libipq/libipq.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netdb.h>
#include <structure.h>
#include <debug.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>


//#define NUFW_PID_FILE  "/var/run/nufw.pid"
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
    struct hostent *authreq_srv;
    /* option */
    char * options_list = "DhVvml:d:p:t:T:";
    int option,daemonize = 0;
    int value;
    unsigned int ident_srv;
    char* version=VERSION;

    /* initialize variables */

    log_engine = LOG_TO_STD; /* default is to send debug messages to stdout + stderr */
    authreq_port = AUTHREQ_PORT;
    authsrv_port = AUTHSRV_PORT;
    packet_timeout = PACKET_TIMEOUT;
    track_size = TRACK_SIZE;
    id_srv = ID_SERVER;
    strncpy(authreq_addr,AUTHREQ_ADDR,HOSTNAME_SIZE);
    debug=DEBUG; /* this shall disapear */
    debug_level=0;
    debug_areas=DEFAULT_DEBUG_AREAS;
    pid_t pidf;

    /*parse options */
    while((option = getopt ( argc, argv, options_list)) != -1 ){
        switch (option){
          case 'V' :
            fprintf (stdout, "PACKAGE (version %s)\n",version);
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
            printf("Listen on UDP port %d\n",value);
            authsrv_port=value;
            break;
            /* destination port */
          case 'p' :
            sscanf(optarg,"%d",&value);
            printf("Auth request send to port %d\n",value);
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
          case 'h' :
            fprintf (stdout ,"PACKAGE [-hVv[v[v[v[v[v[v[v[v[v]]]]]]]]]] [-l local_port] [-d remote_addr] [-p remote_port]  [-t packet_timeout] [-T track_size]\n\
                \t-h : display this help and exit\n\
                \t-V : display version and exit\n\
                \t-D : daemonize\n\
                \t-v : increase debug level (+1 for each 'v') (max useful number : 10)\n\
                \t-m : mark packet with userid\n\
                \t-l : specify listening UDP port (default : 4129)\n\
                \t-d : remote address we send auth requests to (adress of the nuauth server)\n\
                \t-p : remote port we send auth requests to (UDP port nuauth server listens on) (default : 4128)\n\
                \t-t : timeout to forget about packets when they don't match (default : 15 s)\n\
                \t-T : track size (default : 1000)\n");

            return 1;
        }
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
                printf ("nufw already running. Aborting!\n");
                exit(-1);
            }

            if (pf != NULL)
                fclose (pf);
        }

	printf("PID file : " NUFW_PID_FILE " \n");

        if ((pidf = fork()) < 0){
            syslog(SYSLOG_FACILITY(DEBUG_LEVEL_FATAL),"Unable to fork\n");
            exit (-1);
        } else {
            /* parent */
            if (pidf > 0) {
                if ((pf = fopen (NUFW_PID_FILE, "w")) != NULL) {
                    fprintf (pf, "%d\n", (int)pidf);
                    fclose (pf);
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

    init_log_engine();
    if (DEBUG_OR_NOT(DEBUG_LEVEL_CRITICAL,DEBUG_AREA_MAIN))
        syslog (SYSLOG_FACILITY(DEBUG_LEVEL_CRITICAL),"tamere\n");
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


    memset(&adr_srv,0,sizeof adr_srv);

    adr_srv.sin_family= AF_INET;
    adr_srv.sin_port=htons(authreq_port);
    /* hostname conversion */
    authreq_srv=gethostbyname(authreq_addr);
    adr_srv.sin_addr=*(struct in_addr *)authreq_srv->h_addr;

    if (adr_srv.sin_addr.s_addr == INADDR_NONE )
        if (DEBUG_OR_NOT(DEBUG_LEVEL_CRITICAL,DEBUG_AREA_MAIN)){
            if (log_engine == LOG_TO_SYSLOG){
                syslog(SYSLOG_FACILITY(DEBUG_LEVEL_CRITICAL),"Bad Address.");
            }else{
                printf("[%d] Bad Address.",getpid());
            }
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
                syslog(SYSLOG_FACILITY(DEBUG_LEVEL_CRITICAL),"Can not create ipq handle");
            }else{
                printf("[%d] Can not create ipq handle\n",getpid());
            }
        }
    }

    /* create thread for packet server */
    if (pthread_create(&pckt_server,NULL,packetsrv,NULL) == EAGAIN){
        exit(1);
    }
    /* create thread for auth server */
    if (pthread_create(&auth_server,NULL,authsrv,NULL) == EAGAIN){
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

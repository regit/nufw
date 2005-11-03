/*
 ** Copyright (C) 2005 - INL 
 ** Written by Eric Leblond <regit@inl.fr>
 **            INL http://www.inl.fr/
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

#define NUCONNTRACK_PID_FILE  LOCAL_STATE_DIR "/run/nuconntrack.pid"

void nuconntrack_cleanup( int signal ) {
    /* TODO destroy conntrack handle */
     nfqnl_destroy_queue(hndl);
     nfqnl_unbind_pf(h, AF_INET);
     /* TODO close mysql connection */
     
    /* destroy pid file */
    unlink(NUFW_PID_FILE);
    /* exit */
    exit(0);
}

int main(int argc,char * argv[]){
    pthread_t sql_worker;
    struct hostent *authreq_srv;
    /* option */
    char * options_list = "Dhvd:u:p:t:";
    int option,daemonize = 0;
    int value;
    unsigned int ident_srv;
    char* version=PACKAGE_VERSION;
    pid_t pidf;

    struct sigaction act;

    /* initialize variables */

    log_engine = LOG_TO_STD; /* default is to send debug messages to stdout + stderr */
    packet_timeout = PACKET_TIMEOUT;
    track_size = TRACK_SIZE;
    strncpy(authreq_addr,AUTHREQ_ADDR,HOSTNAME_SIZE);
    debug=DEBUG; /* this shall disapear */
    debug_level=0;
    debug_areas=DEFAULT_DEBUG_AREAS;
    
    /*parse options */
    while((option = getopt ( argc, argv, options_list)) != -1 ){
        switch (option){
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
          case 'h' :
            fprintf (stdout ,"%s [-hVv[v[v[v[v[v[v[v[v[v]]]]]]]]]] [-d remote_addr] [-p remote_port]  [-t packet_timeout]\n\
\t-h : display this help and exit\n\
\t-V : display version and exit\n\
\t-D : daemonize\n\
\t-v : increase debug level (+1 for each 'v') (max useful number : 10)\n\
\t-d : remote address we send auth requests to (adress of the nuauth server) (default : 127.0.0.1)\n\
\t-p : remote port we send auth requests to (TCP port nuauth server listens on) (default : 4128)\n"
                "\t-t : timeout to forget about packets when they don't match (default : 15 s)\n\
",PACKAGE_TARNAME);
            return 1;
        }
    }
    if (getuid())
    {
        printf("nuconntrack must be run as root! Sorry\n");
        return 1;
    }

    /* Daemon code */
    if (daemonize == 1) {
        int i;
        struct sigaction action;
        FILE* pf;

        if (access (NUCONNTRACK_PID_FILE, R_OK) == 0) {
            /* Check if the existing process is still alive. */
            pid_t pidv;

            pf = fopen (NUCONNTRACK_PID_FILE, "r");
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
                if ((pf = fopen (NUCONNTRACK_PID_FILE, "w")) != NULL) {
                    fprintf (pf, "%d\n", (int)pidf);
                    fclose (pf);
                } else {
                    printf ("Dying, can not create PID file : " NUCONNTRACK_PID_FILE "\n"); 
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
    	memset(&action,0,sizeof(action));
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

    memset(&adr_srv,0,sizeof adr_srv);

    /* create thread for packet server */
    if (pthread_create(&sql_worker,NULL,mysql_work,NULL) == EAGAIN){
        exit(1);
    }

    memset(&act,0,sizeof(act));
    act.sa_handler = &process_usr1;
    act.sa_flags = SIGUSR1;
    if (sigaction(SIGUSR1,&act,NULL) == -1)
    {
        printf("Could not set signal USR1");
        exit(1);
    }

    memset(&act,0,sizeof(act));
    act.sa_handler = &process_usr2;
    act.sa_flags = SIGUSR2;
    if (sigaction(SIGUSR2,&act,NULL) == -1)
    {
        printf("Could not set signal USR2");
        exit(1);
    }

    memset(&act,0,sizeof(act));
    act.sa_handler = &process_poll;
    act.sa_flags = SIGPOLL;
    if (sigaction(SIGPOLL,&act,NULL) == -1)
    {
        printf("Could not set signal POLL");
        exit(1);
    }

	cth = nfct_open(CONNTRACK, event_mask);
				if (!cth)
					exit_error(OTHER_PROBLEM, 
						   "Not enough memory");
				signal(SIGINT, event_sighandler);
				nfct_set_callback(cth, handler);
				res = nfct_event_conntrack(cth);
}

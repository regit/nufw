/*
 ** Copyright (C) 2005 - INL 
 ** Written by Vincent Deffontaines <gryzor@inl.fr>
 **            Eric Leblond <regit@inl.fr>
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


#include "nutrackd.h"

#define NUTRACKD_PID_FILE  LOCAL_STATE_DIR "/run/nutrackd.pid"

void nutrackd_cleanup( int signal ) {
    /* TODO destroy conntrack handle */
//     nfqnl_destroy_queue(hndl);
//     nfqnl_unbind_pf(h, AF_INET);
     /* TODO close mysql connection(s) */
     
    /* destroy pid file */
    unlink(NUTRACKD_PID_FILE);
    /* exit */
    exit(0);
}

nfct_callback *update_handler(void *arg, unsigned int flags, int type)
{
  struct nfct_conntrack *conn = arg;
  // arg is a nfct_conntrack object - we can parse it directly
//  u_int8_t proto = conn->tuple[0].protonum;
//  u_int32_t src = conn->tuple[0].src.v4;
//  u_int32_t dst = conn->tuple[0].dst.v4;
  u_int16_t sport = 0;
  u_int16_t dport = 0;

  switch (conn->tuple[0].protonum){
        case IPPROTO_TCP :
          sport = conn->tuple[0].l4src.tcp.port;
          dport = conn->tuple[0].l4dst.tcp.port;
        break;
        case IPPROTO_UDP :
          sport = conn->tuple[0].l4src.udp.port;
          dport = conn->tuple[0].l4dst.udp.port;
        break;
        default :
          sport = 0;
          dport = 0;
        break;
  }
  if (update_sql_table(conn->tuple[0].src.v4,
                       conn->tuple[0].dst.v4,
                       conn->tuple[0].protonum,
                       sport,
                       dport)) //This prototype sucks
  {
      //log shit
  }
}

int main(int argc,char * argv[]){
    pthread_t sql_worker;
//    struct hostent *authreq_srv;
    /* options */
    char * options_list = "Dhvd:u:p:t:";
    int option,daemonize = 0;
    int value;
    unsigned int ident_srv;
    char* version=PACKAGE_VERSION;
    pid_t pidf;
    int packet_timeout;
    int res;
    struct nfct_handle *cth;

//    struct sigaction act;

    /* initialize variables */

    log_engine = LOG_TO_STD; /* default is to send debug messages to stdout + stderr */
    packet_timeout = PACKET_TIMEOUT;
//    strncpy(authreq_addr,AUTHREQ_ADDR,HOSTNAME_SIZE);
//    debug=DEBUG; /* this shall disapear */
    debug_level=0;
    
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
            /* packet timeout */
          case 't' :
            sscanf(optarg,"%d",&packet_timeout);
            break;
            /* max size of packet list */
          case 'h' :
            fprintf (stdout ,"%s [-hVv[v[v[v[v[v[v[v[v[v]]]]]]]]]] [-t packet_timeout]\n\
\t-h : display this help and exit\n\
\t-V : display version and exit\n\
\t-D : daemonize\n\
\t-v : increase debug level (+1 for each 'v') (max useful number : 10)\n", PACKAGE_NAME);
            return 1;
        }
    }
    if (getuid())
    {
        printf("nutrackd must be run as root! Sorry\n");
        return 1;
    }

    /* Daemon code */
    if (daemonize == 1) {
        int i;
        struct sigaction action;
        FILE* pf;

        if (access (NUTRACKD_PID_FILE, R_OK) == 0) {
            /* Check if the existing process is still alive. */
            pid_t pidv;

            pf = fopen (NUTRACKD_PID_FILE, "r");
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
                if ((pf = fopen (NUTRACKD_PID_FILE, "w")) != NULL) {
                    fprintf (pf, "%d\n", (int)pidf);
                    fclose (pf);
                } else {
                    printf ("Dying, can not create PID file : " NUTRACKD_PID_FILE "\n"); 
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
        action.sa_handler = nutrackd_cleanup;
        sigemptyset( & (action.sa_mask));
        action.sa_flags = 0;
        if ( sigaction(SIGTERM, & action , NULL ) != 0) {
            printf("Error %d \n",errno);
            exit(1);
        }

        /* set log engine */
//        log_engine = LOG_TO_SYSLOG;
    }

//    signal(SIGPIPE,SIG_IGN);

//    init_log_engine();
    /* create socket for sending auth request */
//    sck_auth_request = socket (AF_INET,SOCK_DGRAM,0);
//
//    if (sck_auth_request == -1)
//        if (DEBUG_OR_NOT(DEBUG_LEVEL_CRITICAL,DEBUG_AREA_MAIN)){
//            if (log_engine == LOG_TO_SYSLOG){
//                syslog(SYSLOG_FACILITY(DEBUG_LEVEL_CRITICAL),"socket()");
//            }else{
//                printf("[%d] socket()",getpid());
//            }
//        }


    cth = nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_DESTROY);
    if (!cth)
      fprintf(stderr,"%s : Not enough memory",PACKAGE_NAME);
//    signal(SIGINT, event_sighandler);
    nfct_register_callback(cth, update_handler,NULL);
    res = nfct_event_conntrack(cth);
}

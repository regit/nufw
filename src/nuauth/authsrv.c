
/*
 ** Copyright(C) 2003 Eric Leblond <eric@regit.org>
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

#include <auth_srv.h>

#ifndef _NUAUTHVARS
#define _NUAUTHVARS
confparams nuauth_vars[] = {
    { "nuauth_client_listen_addr" ,  G_TOKEN_STRING, 0 , AUTHREQ_CLIENT_LISTEN_ADDR },
    { "nuauth_nufw_listen_addr" ,  G_TOKEN_STRING, 0 , AUTHREQ_NUFW_LISTEN_ADDR },
    { "nuauth_gw_packet_port" , G_TOKEN_INT , AUTHREQ_PORT,NULL },
    { "nuauth_user_packet_port" , G_TOKEN_INT , AUTHREQ_PORT ,NULL},
    { "nufw_gw_addr" , G_TOKEN_STRING , 0, GWSRV_ADDR },
    { "nufw_gw_port" , G_TOKEN_INT , GWSRV_PORT, NULL },
    { "nuauth_prio" , G_TOKEN_INT , PRIO , NULL},
    { "nuauth_packet_timeout" , G_TOKEN_INT , PACKET_TIMEOUT, NULL },
    { "nuauth_number_usercheckers" , G_TOKEN_INT , NB_USERCHECK, NULL},
    { "nuauth_number_aclcheckers" , G_TOKEN_INT , NB_ACLCHECK, NULL },
    { "nuauth_number_loggers" , G_TOKEN_INT , NB_ACLCHECK, NULL },
    { "nuauth_log_users" , G_TOKEN_INT , 1, NULL },
    { "nuauth_user_check_module" , G_TOKEN_STRING , 1, NULL },
    { "nuauth_acl_check_module" , G_TOKEN_STRING , 1, NULL },
    { "nuauth_user_logs_module" , G_TOKEN_STRING , 1, NULL },
    { "nuauth_prio_to_nok" , G_TOKEN_INT , 1, NULL }
};
#endif 


#define NUAUTH_PID_FILE  LOCAL_STATE_DIR "/run/nuauth/nuauth.pid"

void nuauth_cleanup( int signal ) {
    /* destroy pid file */
    unlink(NUAUTH_PID_FILE);
    /* exit */
    exit(0);
}



int main(int argc,char * argv[]) {
    GThread * pckt_server, * auth_server;
    /* option */
    char * options_list = "DhVvl:L:C:d:p:t:T:";
    int option,daemonize = 0;
    int value;
    char* nuauth_client_listen_addr=AUTHREQ_CLIENT_LISTEN_ADDR;
    char* nuauth_nufw_listen_addr=AUTHREQ_NUFW_LISTEN_ADDR;
    char* version=VERSION;
    char* gwsrv_addr=GWSRV_ADDR;
    char *configfile=DEFAULT_CONF_FILE;
    int nbacl_check=NB_ACLCHECK;
    int nbuser_check=NB_USERCHECK;
    int nuauth_number_loggers=NB_ACLCHECK;
    char * nuauth_acl_check_module=DEFAULT_AUTH_MODULE;
    char * nuauth_user_check_module=DEFAULT_AUTH_MODULE;
    char * nuauth_user_logs_module=DEFAULT_LOGS_MODULE;
    gpointer vpointer;
    pid_t pidf;
    struct hostent *nufw_list_srv, *client_list_srv;

    /* initialize variables */

    authreq_port = AUTHREQ_PORT;
    gwsrv_port = GWSRV_PORT;
    userpckt_port = USERPCKT_PORT; 
    packet_timeout = PACKET_TIMEOUT;
    nuauth_prio_to_nok= PRIO_TO_NOK;
    //    strncpy(client_listen_address,CLIENT_LISTEN_ADDR,HOSTNAME_SIZE);
    //    strncpy(nufw_listen_address,NUFW_LISTEN_ADDR,HOSTNAME_SIZE);
    /* 
     * Minimum debug_level value is 2 -> for 1) fatal and 2) critical messages to always
     * be outputed
     */
    debug_level=0;
    debug_areas=DEFAULT_DEBUG_AREAS;

    /* parse conf file */
    parse_conffile(configfile,sizeof(nuauth_vars)/sizeof(confparams),nuauth_vars);
    /* set variable value from config file */

    vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_client_listen_addr");
    nuauth_client_listen_addr=(char *)(vpointer?vpointer:nuauth_client_listen_addr);
    vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_nufw_listen_addr");
    nuauth_nufw_listen_addr=(char *)(vpointer?vpointer:nuauth_nufw_listen_addr);
    vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nufw_gw_addr");
    gwsrv_addr=(char*)(vpointer?vpointer:gwsrv_addr);
    vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_gw_packet_port");
    authreq_port=*(int*)(vpointer?vpointer:&authreq_port);
    vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nufw_gw_port");
    gwsrv_port=*(int*)(vpointer?vpointer:&gwsrv_port);
    vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_user_packet_port");
    userpckt_port=*(int*)(vpointer?vpointer:&userpckt_port);
    vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_number_usercheckers");
    nbuser_check=*(int*)(vpointer?vpointer:&nbuser_check);
    vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_number_aclcheckers");
    nbacl_check=*(int*)(vpointer?vpointer:&nbacl_check);
    vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_log_users");
    nuauth_log_users=*(int*)(vpointer?vpointer:&nuauth_log_users);
    vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_user_check_module");
    nuauth_user_check_module=(char*)(vpointer?vpointer:nuauth_user_check_module);
    vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_acl_check_module");
    nuauth_acl_check_module=(char*)(vpointer?vpointer:nuauth_acl_check_module);

    vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_prio_to_nok");
    nuauth_prio_to_nok=*(int*)(vpointer?vpointer:&nuauth_prio_to_nok);

    vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_user_logs_module");
    nuauth_user_logs_module=(char*)(vpointer?vpointer:nuauth_user_logs_module);

    vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_number_loggers");
    nuauth_number_loggers=*(int*)(vpointer?vpointer:nuauth_number_loggers);

    vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_packet_timeout");
    packet_timeout=*(int*)(vpointer?vpointer:packet_timeout);

    /*parse options */
    while((option = getopt ( argc, argv, options_list)) != -1 ){
        switch (option){
          case 'V' :
            fprintf (stdout, "nuauth (version %s)\n",version);
            return 1;
          case 'v' :
            /*fprintf (stdout, "Debug should be On (++)\n");*/
            debug_level+=1;
            break;
            /* port we listen for auth answer */
          case 'l' :
            sscanf(optarg,"%d",&value);
            printf("Listen on UDP port for user packet %d\n",value);
            userpckt_port=value;
            break;
            /* Adress we listen for NUFW originating packets */
          case 'L' :
            // strncpy(nufw_listen_address,optarg,HOSTNAME_SIZE);
            free(nuauth_nufw_listen_addr);
            nuauth_nufw_listen_addr = (char *)malloc(HOSTNAME_SIZE);
            if (nuauth_nufw_listen_addr == NULL){return -1;}
            strncpy(nuauth_nufw_listen_addr,optarg,HOSTNAME_SIZE);
            printf("Waiting for Nufw daemon packets on %s\n",nuauth_nufw_listen_addr);
            //printf("Waiting for Nufw daemon packets on %s\n",nufw_listen_address);
            break;
            /* Adress we listen for NUFW originating packets */
          case 'C' :
            //strncpy(client_listen_address,optarg,HOSTNAME_SIZE);
            free(nuauth_client_listen_addr);
            nuauth_client_listen_addr = (char *)malloc(HOSTNAME_SIZE);
            if (nuauth_client_listen_addr == NULL){return -1;}
            strncpy(nuauth_client_listen_addr,optarg,HOSTNAME_SIZE);
            printf("Waiting for clients auth packets on %s\n",nuauth_client_listen_addr);
            //printf("Waiting for clients auth packets on %s\n",client_listen_address);
            break;
            /* destination port */
          case 'p' :
            sscanf(optarg,"%d",&value);
            printf("Auth Answer sent to gw on port %d\n",value);
            gwsrv_port=value;
            break;
            /* destination IP */
          case 'd' :
            strncpy(gwsrv_addr,optarg,HOSTNAME_SIZE);
            printf("Sending Auth Answer to gw at %s\n",gwsrv_addr);
            break;
            /* packet timeout */
          case 't' :
            sscanf(optarg,"%d",&packet_timeout);
            break;
            /* max size of packet list */
          case 'D' :
            daemonize=1;
            break;
          case 'h' :
            fprintf (stdout ,"nuauth [-hDVv[v[v[v[v[v[v[v[v]]]]]]]]] [-l user_packet_port] [-C local_addr] [-L local_addr] \n\
                \t\t[-d nufw_gw_addr] [-p nufw_gw_port]  [-t packet_timeout]\n\
                \t-h : display this help and exit\n\
                \t-D : run as a daemon, send debug messages to syslog (else stdout/stderr)\n\
                \t-V : display version and exit\n\
                \t-v : increase debug level (+1 for each 'v') (max useful number : 10)\n\
                \t-l : specify listening UDP port (this port waits for clients, not nuauth) (default : 4130)\n\
                \t-L : specify NUFW listening IP address (local) (this address waits for nufw data) (default : 127.0.0.1)\n\
                \t-C : specify clients listening IP address (local) (this address waits for clients auth) (default : 0.0.0.0)\n\
                \t-d : (remote) address of the nufw (gateway) server\n\
                \t-p : (remote) port we use to send responses to nufw server(default : 4128)\n\
                \t-t : timeout to forget about packets when they don't match (default : 15 s)\n");
            return 1;
        }
    }

    /* debug cannot be above 10 */
    if (debug_level > MAX_DEBUG_LEVEL)
        debug_level=MAX_DEBUG_LEVEL;
    if (debug_level < MIN_DEBUG_LEVEL)
        debug_level=MIN_DEBUG_LEVEL;
    if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN))
        g_message("debug_level is %i\n",debug_level);


    if (daemonize == 1) {
        int i;
        struct sigaction action;
        FILE* pf;

        if (access (NUAUTH_PID_FILE, R_OK) == 0) {
            /* Check if the existing process is still alive. */
            pid_t pidv;

            pf = fopen (NUAUTH_PID_FILE, "r");
            if (pf != NULL &&
                fscanf (pf, "%d", &pidv) == 1 &&
                kill (pidv, 0) == 0 ) {
                fclose (pf);
                printf ("nuauth already running. Aborting!\n");
                exit(-1);
            }

            if (pf != NULL)
                fclose (pf);
        }


        if ((pidf = fork()) < 0){
            g_error("Unable to fork\n");
            exit (-1); /* this should be useless !! */
        } else {
            if (pidf > 0) {
                if ((pf = fopen (NUAUTH_PID_FILE, "w")) != NULL) {
                    fprintf (pf, "%d\n", (int)pidf);
                    fclose (pf);
                } else {
                    printf ("Dying, can not create PID file : " NUAUTH_PID_FILE "\n"); 
                    exit(-1);
                }
                exit(0);
            }
        }

        chdir("/");

        setsid();

        /* intercept SIGTERM */
        action.sa_handler = nuauth_cleanup;
        sigemptyset( & (action.sa_mask));
        action.sa_flags = 0;
        if ( sigaction( SIGTERM, & action , NULL ) != 0) {
            printf("Error\n");
            exit(1);
        }



        set_glib_loghandlers();

        for (i = 0; i < FOPEN_MAX ; i++){
            close(i);
        }
    }

    signal(SIGPIPE,SIG_IGN);

    /* initialize packets list */
    conn_list = g_hash_table_new_full ((GHashFunc)hash_connection,
        compare_connection
        ,NULL,
        (GDestroyNotify) free_connection); 
    /* initiate user hash */
    users_hash = g_hash_table_new (NULL, NULL);


    /* create srv addr for sending auth answer*/
    adr_srv.sin_family= AF_INET;
    adr_srv.sin_port=htons(gwsrv_port);
    adr_srv.sin_addr.s_addr=inet_addr(gwsrv_addr);

    if (adr_srv.sin_addr.s_addr == INADDR_NONE ){
        printf("Bad Address.\n");
        exit(-1);
    }
    /* socket ready */
    //listening adress for clients requests
    memset(&client_srv,0,sizeof client_srv);

    /* hostname conversion */
    //client_list_srv=gethostbyname(client_listen_address);
    client_list_srv=gethostbyname(nuauth_client_listen_addr);
    client_srv.sin_addr=*(struct in_addr *)client_list_srv->h_addr;

    if (client_srv.sin_addr.s_addr == INADDR_NONE ){
        if (DEBUG_OR_NOT(DEBUG_LEVEL_CRITICAL,DEBUG_AREA_MAIN))
            g_warning("Bad Address was passed with \"-C\" parameter. Ignored.");
        client_srv.sin_addr.s_addr = INADDR_ANY;
    }

    // INIT adress for listening to nufw
    memset(&nufw_srv,0,sizeof nufw_srv);

    /* hostname conversion */
    //nufw_list_srv=gethostbyname(nufw_listen_address);
    nufw_list_srv=gethostbyname(nuauth_nufw_listen_addr);
    nufw_srv.sin_addr=*(struct in_addr *)nufw_list_srv->h_addr;

    if (nufw_srv.sin_addr.s_addr == INADDR_NONE ){
        if (DEBUG_OR_NOT(DEBUG_LEVEL_CRITICAL,DEBUG_AREA_MAIN))
            g_warning("Bad Address was passed with \"-L\" parameter. Ignored.");
        nufw_srv.sin_addr.s_addr = INADDR_ANY;
    }

    /* Initialize glib thread system */
    g_thread_init(NULL);

    /* external auth module loading */

    module_acl_check=NULL;
    module_user_check=NULL;

    auth_module=g_module_open (g_module_build_path(MODULE_PATH,
          nuauth_user_check_module)
        ,0);
    if (auth_module == NULL){
        g_error("unable to load module %s in %s",nuauth_user_check_module,MODULE_PATH);
    }

    if (!g_module_symbol (auth_module, "user_check", 
          (gpointer*)&module_user_check))
    {
        g_error ("Unable to load user check function\n");
    }

    if ( strcmp(nuauth_user_check_module,nuauth_acl_check_module)){
        auth_module = g_module_open (g_module_build_path(MODULE_PATH,
              nuauth_acl_check_module)
            ,0);
        if (auth_module == NULL){
            g_error("unable to load module %s in %s",nuauth_acl_check_module,MODULE_PATH);
        }
    }

    if (!g_module_symbol (auth_module, "acl_check", 
          (gpointer*)&module_acl_check))
    {
        g_error ("Unable to load acl check function\n");
    }


    logs_module=g_module_open (g_module_build_path(MODULE_PATH,
          nuauth_user_logs_module)
        ,0);
    if (logs_module == NULL){
        g_error("unable to load module %s in %s",nuauth_user_logs_module,MODULE_PATH);
    }

    if (!g_module_symbol (logs_module, "user_packet_logs", 
          (gpointer*) &module_user_logs))
    {
        g_error ("Unable to load user logs function\n");
    }


    /* internal Use */
    ALLGROUP=NULL;
    ALLGROUP=g_slist_prepend(ALLGROUP, GINT_TO_POINTER(0) );

    DUMMYACL.groups = ALLGROUP;
    DUMMYACL.answer = NOK;
    DUMMYACLS = g_slist_prepend(NULL,&DUMMYACL);
    free_mutex_list=NULL;
    busy_mutex_list=NULL;
    /* create thread for packet server */
    pckt_server = g_thread_create ( packet_authsrv,
        NULL,
        FALSE,
        NULL);
    if (! pckt_server )
        exit(1);

    /* create thread for auth server */
    auth_server = g_thread_create ( user_authsrv,
        NULL,
        FALSE,
        NULL);
    if (! auth_server )
        exit(1);


    /* private data for crypt */
    crypt_priv = g_private_new (g_free);

    /* create pckt workers */

    acl_checkers = g_thread_pool_new  ((GFunc) acl_check_and_decide,
        NULL,
        nbacl_check,
        TRUE,
        NULL);

    /* create user worker */
    user_checkers = g_thread_pool_new  ((GFunc) user_check_and_decide,
        NULL,
       nbuser_check,
      TRUE,
       NULL);

    user_loggers = g_thread_pool_new  ((GFunc)  real_log_user_packet,
        NULL,
        nuauth_number_loggers,
        TRUE,
        NULL);

    /* admin task */
    for(;;){
//        clean_connections_list();
        if (DEBUG_OR_NOT(DEBUG_LEVEL_MESSAGE,DEBUG_AREA_MAIN)){
            g_message("%u unassigned task(s), %d connection(s), and %d/%d free/busy mutex(es) \n",
                g_thread_pool_unprocessed(user_checkers),
                g_hash_table_size(conn_list),
                g_slist_length(free_mutex_list),
                g_slist_length(busy_mutex_list)
                );  
        }
        sleep(1);	
    }

}


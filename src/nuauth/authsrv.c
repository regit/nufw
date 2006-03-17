/*
 ** Copyright(C) 2004-2005 INL
 ** Written by Eric Leblond <regit@inl.fr>
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

/*! \file nuauth/authsrv.c
  \brief Main file

  It takes care of init stuffs and runs sheduled tasks at a given interval.
  */


#include <auth_srv.h>
#include <gcrypt.h>
#include <sasl/saslutil.h>
#include "gcrypt_init.h"
#include "tls.h"
#include "sasl.h"
#include "security.h"

typedef struct
{
    int daemonize;
    char* nuauth_client_listen_addr;
    char* nuauth_nufw_listen_addr;
} command_line_params_t;    

void stop_threads()
{
    /* ask theads to stop */
    g_message("Ask threads to stop.");
    if (nuauthconf->push && nuauthconf->hello_authentication) {
        g_mutex_lock (nuauthdatas->localid_auth_thread.mutex);
    }
    
    /* wait thread end */
    g_message("Wait thread end ...");
    
    /* kill push worker */
    g_mutex_lock (nuauthdatas->tls_pusher.mutex);
    log_message(DEBUG, AREA_MAIN, "Wait thread 'tls pusher'");
    g_thread_join (nuauthdatas->tls_pusher.thread);

    /* kill entries point */
    g_mutex_lock (nuauthdatas->tls_auth_server.mutex);
    g_mutex_lock (nuauthdatas->tls_nufw_server.mutex);
    
    log_message(DEBUG, AREA_MAIN, "Wait thread 'tls auth server'");
    g_thread_join (nuauthdatas->tls_auth_server.thread);

    log_message(DEBUG, AREA_MAIN, "Wait thread 'tls nufw server'");
    g_thread_join (nuauthdatas->tls_nufw_server.thread);
    
    /* end logging threads */
    g_thread_pool_free(nuauthdatas->user_session_loggers,TRUE,TRUE);
    g_thread_pool_free(nuauthdatas->user_loggers,TRUE,TRUE);
    g_thread_pool_free(nuauthdatas->decisions_workers,TRUE,TRUE);
    
    g_thread_pool_free(nuauthdatas->acl_checkers,TRUE,TRUE);
    
    g_mutex_lock (nuauthdatas->limited_connections_handler.mutex);
    log_message(DEBUG, AREA_MAIN, "Wait thread 'limited connections'");
    g_thread_join (nuauthdatas->limited_connections_handler.thread);

    g_mutex_lock (nuauthdatas->search_and_fill_worker.mutex);
    log_message(DEBUG, AREA_MAIN, "Wait thread 'search&fill'");
    g_thread_join (nuauthdatas->search_and_fill_worker.thread);

    /* working  */
    g_thread_pool_free(nuauthdatas->ip_authentication_workers,TRUE,TRUE);
    
    if (nuauthconf->push && nuauthconf->hello_authentication) {
        log_message(DEBUG, AREA_MAIN, "Wait thread 'localid'");
        g_thread_join (nuauthdatas->localid_auth_thread.thread);
    }

    /* done! */
    g_message("Threads stopped.");
}    

void free_threads()
{
    /* free all thread mutex */
    g_mutex_unlock (nuauthdatas->tls_pusher.mutex);
    g_mutex_free (nuauthdatas->tls_pusher.mutex);
    
    g_mutex_unlock (nuauthdatas->search_and_fill_worker.mutex);
    g_mutex_free (nuauthdatas->search_and_fill_worker.mutex);

    g_mutex_unlock (nuauthdatas->tls_auth_server.mutex);
    g_mutex_free (nuauthdatas->tls_auth_server.mutex);

    g_mutex_unlock (nuauthdatas->tls_nufw_server.mutex);
    g_mutex_free (nuauthdatas->tls_nufw_server.mutex);

    g_mutex_unlock (nuauthdatas->limited_connections_handler.mutex);
    g_mutex_free (nuauthdatas->limited_connections_handler.mutex);
    
    if (nuauthconf->push && nuauthconf->hello_authentication) {
        g_mutex_unlock (nuauthdatas->localid_auth_thread.mutex);
        g_mutex_free (nuauthdatas->localid_auth_thread.mutex);
    }
}    

/**
 * exit function if a signal is received in daemon mode.
 * 
 * \param signal Code of raised signal
 */
void nuauth_cleanup( int signal ) 
{
    /* first of all, reinstall old handlers (ignore errors) */
    (void)sigaction(SIGTERM, &nuauthdatas->old_sigterm_hdl, NULL);
    (void)sigaction(SIGINT, &nuauthdatas->old_sigint_hdl, NULL);

    if (signal == SIGINT)
        g_message("CTRL+c catched: stop NuAuth server.");
    else if (signal == SIGTERM)
        g_message("SIGTERM catched: stop NuAuth server.");

    stop_threads();

    /* free nufw server hash */
    if (DEBUG_OR_NOT(DEBUG_LEVEL_CRITICAL,DEBUG_AREA_MAIN))
        g_message("caught interrupt, cleaning");
    close_nufw_servers();

    /* free client hash */
    close_clients();
    free_nuauth_params (nuauthconf);

    /* clean gnutls */
    end_tls();
    end_audit();

    unload_modules();
    if (nuauthconf->acl_cache){
        clear_cache(nuauthdatas->acl_cache);
    }
    if (nuauthconf->user_cache){
        clear_cache(nuauthdatas->user_cache);
    }
    free_threads();

    /* destroy pid file */
    unlink(NUAUTH_PID_FILE);
    
    g_message("NuAuth exit");
    exit(EXIT_SUCCESS);
}

void daemonize() 
{
    FILE* pf;
    pid_t pidf;

    if (access (NUAUTH_PID_FILE, R_OK) == 0) {
        /* Check if the existing process is still alive. */
        pid_t pidv;

        pf = fopen (NUAUTH_PID_FILE, "r");
        if (pf != NULL &&
                fscanf (pf, "%d", &pidv) == 1 &&
                kill (pidv, 0) == 0 ) {
            fclose (pf);
            printf ("pid file exists. Is nuauth already running? Aborting!\n");
            exit(EXIT_FAILURE);
        }

        if (pf != NULL)
            fclose (pf);
    }

    pidf = fork();
    if (pidf < 0) {
        g_error("Unable to fork\n");
        exit (EXIT_FAILURE); /* this should be useless !! */
    } else {
        if (pidf > 0) {
            pf = fopen (NUAUTH_PID_FILE, "w");
            if (pf != NULL) {
                fprintf (pf, "%d\n", (int)pidf);
                fclose (pf);
            } else {
                printf ("Dying, can not create PID file \"" NUAUTH_PID_FILE "\".\n"); 
                exit(EXIT_FAILURE);
            }
            exit(EXIT_SUCCESS);
        }
    }

    chdir("/");

    setsid();

    set_glib_loghandlers();

    /* Close stdin, stdout, stderr. */
    (void) close(0);
    (void) close(1);
    (void) close(2);
}

void print_usage() 
{
    fprintf (stdout,
            "nuauth [-hDVv[v[v[v[v[v[v[v[v]]]]]]]]] [-l user_packet_port] [-C local_addr] [-L local_addr] \n"
            "\t\t[-t packet_timeout]\n"
            "\t-h : display this help and exit\n"
            "\t-D : run as a daemon, send debug messages to syslog (else stdout/stderr)\n"
            "\t-V : display version and exit\n"
            "\t-v : increase debug level (+1 for each 'v') (max useful number : 10)\n"
            "\t-l : specify listening TCP port (this port waits for clients) (default : 4130)\n"
            "\t-L : specify NUFW listening IP address (local) (this address waits for nufw data) (default : 127.0.0.1)\n"
            "\t-C : specify clients listening IP address (local) (this address waits for clients auth) (default : 0.0.0.0)\n"
            "\t-t : timeout to forget about packets when they don't match (default : 15 s)\n");
}

void parse_options(int argc, char **argv, command_line_params_t *params) 
{
    char* version=VERSION;
    char * options_list = "DhVvl:L:C:p:t:T:";
    int option;
    int value;

    /*parse options */
    while((option = getopt ( argc, argv, options_list)) != -1 ){
        switch (option){
            case 'V' :
                fprintf (stdout, "nuauth (version %s)\n",version);
                exit(EXIT_SUCCESS);
                break;

            case 'v' :
                /*fprintf (stdout, "Debug should be On (++)\n");*/
                nuauthconf->debug_level+=1;
                break;

            case 'l' :
                /* port we listen for auth answer */
                sscanf(optarg,"%d",&value);
                printf("Waiting for user packets on TCP port %d\n",value);
                nuauthconf->userpckt_port=value;
                break;

            case 'L' :
                /* Adress we listen for NUFW originating packets */
                /* SECURE_STRNCPY(nufw_listen_address, optarg, HOSTNAME_SIZE); */
                params->nuauth_nufw_listen_addr = (char *)calloc(HOSTNAME_SIZE, sizeof(char));
                if (params->nuauth_nufw_listen_addr == NULL)
                {
                    /* TODO: Error message and free memory? */
                    exit(EXIT_FAILURE);
                }
                SECURE_STRNCPY (params->nuauth_nufw_listen_addr, optarg, HOSTNAME_SIZE);
                printf("Waiting for Nufw daemon packets on %s\n", params->nuauth_nufw_listen_addr);
                break;

            case 'C' :
                /* Adress we listen for NUFW originating packets */
                params->nuauth_client_listen_addr = (char *)calloc(HOSTNAME_SIZE, sizeof(char));
                if (params->nuauth_client_listen_addr == NULL)
                {
                    /* TODO: Error message and free memory? */
                    exit(EXIT_FAILURE);
                }
                SECURE_STRNCPY(params->nuauth_client_listen_addr, optarg, HOSTNAME_SIZE);
                printf("Waiting for clients auth packets on %s\n", params->nuauth_client_listen_addr);
                break;

            case 't' :
                /* packet timeout */
                sscanf(optarg,"%d",&(nuauthconf->packet_timeout));
                break;

            case 'D' :
                params->daemonize=1;
                break;

            case 'h' :
                print_usage();
                exit(EXIT_SUCCESS);                
        }
    }
}

void install_signals() 
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = nuauth_cleanup;
    sigemptyset( & (action.sa_mask));
    action.sa_flags = 0;

    /* intercept SIGTERM */
    if ( sigaction(SIGTERM, &action, &nuauthdatas->old_sigterm_hdl) != 0) {
        printf("Error\n");
        exit(EXIT_FAILURE);
    }

    /* intercept SIGINT */
    if ( sigaction(SIGINT, &action, &nuauthdatas->old_sigint_hdl) != 0) {
        printf("Error\n");
        exit(EXIT_FAILURE);
    }

    /* intercept SIGHUP */
    memset(&action, 0, sizeof(action));
    action.sa_handler = nuauth_reload;
    sigemptyset( & (action.sa_mask));
    action.sa_flags = 0;
    if ( sigaction(SIGHUP, &action, NULL) != 0) {
        printf("Error\n");
        exit(EXIT_FAILURE);
    }

    /* ignore SIGPIPE */
    signal(SIGPIPE,SIG_IGN);
}

void create_thread(struct nuauth_thread_t *thread, void* (*func) (GMutex*) )
{
    thread->mutex = g_mutex_new();
    thread->thread = g_thread_create ((GThreadFunc)func, thread->mutex, TRUE, NULL);
    if (thread->thread == NULL)
        exit(EXIT_FAILURE);
}

void configure_app(int argc, char **argv) 
{
    command_line_params_t params;

    /* Initialize glib thread system */
    g_thread_init(NULL);
    g_thread_pool_set_max_unused_threads (5);

    /* init nuauthdatas */
    nuauthdatas=g_new0(struct nuauth_datas,1);
    nuauthdatas->reload_cond=g_cond_new ();
    nuauthdatas->reload_cond_mutex=g_mutex_new ();

    /* set default parameters */
    params.daemonize = 0;
    params.nuauth_client_listen_addr=NULL;
    params.nuauth_nufw_listen_addr=NULL;

    /* load configuration */
    init_nuauthconf(&nuauthconf);

    log_message (INFO, AREA_MAIN, "Start NuAuth server.");
    
    /* init gcrypt and gnutls */
    gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_gthread);

    gnutls_global_init();

    /* init credential */
    create_x509_credentials();

#if 0    
    /* TODO : it stink ? */
    *vtable=g_new(GMemVTable, 1);
    vtable->malloc=&(malloc);
    vtable->realloc=&(realloc);
    vtable->free=&(free);
    vtable->calloc = NULL;
    vtable->try_malloc = NULL;
    vtable->try_realloc = NULL;
    g_mem_set_vtable(glib_mem_profiler_table);
#endif        

    parse_options(argc, argv, &params);

    build_nuauthconf(nuauthconf, 
            params.nuauth_client_listen_addr,
            params.nuauth_nufw_listen_addr,
            NULL, NULL, NULL);

    if (nuauthconf->uses_utf8){
        setlocale(LC_ALL,"");	
    }

    /* debug cannot be above 10 */
    if (nuauthconf->debug_level > MAX_DEBUG_LEVEL)
        nuauthconf->debug_level=MAX_DEBUG_LEVEL;
    if (nuauthconf->debug_level < MIN_DEBUG_LEVEL)
        nuauthconf->debug_level=MIN_DEBUG_LEVEL;
    if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN))
        g_message("debug_level is %i\n",nuauthconf->debug_level);

    if (params.daemonize == 1) {
        daemonize();
    } else {
        g_message("Starting nuauth");
    }
}

void init_nuauthdatas() 
{
    nuauthdatas->tls_push_queue = g_async_queue_new ();
    if (!nuauthdatas->tls_push_queue)
        exit(EXIT_FAILURE);

    /* initialize packets list */
    conn_list = g_hash_table_new_full ((GHashFunc)hash_connection,
            compare_connection,
            NULL,
            (GDestroyNotify) free_connection); 

    /* async queue initialisation */
    nuauthdatas->connections_queue = g_async_queue_new();
    if (!nuauthdatas->connections_queue)
        exit(EXIT_FAILURE);

    /* init and load modules */
    init_modules_system();
    load_modules();

    /* init periods */
    nuauthconf->periods=init_periods(nuauthconf);
    
    /* internal Use */
    ALLGROUP = g_slist_prepend(NULL, GINT_TO_POINTER(0) );

    if (nuauthconf->acl_cache)
        init_acl_cache();

    /* create user cache thread */
    if (nuauthconf->user_cache)
        init_user_cache();

    null_message = g_new0(struct cache_message, 1);
    null_queue_datas = g_new0(gchar,1);

    if (nuauthconf->do_ip_authentication)
        /* create thread of pool */
        nuauthdatas->ip_authentication_workers = g_thread_pool_new ((GFunc) external_ip_auth,
                NULL,
                nuauthconf->nbipauth_check,
                POOL_TYPE,
                NULL);

    /* create thread for client request sender */
    create_thread (&nuauthdatas->tls_pusher, push_worker);

    /* init private datas for pool thread */
    nuauthdatas->aclqueue = g_private_new(g_free);
    nuauthdatas->userqueue = g_private_new(g_free);

    /* create thread for search_and_fill thread */
    log_message (VERBOSE_DEBUG, AREA_MAIN, "Creating search_and_fill thread");
    create_thread (&nuauthdatas->search_and_fill_worker, search_and_fill);

    if (nuauthconf->push && nuauthconf->hello_authentication){
        if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
            g_message("Creating hello mode authentication thread");
        nuauthdatas->localid_auth_queue = g_async_queue_new ();
        create_thread (&nuauthdatas->localid_auth_thread, localid_auth);
    }

    /* create acl checker workers */
    if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
        g_message("Creating %d acl checkers",nuauthconf->nbacl_check);
    nuauthdatas->acl_checkers = g_thread_pool_new ((GFunc)acl_check_and_decide,
            NULL,
            nuauthconf->nbacl_check,
            POOL_TYPE,
            NULL);

    /* create user checker workers */
    if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
        g_message("Creating %d user checkers",nuauthconf->nbuser_check);
    nuauthdatas->user_checkers = g_thread_pool_new ((GFunc)user_check_and_decide,
            NULL,
            nuauthconf->nbuser_check,
            POOL_TYPE,
            NULL);

    /* create user logger workers */
    if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
        g_message("Creating %d user loggers", nuauthconf->nbloggers);
    }
    nuauthdatas->user_loggers = g_thread_pool_new ((GFunc)real_log_user_packet,
            NULL,
            nuauthconf->nbloggers,
            POOL_TYPE,
            NULL);
    if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
        g_message("Creating %d user session loggers", nuauthconf->nbloggers);
    }
    nuauthdatas->user_session_loggers = g_thread_pool_new  ((GFunc)  log_user_session_thread,
            NULL,
            nuauthconf->nbloggers,
            POOL_TYPE,
            NULL);

    /* create decisions workers (if needed) */
    if ( nuauthconf->log_users_sync ){
        if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
            g_message("Creating %d decision workers", nuauthconf->nbloggers);
        }
        nuauthdatas->decisions_workers = g_thread_pool_new  ((GFunc)  decisions_queue_work,
                NULL,
                nuauthconf->nbloggers,
                POOL_TYPE,
                NULL);
    }

    /* create TLS authentification server threads (auth + nufw) */
    log_message (VERBOSE_DEBUG, AREA_MAIN, "Creating tls authentication server thread");
    create_thread (&nuauthdatas->tls_auth_server, tls_user_authsrv);

    log_message (VERBOSE_DEBUG, AREA_MAIN, "Creating tls nufw server thread");
    create_thread (&nuauthdatas->tls_nufw_server, tls_nufw_authsrv);

    create_thread (&nuauthdatas->limited_connections_handler, limited_connection_handler);

    log_message (INFO, AREA_MAIN, "Threads system started");
}

void main_loop()
{
    struct timespec sleep;

    /* a little sleep (1 second), we are waiting for threads to initiate:w */
    sleep.tv_sec = 1;
    sleep.tv_nsec = 0;
    nanosleep(&sleep, NULL);	

    /* Set sleep in loop to 0.5 second */
    sleep.tv_sec = 0;
    sleep.tv_nsec = 500000000;

    /* admin task */
    for(;;){
        struct cache_message * message;
        clean_connections_list();
        if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_MAIN)){
            if (g_thread_pool_unprocessed(nuauthdatas->user_checkers) || g_thread_pool_unprocessed(nuauthdatas->acl_checkers)){
                g_message("%u user/%u acl unassigned task(s), %d connection(s)\n",
                        g_thread_pool_unprocessed(nuauthdatas->user_checkers),
                        g_thread_pool_unprocessed(nuauthdatas->acl_checkers),
                        g_hash_table_size(conn_list)
                        );  
            }
        }
        if (nuauthconf->acl_cache){
            /* send update message to cache thread */
            message=g_new0(struct cache_message,1);
            message->type=REFRESH_MESSAGE;
            g_async_queue_push(nuauthdatas->acl_cache->queue,message);
        }
        if (nuauthconf->push){
            if (nuauthconf->hello_authentication) {
                struct internal_message * message=g_new0(struct internal_message,1);
                message->type=REFRESH_MESSAGE;
                g_async_queue_push(nuauthdatas->localid_auth_queue,message);
            }
        }
        {
            struct internal_message * message=g_new0(struct internal_message,1);
            message->type=REFRESH_MESSAGE;
            g_async_queue_push(nuauthdatas->limited_connections_queue,message);
        } 

        /* a little sleep (1/2 second) */
        nanosleep(&sleep, NULL);	
    }
}

int main(int argc,char * argv[]) 
{
    configure_app(argc, argv);
    install_signals();
    init_nuauthdatas();
    init_audit();
    main_loop();
    return EXIT_SUCCESS;
}


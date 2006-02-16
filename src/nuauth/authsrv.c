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


/**
 * exit function if a signal is received in daemon mode.
 * 
 * Argument : a signal
 * Return : None
 */
void nuauth_cleanup( int signal ) {
    /* free nufw server hash */
    if (DEBUG_OR_NOT(DEBUG_LEVEL_CRITICAL,DEBUG_AREA_MAIN))
        g_message("caught interrupt, cleaning");
    close_servers(signal);
    /* free client hash */
    close_clients(signal);
    /* clean gnutls */
    end_tls(signal);
    end_audit(signal);
    /* destroy pid file */
    unlink(NUAUTH_PID_FILE);
    /* exit */
    exit(0);
}

int main(int argc,char * argv[]) 
{
  /* option */
  char * options_list = "DhVvl:L:C:p:t:T:";
  int option,daemonize = 0;
  int value;
  char* version=VERSION;
  tracking empty_header;
  struct sigaction action;
  pid_t pidf;
  char* nuauth_client_listen_addr=NULL;
  char* nuauth_nufw_listen_addr=NULL;

  /* init gcrypt and gnutls */
  //        gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_gthread);

  /* Initialize glib thread system */
  g_thread_init(NULL);
  g_thread_pool_set_max_unused_threads (5);
  gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_gthread);

  gnutls_global_init();

  /* init nuauthdatas */
  nuauthdatas=g_new0(struct nuauth_datas,1);
  nuauthdatas->reload_cond=g_cond_new ();
  nuauthdatas->reload_cond_mutex=g_mutex_new ();
       
  /* load configuration */
  nuauthconf=init_nuauthconf();
  
  /* init credential */
  create_x509_credentials();

  nuauthdatas->tls_push_queue = g_async_queue_new ();
  if (!nuauthdatas->tls_push_queue)
      exit(1);


  /*vtable=g_new(GMemVTable, 1);
    vtable->malloc=&(malloc);
    vtable->realloc=&(realloc);
    vtable->free=&(free);
    vtable->calloc = NULL;
    vtable->try_malloc = NULL;
    vtable->try_realloc = NULL;*/
  /* TODO : it stink ? */
  //	 g_mem_set_vtable(glib_mem_profiler_table);


  /*parse options */
  while((option = getopt ( argc, argv, options_list)) != -1 ){
      switch (option){
        case 'V' :
                fprintf (stdout, "nuauth (version %s)\n",version);
                return 1;
        case 'v' :
                /*fprintf (stdout, "Debug should be On (++)\n");*/
                nuauthconf->debug_level+=1;
                break;
                /* port we listen for auth answer */
        case 'l' :
                sscanf(optarg,"%d",&value);
                printf("Waiting for user packets on TCP port %d\n",value);
                nuauthconf->userpckt_port=value;
                break;
                /* Adress we listen for NUFW originating packets */
        case 'L' :
                // strncpy(nufw_listen_address,optarg,HOSTNAME_SIZE);
                nuauth_nufw_listen_addr = (char *)calloc(HOSTNAME_SIZE,sizeof(char));
                if (nuauth_nufw_listen_addr == NULL){return -1;}
                strncpy(nuauth_nufw_listen_addr,optarg,HOSTNAME_SIZE);
                printf("Waiting for Nufw daemon packets on %s\n",nuauth_nufw_listen_addr);
                //printf("Waiting for Nufw daemon packets on %s\n",nufw_listen_address);
                break;
                /* Adress we listen for NUFW originating packets */
        case 'C' :
                nuauth_client_listen_addr = (char *)calloc(HOSTNAME_SIZE,sizeof(char));
                if (nuauth_client_listen_addr == NULL){return -1;}
                strncpy(nuauth_client_listen_addr,optarg,HOSTNAME_SIZE);
                printf("Waiting for clients auth packets on %s\n",nuauth_client_listen_addr);
                break;
                /* packet timeout */
        case 't' :
                sscanf(optarg,"%d",&(nuauthconf->packet_timeout));
                break;
        case 'D' :
                daemonize=1;
                break;
        case 'h' :
                fprintf (stdout ,"nuauth [-hDVv[v[v[v[v[v[v[v[v]]]]]]]]] [-l user_packet_port] [-C local_addr] [-L local_addr] \n\
                                \t\t[-t packet_timeout]\n\
                                \t-h : display this help and exit\n\
                                \t-D : run as a daemon, send debug messages to syslog (else stdout/stderr)\n\
                                \t-V : display version and exit\n\
                                \t-v : increase debug level (+1 for each 'v') (max useful number : 10)\n\
                                \t-l : specify listening TCP port (this port waits for clients) (default : 4130)\n\
                                \t-L : specify NUFW listening IP address (local) (this address waits for nufw data) (default : 127.0.0.1)\n\
                                \t-C : specify clients listening IP address (local) (this address waits for clients auth) (default : 0.0.0.0)\n\
                                \t-t : timeout to forget about packets when they don't match (default : 15 s)\n");
                return 1;
      }
  }

  build_nuauthconf(nuauthconf,nuauth_client_listen_addr,nuauth_nufw_listen_addr,
                  NULL,NULL,NULL);


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

  if (daemonize == 1) {
      int i;
      FILE* pf;

      if (access (NUAUTH_PID_FILE, R_OK) == 0) {
          /* Check if the existing process is still alive. */
          pid_t pidv;

          pf = fopen (NUAUTH_PID_FILE, "r");
          if (pf != NULL &&
                          fscanf (pf, "%d", &pidv) == 1 &&
                          kill (pidv, 0) == 0 ) {
              fclose (pf);
              printf ("pid file exists. Is nuauth already running? Aborting!\n");
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



      set_glib_loghandlers();

      for (i = 0; i < FOPEN_MAX ; i++){
          close(i);
      }
  } else {
      g_message("Starting nuauth");
  }
  /* intercept SIGTERM */
  memset(&action,0,sizeof(action));
  action.sa_handler = nuauth_cleanup;
  sigemptyset( & (action.sa_mask));
  action.sa_flags = 0;
  if ( sigaction( SIGTERM, & action , NULL ) != 0) {
      printf("Error\n");
      exit(1);
  }
  if ( sigaction( SIGINT, & action , NULL ) != 0) {
      printf("Error\n");
      exit(1);
  }
  /* intercept SIGTERM */
  memset(&action,0,sizeof(action));
  action.sa_handler = nuauth_reload;
  sigemptyset( & (action.sa_mask));
  action.sa_flags = 0;
  if ( sigaction( SIGHUP, & action , NULL ) != 0) {
      printf("Error\n");
      exit(1);
  }


  signal(SIGPIPE,SIG_IGN);

  /* initialize packets list */
  conn_list = g_hash_table_new_full ((GHashFunc)hash_connection,
                  compare_connection,
                  NULL,
                  (GDestroyNotify) free_connection); 

  /* async  queue initialisation */

  nuauthdatas->connexions_queue = g_async_queue_new();
  if (!nuauthdatas->connexions_queue)
      exit(1);

  /* init modules system */
  init_modules_system();
  /* load modules */
  load_modules();

/* init periods */
  nuauthconf->periods=init_periods(nuauthconf);
  /* internal Use */
  ALLGROUP=NULL;
  ALLGROUP=g_slist_prepend(ALLGROUP, GINT_TO_POINTER(0) );


  if (nuauthconf->acl_cache) {
      init_acl_cache();
  }

  /* create user cache thread */
  if (nuauthconf->user_cache ){
      init_user_cache();
  }

  null_message=g_new0(struct cache_message,1);
  null_queue_datas=g_new0(gchar,1);

  if (nuauthconf->do_ip_authentication){
      /* create thread of pool */
      nuauthdatas->ip_authentication_workers = g_thread_pool_new  ((GFunc) external_ip_auth,
                      NULL,
                      nuauthconf->nbipauth_check,
                      POOL_TYPE,
                      NULL);
  }

  /* fill empty header to be able to run push_control */
  empty_header.saddr=INADDR_ANY;
  /* create thread for client request sender */
  nuauthdatas->tls_pusher = g_thread_create ( (GThreadFunc)push_worker,
                  NULL,
                  FALSE,
                  NULL);
  if (! nuauthdatas->tls_pusher )
      exit(1);


  /* init private datas for pool thread */
  nuauthdatas->aclqueue = g_private_new(g_free);
  nuauthdatas->userqueue = g_private_new(g_free);

  /* create thread for search_and_fill thread */
  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
      g_message("Creating search_and_fill thread");
  }
  nuauthdatas->search_and_fill_worker = g_thread_create ( (GThreadFunc) search_and_fill,
                  NULL,
                  FALSE,
                  NULL);
  if (! nuauthdatas->search_and_fill_worker )
      exit(1);

  if (nuauthconf->push && nuauthconf->hello_authentication){
      if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
          g_message("Creating hello mode authentication thread");
      nuauthdatas->localid_auth_queue = g_async_queue_new ();
      nuauthdatas->localid_auth_thread = g_thread_create ( (GThreadFunc) localid_auth,
                      NULL,
                      FALSE,
                      NULL);
      if (! nuauthdatas->localid_auth_thread )
          exit(1);
  }

  /* create pckt workers */

  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
      g_message("Creating %d acl checkers",nuauthconf->nbacl_check);
  nuauthdatas->acl_checkers = g_thread_pool_new  ((GFunc) acl_check_and_decide,
                  NULL,
                  nuauthconf->nbacl_check,
                  POOL_TYPE,
                  NULL);

  /* create user worker */

  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
      g_message("Creating %d user checkers",nuauthconf->nbuser_check);
  nuauthdatas->user_checkers = g_thread_pool_new  ((GFunc) user_check_and_decide,
                  NULL,
                  nuauthconf->nbuser_check,
                  POOL_TYPE,
                  NULL);


  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
      g_message("Creating %d user loggers", nuauthconf->nbloggers);
  }
  nuauthdatas->user_loggers = g_thread_pool_new  ((GFunc)  real_log_user_packet,
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


  /* create thread for tsl  auth server */
  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
      g_message("Creating tls authentication server thread");
  nuauthdatas->tls_auth_server = g_thread_create ( tls_user_authsrv,
                  NULL,
                  FALSE,
                  NULL);
  if (! nuauthdatas->tls_auth_server )
      exit(1);
  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
      g_message("Creating tls nufw server thread");
  nuauthdatas->tls_nufw_server = g_thread_create ( tls_nufw_authsrv,
                  NULL,
                  FALSE,
                  NULL);
  if (! nuauthdatas->tls_nufw_server ){
      exit(1);
  }
   nuauthdatas->limited_connexions_handler = g_thread_create ( limited_connection_handler,
                  NULL,
                  FALSE,
                  NULL);
  

  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
      g_message("Threads system started");

  /* init audit structure */
  init_audit();
  /* a little sleep */
  usleep(500000);	

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
              g_async_queue_push(nuauthdatas->limited_connexions_queue,message);
      } 
      /* a little sleep */
      usleep(500000);	
  }

}



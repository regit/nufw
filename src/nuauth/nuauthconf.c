/*
 ** Copyright(C) 2005 INL
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

#include <auth_srv.h>
#include <time.h>

int build_nuauthconf(struct nuauth_params * nuauthconf,
                char* nuauth_client_listen_addr,
                char* nuauth_nufw_listen_addr,
                char* gwsrv_addr,
                char* nuauth_multi_users,
                char* nuauth_multi_servers)
{
  struct hostent *nufw_list_srv, *client_list_srv;
  if((!  nuauthconf->push) && nuauthconf->hello_authentication ){
      g_message("nuauth_hello_authentication required nuauth_push to be 1, resetting to 0");
      nuauthconf->hello_authentication=0;
  }

  if (gwsrv_addr) {
      /* parse nufw server address */
      nuauthconf->authorized_servers= generate_inaddr_list(gwsrv_addr);
  }

  /* hostname conversion */
  if (nuauth_client_listen_addr){
      client_list_srv=gethostbyname(nuauth_client_listen_addr);
      if (client_list_srv != NULL){
          nuauthconf->client_srv=g_memdup(client_list_srv->h_addr,sizeof(*client_list_srv->h_addr));

          if (nuauthconf->client_srv->s_addr == INADDR_NONE ){
              if (DEBUG_OR_NOT(DEBUG_LEVEL_CRITICAL,DEBUG_AREA_MAIN)){
                  g_warning("Bad Address was passed for client listening address. Ignored. Using INADDR_ANY instead!");
              }
              nuauthconf->client_srv->s_addr = INADDR_ANY;
          }
      } else {
          if (DEBUG_OR_NOT(DEBUG_LEVEL_CRITICAL,DEBUG_AREA_MAIN)){
              g_warning("Can not resolve client listening address (%s). Ignored. Using INADDR_ANY instead!", nuauth_client_listen_addr);
          }
          nuauthconf->client_srv->s_addr = INADDR_ANY;
      }
  }

  /* hostname conversion */
  if (nuauth_nufw_listen_addr){
      nufw_list_srv=gethostbyname(nuauth_nufw_listen_addr);
      if (nufw_list_srv != NULL){
          nuauthconf->nufw_srv=g_memdup(nufw_list_srv->h_addr, sizeof(*nufw_list_srv->h_addr));

          if (nuauthconf->nufw_srv->s_addr == INADDR_NONE ){
              if (DEBUG_OR_NOT(DEBUG_LEVEL_CRITICAL,DEBUG_AREA_MAIN)){
                  g_warning("Bad Address was passed for nufw listening address. Ignored. Using INADDR_ANY instead!");
          }
              nuauthconf->nufw_srv->s_addr = INADDR_ANY;
          }
      } else {
          if (DEBUG_OR_NOT(DEBUG_LEVEL_CRITICAL,DEBUG_AREA_MAIN)){
              g_warning("Bad Address was passed for nufw listening address. Ignored. Using INADDR_ANY instead!");
          }
          nuauthconf->nufw_srv->s_addr = INADDR_ANY;
      }
  }

  if ((nuauth_multi_users || nuauth_multi_servers)&&(!(nuauth_multi_servers&&nuauth_multi_users))){
      g_warning("The two options nuauth_multi_users and nuauth_multi_servers need to set simultaneoulsy");
  } else {
      /* parse multi user auth users */
      if (nuauth_multi_users){
          nuauthconf->multi_users_array =  g_strsplit(nuauth_multi_users,",",0);
      }
      /* parse multi user clients */
      if (nuauth_multi_servers){
          nuauthconf->multi_servers_array =  generate_inaddr_list(nuauth_multi_servers);
      }
  }
  if (!(nuauthconf->user_cache &&  (nuauth_multi_users && nuauth_multi_servers) )){
      nuauthconf->user_cache=0;
  }
  return 1;
}

void init_nuauthconf(struct nuauth_params **result)
{
  struct nuauth_params* conf;
  char* nuauth_client_listen_addr = NULL;
  char* nuauth_nufw_listen_addr = NULL;
  char* gwsrv_addr = NULL;
  confparams nuauth_vars[] = {
      { "nuauth_client_listen_addr" ,  G_TOKEN_STRING, 0 , AUTHREQ_CLIENT_LISTEN_ADDR },
      { "nuauth_nufw_listen_addr" ,  G_TOKEN_STRING, 0 , AUTHREQ_NUFW_LISTEN_ADDR },
      { "nuauth_gw_packet_port" , G_TOKEN_INT , AUTHREQ_PORT,NULL },
      { "nuauth_user_packet_port" , G_TOKEN_INT , USERPCKT_PORT ,NULL},
      { "nufw_gw_addr" , G_TOKEN_STRING , 0, GWSRV_ADDR },
      { "nuauth_packet_timeout" , G_TOKEN_INT , PACKET_TIMEOUT, NULL },
      { "nuauth_session_duration" , G_TOKEN_INT , SESSION_DURATION, NULL },
      { "nuauth_number_usercheckers" , G_TOKEN_INT , NB_USERCHECK, NULL},
      { "nuauth_number_aclcheckers" , G_TOKEN_INT , NB_ACLCHECK, NULL },
      { "nuauth_number_ipauthcheckers" , G_TOKEN_INT , NB_ACLCHECK, NULL },
      { "nuauth_number_loggers" , G_TOKEN_INT , NB_LOGGERS, NULL },
      { "nuauth_number_session_loggers" , G_TOKEN_INT , NB_LOGGERS, NULL },
      { "nuauth_log_users" , G_TOKEN_INT , 1, NULL },
      { "nuauth_log_users_sync" , G_TOKEN_INT , 0, NULL },
      { "nuauth_log_users_strict" , G_TOKEN_INT , 1, NULL },
      { "nuauth_log_users_without_realm" , G_TOKEN_INT , 1, NULL },
      { "nuauth_prio_to_nok" , G_TOKEN_INT , 1, NULL },
      { "nuauth_connect_policy" , G_TOKEN_INT , POLICY_MULTIPLE_LOGIN, NULL },
      { "nuauth_datas_persistance" , G_TOKEN_INT , 9, NULL },
      { "nuauth_push_to_client" , G_TOKEN_INT , 1,NULL },
      { "nuauth_do_ip_authentication" , G_TOKEN_INT , 0,NULL },
      { "nuauth_multi_users" , G_TOKEN_STRING , 1, NULL },
      { "nuauth_multi_servers" , G_TOKEN_STRING , 1, NULL },
      { "nuauth_acl_cache" , G_TOKEN_INT , 0,NULL },
      { "nuauth_user_cache" , G_TOKEN_INT , 0,NULL },
#if USE_UTF8
      { "nuauth_uses_utf8" , G_TOKEN_INT , 1,NULL },
#else 
      { "nuauth_uses_utf8" , G_TOKEN_INT , 0,NULL },
#endif
      { "nuauth_hello_authentication" , G_TOKEN_INT , 0,NULL },
  };
  const unsigned int nb_params = sizeof(nuauth_vars)/sizeof(confparams);
  gchar *nuauth_multi_users=NULL;
  gchar *nuauth_multi_servers=NULL;

  conf=g_new0(struct nuauth_params,1);
  *result = conf;

  /* 
   * Minimum debug_level value is 2 -> for 1) fatal and 2) critical messages to always
   * be outputed
   */
  conf->debug_level=0;
  conf->debug_areas=DEFAULT_DEBUG_AREAS;
  
  /* parse conf file */
  parse_conffile(DEFAULT_CONF_FILE, nb_params, nuauth_vars);
  
#define READ_CONF(KEY) \
  get_confvar_value(nuauth_vars, nb_params, KEY)  

  nuauth_client_listen_addr = (char *)READ_CONF("nuauth_client_listen_addr");
  nuauth_nufw_listen_addr = (char *)READ_CONF("nuauth_nufw_listen_addr");
  gwsrv_addr = (char *)READ_CONF("nufw_gw_addr");
  nuauth_multi_users = (char *)READ_CONF("nuauth_multi_users");
  nuauth_multi_servers = (char *)READ_CONF("nuauth_multi_servers");

  conf->authreq_port = *(int*)READ_CONF("nuauth_gw_packet_port");
  conf->userpckt_port = *(int*)READ_CONF("nuauth_user_packet_port");
  conf->nbuser_check = *(int*)READ_CONF("nuauth_number_usercheckers");
  conf->nbacl_check = *(int*)READ_CONF("nuauth_number_aclcheckers");
  conf->nbipauth_check = *(int*)READ_CONF("nuauth_number_ipauthcheckers");
  conf->log_users = *(int*)READ_CONF("nuauth_log_users");
  conf->log_users_sync = *(int*)READ_CONF("nuauth_log_users_sync");
  conf->log_users_strict = *(int*)READ_CONF("nuauth_log_users_strict");
  conf->log_users_without_realm = *(int*)READ_CONF("nuauth_log_users_without_realm");
  conf->prio_to_nok = *(int*)READ_CONF("nuauth_prio_to_nok");
  conf->connect_policy = *(int*)READ_CONF("nuauth_connect_policy");
  conf->nbloggers = *(int*)READ_CONF("nuauth_number_loggers");
  conf->nb_session_loggers = *(int*)READ_CONF("nuauth_number_session_loggers");
  conf->packet_timeout = *(int*)READ_CONF("nuauth_packet_timeout");
  conf->session_duration = *(int*)READ_CONF("nuauth_session_duration");
  conf->datas_persistance = *(int*)READ_CONF("nuauth_datas_persistance");
  conf->push = *(int*)READ_CONF("nuauth_push_to_client");
  conf->do_ip_authentication = *(int*)READ_CONF("nuauth_do_ip_authentication");
  conf->acl_cache = *(int*)READ_CONF("nuauth_acl_cache");
  conf->user_cache = *(int*)READ_CONF("nuauth_user_cache");
  conf->uses_utf8 = *(int*)READ_CONF("nuauth_uses_utf8");
  conf->hello_authentication = *(int*)READ_CONF("nuauth_hello_authentication");
#undef READ_CONF
  
  build_nuauthconf(conf,nuauth_client_listen_addr,nuauth_nufw_listen_addr,
                  gwsrv_addr,nuauth_multi_users,nuauth_multi_servers);

  g_free(nuauth_client_listen_addr);
  g_free(nuauth_nufw_listen_addr);
  g_free(gwsrv_addr);
  g_free(nuauth_multi_users);
  g_free(nuauth_multi_servers);
}

void free_nuauth_params(struct nuauth_params* data)
{
	g_free(data->nufw_srv);
	g_free(data->client_srv);
	g_free(data->authorized_servers);
	g_strfreev(data->multi_users_array);
	g_free(data->multi_servers_array);
}

static struct nuauth_params* compare_and_update_nuauthparams(struct nuauth_params* current,struct nuauth_params* new);

/**
 * exit function if a signal is received in daemon mode.
 * 
 * Argument : a signal
 * Return : None
 */
void nuauth_reload( int signal ) {
    int pool_threads_num=0;
    struct nuauth_params* newconf=NULL;
    struct nuauth_params* actconf;
    struct timespec sleep;
    sleep.tv_sec = 0;
    sleep.tv_nsec = 100000000;  /* 0.1 second */
    
    init_nuauthconf(&newconf);
    g_message("nuauth module reloading");

    /* set flag to block threads of pool at start */
    nuauthdatas->need_reload=1;
    /* stop unused threads : now newly created threads will be locked */
    g_thread_pool_stop_unused_threads();
    /* we have to wait that all threads are blocked */
    do {
        nanosleep(&sleep, NULL);

	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
		g_message("waiting for threads to finish at %s:%d",__FILE__,__LINE__);
        }
        /* 1. count thread in pool */
        pool_threads_num=g_thread_pool_get_num_threads(nuauthdatas->user_checkers)
                + g_thread_pool_get_num_threads(nuauthdatas->acl_checkers)
                + g_thread_pool_get_num_threads(nuauthdatas->user_loggers);
                + g_thread_pool_get_num_threads(nuauthdatas->user_session_loggers);
        if (nuauthconf->do_ip_authentication){
            pool_threads_num+=g_thread_pool_get_num_threads(nuauthdatas->ip_authentication_workers); 
        }
        if ( nuauthconf->log_users_sync ){
            pool_threads_num+= g_thread_pool_get_num_threads(nuauthdatas->decisions_workers);
        }
        pool_threads_num-=g_thread_pool_get_num_unused_threads ();

	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
		g_message("got %d on %d",nuauthdatas->locked_threads_number,pool_threads_num);
	}
    /* compare against thread in state lock */
    } while (nuauthdatas->locked_threads_number<pool_threads_num);
    /* we've reached equality thus all threads are blocked now */
    /* unload modules */
    unload_modules();
    /* switch conf before loading modules */
    actconf=compare_and_update_nuauthparams(nuauthconf,newconf);
    if (actconf){
        g_free(nuauthconf);
        nuauthconf=actconf;
    }
    /* reload modules with new conf */
    load_modules();
    /* liberate threads by broadcasting condition */
    nuauthdatas->need_reload=0;
    g_mutex_lock(nuauthdatas->reload_cond_mutex);
    g_cond_broadcast(nuauthdatas->reload_cond);
    g_mutex_unlock(nuauthdatas->reload_cond_mutex);
}

static struct nuauth_params* compare_and_update_nuauthparams(struct nuauth_params* current,struct nuauth_params* new)
{
  gboolean restart=FALSE;
  if( current->authreq_port != new->authreq_port ){
      g_warning("authreq_port has changed, please restart");
      restart=TRUE;
  }

  if( current->userpckt_port != new->userpckt_port ){
      g_warning("userpckt_port has changed, please restart");
      restart=TRUE;
  }

  if( current->log_users_sync != new->log_users_sync  ){
      g_warning("log_users_sync has changed, please restart");
      restart=TRUE;
  }

  if( current->log_users_strict != new->log_users_strict  ){
      g_warning("log_users_strict has changed, please restart");
      restart=TRUE;
  }

  if( current->push != new->push  ){
      g_warning("switch between push and poll mode has been asked, please restart");
      restart=TRUE;
  }

  if( current->acl_cache != new->acl_cache  ){
      g_warning("switch between acl caching or not has been asked, please restart");
      restart=TRUE;
  }

  if( current->user_cache != new->user_cache  ){
      g_warning("switch between user caching or not has been asked, please restart");
      restart=TRUE;
  }

  if( current->do_ip_authentication != new->do_ip_authentication   ){
      g_warning("switch on ip authentication feature has been asked, please restart");
      restart=TRUE;
  }

  if( current->hello_authentication != new->hello_authentication   ){
      g_warning("switch on ip authentication feature has been asked, please restart");
      restart=TRUE;
  }

  if( (current->nufw_srv)->s_addr != (new->nufw_srv)->s_addr  ){
      g_warning("nufw listening ip has changed, please restart");
      g_message("was %s",inet_ntoa(*(current->nufw_srv)));
      g_message("want %s",inet_ntoa(*(new->nufw_srv)));
      restart=TRUE;
  }

  if( (current->client_srv)->s_addr != (new->client_srv)->s_addr  ){
      g_warning("client listening ip has changed, please restart");
      restart=TRUE;
  }


  if (restart == FALSE){
      /* checking nuauth tuning parameters */
      g_thread_pool_set_max_threads(nuauthdatas->user_checkers,new->nbuser_check,NULL);
      g_thread_pool_set_max_threads(nuauthdatas->acl_checkers,new->nbacl_check,NULL);
      if (new->do_ip_authentication){
          g_thread_pool_set_max_threads(nuauthdatas->ip_authentication_workers,new->nbipauth_check,NULL);
      }
      if(new->log_users_sync){
          g_thread_pool_set_max_threads(nuauthdatas->decisions_workers,new->nbloggers,NULL);
      }
      g_thread_pool_set_max_threads(nuauthdatas->user_loggers,new->nbloggers,NULL);
      g_thread_pool_set_max_threads(nuauthdatas->user_session_loggers,new->nb_session_loggers,NULL);
      /* debug is set via command line thus duplicate */
      new->debug_level=current->debug_level;
      new->debug_areas=current->debug_areas;
      destroy_periods(current->periods);
      new->periods=init_periods(new);
      free_nuauth_params(current);
      return new;
  } else {
      free_nuauth_params(new);
      return NULL;
  }
}


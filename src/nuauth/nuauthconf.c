/*
 ** Copyright(C) 2005-2006 INL
 ** Written by Eric Leblond <regit@inl.fr>
 **
 ** $Id$
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

/**
 * \addtogroup NuauthConf
 * @{
 */

/** \file nuauthconf.c
 * \brief Contain functions used to regenerate configuration and reload
 */

int build_prenuauthconf(struct nuauth_params * prenuauthconf,
                char* gwsrv_addr)
{
  if((!  prenuauthconf->push) && prenuauthconf->hello_authentication ){
      g_message("nuauth_hello_authentication required nuauth_push to be 1, resetting to 0");
      prenuauthconf->hello_authentication=0;
  }

  if (gwsrv_addr) {
      /* parse nufw server address */
      prenuauthconf->authorized_servers= generate_inaddr_list(gwsrv_addr);
  }

  if (prenuauthconf->nufw_has_fixed_timeout){
    prenuauthconf->nufw_has_conntrack=1;
  }
  return 1;
}

void init_nuauthconf(struct nuauth_params **result)
{
  struct nuauth_params* conf;
  char* gwsrv_addr = NULL;
  confparams nuauth_vars[] = {
      { "nuauth_client_listen_addr" ,  G_TOKEN_STRING, 0 , g_strdup(AUTHREQ_CLIENT_LISTEN_ADDR) },
      { "nuauth_nufw_listen_addr" ,  G_TOKEN_STRING, 0 , g_strdup(AUTHREQ_NUFW_LISTEN_ADDR) },
      { "nuauth_gw_packet_port" , G_TOKEN_STRING, 0, g_strdup(AUTHREQ_PORT) },
      { "nuauth_user_packet_port" , G_TOKEN_STRING , 0, g_strdup(USERPCKT_PORT) },
      { "nufw_gw_addr" , G_TOKEN_STRING , 0, g_strdup(GWSRV_ADDR) },
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
      { "nuauth_reject_after_timeout" , G_TOKEN_INT , 0, NULL },
      { "nuauth_reject_authenticated_drop" , G_TOKEN_INT , 0, NULL },
      { "nuauth_datas_persistance" , G_TOKEN_INT , 9, NULL },
      { "nuauth_push_to_client" , G_TOKEN_INT , 1,NULL },
      { "nuauth_do_ip_authentication" , G_TOKEN_INT , 0,NULL },
      { "nuauth_acl_cache" , G_TOKEN_INT , 0,NULL },
      { "nuauth_user_cache" , G_TOKEN_INT , 0,NULL },
#if USE_UTF8
      { "nuauth_uses_utf8" , G_TOKEN_INT , 1,NULL },
#else
      { "nuauth_uses_utf8" , G_TOKEN_INT , 0,NULL },
#endif
      {"nuauth_debug_areas", G_TOKEN_INT, DEFAULT_DEBUG_AREAS, NULL},
      {"nuauth_debug_level", G_TOKEN_INT, DEFAULT_DEBUG_LEVEL, NULL},
      { "nuauth_hello_authentication" , G_TOKEN_INT , 0, NULL },
      { "nufw_has_conntrack" , G_TOKEN_INT , 1, NULL },
      { "nufw_has_fixed_timeout" , G_TOKEN_INT , 1, NULL },
      { "nuauth_uses_fake_sasl" , G_TOKEN_INT , 0, NULL },
      { "nuauth_use_command_server" , G_TOKEN_INT , 0, NULL },
  };
  const unsigned int nb_params = sizeof(nuauth_vars)/sizeof(confparams);

  conf=g_new0(struct nuauth_params,1);
  *result = conf;

  /* parse conf file */
  parse_conffile(DEFAULT_CONF_FILE, nb_params, nuauth_vars);

#define READ_CONF(KEY) \
  get_confvar_value(nuauth_vars, nb_params, KEY)

  conf->client_srv = (char *)READ_CONF("nuauth_client_listen_addr");
  conf->nufw_srv = (char *)READ_CONF("nuauth_nufw_listen_addr");
  gwsrv_addr = (char *)READ_CONF("nufw_gw_addr");
  conf->authreq_port = (char *)READ_CONF("nuauth_gw_packet_port");
  conf->userpckt_port = (char *)READ_CONF("nuauth_user_packet_port");

  conf->nbuser_check = *(int*)READ_CONF("nuauth_number_usercheckers");
  conf->nbacl_check = *(int*)READ_CONF("nuauth_number_aclcheckers");
  conf->nbipauth_check = *(int*)READ_CONF("nuauth_number_ipauthcheckers");
  conf->log_users = *(int*)READ_CONF("nuauth_log_users");
  conf->log_users_sync = *(int*)READ_CONF("nuauth_log_users_sync");
  conf->log_users_strict = *(int*)READ_CONF("nuauth_log_users_strict");
  conf->log_users_without_realm = *(int*)READ_CONF("nuauth_log_users_without_realm");
  conf->prio_to_nok = *(int*)READ_CONF("nuauth_prio_to_nok");
  conf->connect_policy = *(int*)READ_CONF("nuauth_connect_policy");
  conf->reject_after_timeout = *(int*)READ_CONF("nuauth_reject_after_timeout");
  conf->reject_authenticated_drop = *(int*)READ_CONF("nuauth_reject_authenticated_drop");
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
  conf->debug_areas = *(int*)READ_CONF("nuauth_debug_areas");
  conf->debug_level = *(int*)READ_CONF("nuauth_debug_level");
  conf->nufw_has_conntrack = *(int*)READ_CONF("nufw_has_conntrack");
  conf->nufw_has_fixed_timeout = *(int*)READ_CONF("nufw_has_fixed_timeout");
  conf->nuauth_uses_fake_sasl = *(int*)READ_CONF("nuauth_uses_fake_sasl");
  conf->use_command_server = *(int*)READ_CONF("nuauth_use_command_server");
#undef READ_CONF

  if (conf->debug_level>9){
        conf->debug_level=9;
  }
  /* free config struct */
  free_confparams(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams));

  build_prenuauthconf(conf, gwsrv_addr);

  g_free(gwsrv_addr);
}

void free_nuauth_params(struct nuauth_params* data)
{
	g_free(data->authorized_servers);
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

	log_message(VERBOSE_DEBUG, AREA_MAIN, "waiting for threads to finish at %s:%d",__FILE__,__LINE__);
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

	log_message(VERBOSE_DEBUG, AREA_MAIN, "got %d on %d",nuauthdatas->locked_threads_number,pool_threads_num);
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
    /* init period */
    nuauthconf->periods=init_periods(nuauthconf);
    /* liberate threads by broadcasting condition */
    nuauthdatas->need_reload=0;
    g_mutex_lock(nuauthdatas->reload_cond_mutex);
    g_cond_broadcast(nuauthdatas->reload_cond);
    g_mutex_unlock(nuauthdatas->reload_cond_mutex);
}

static struct nuauth_params* compare_and_update_nuauthparams(struct nuauth_params* current,struct nuauth_params* new)
{
  gboolean restart=FALSE;
  if( strcmp(current->authreq_port, new->authreq_port) != 0){
      g_warning("authreq_port has changed, please restart");
      restart=TRUE;
  }

  if( strcmp(current->userpckt_port, new->userpckt_port) !=0 ){
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

  if( strcmp(current->nufw_srv, new->nufw_srv) != 0  ){
      g_warning("nufw listening ip has changed, please restart");
      restart=TRUE;
  }

  if( strcmp(current->client_srv, new->client_srv) != 0 ){
      g_warning("client listening ip has changed, please restart");
      restart=TRUE;
  }

  if( current->nufw_has_conntrack != new->nufw_has_conntrack  ){
      g_warning("nufw conntrack mode has changed, please restart");
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
      destroy_periods(current->periods);
      free_nuauth_params(current);
      return new;
  } else {
      free_nuauth_params(new);
      return NULL;
  }
}

/** @} */

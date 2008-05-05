/*
 ** Copyright(C) 2005-2007 INL
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

int build_prenuauthconf(struct nuauth_params *prenuauthconf,
			char *gwsrv_addr, policy_t connect_policy)
{
	if ((!prenuauthconf->push) && prenuauthconf->hello_authentication) {
		g_message
		    ("nuauth_hello_authentication required nuauth_push to be 1, resetting to 0");
		prenuauthconf->hello_authentication = 0;
	}

	if (gwsrv_addr) {
		/* parse nufw server address */
		prenuauthconf->authorized_servers =
		    generate_inaddr_list(gwsrv_addr);
	}

	if (prenuauthconf->nufw_has_fixed_timeout) {
		prenuauthconf->nufw_has_conntrack = 1;
	}

	if ((!prenuauthconf->single_user_client_limit) &&
			(!prenuauthconf->single_ip_client_limit) &&
			(connect_policy != POLICY_MULTIPLE_LOGIN)) {
		/* config file has a deprecated option, send warning and
		 * modify value */
		log_message(CRITICAL, DEBUG_AREA_MAIN,
				"nuauth_connect_policy variable is deprecated. DO NOT use it.");
		switch (connect_policy) {
			case POLICY_ONE_LOGIN:
				prenuauthconf->single_user_client_limit = 1;
				break;
			case POLICY_PER_IP_ONE_LOGIN:
				prenuauthconf->single_ip_client_limit = 1;
				break;
			case POLICY_MULTIPLE_LOGIN:
			default:
				break;
		}
	}

	return 1;
}

int init_nuauthconf(struct nuauth_params **result)
{
	struct nuauth_params *conf;
	char *gwsrv_addr = NULL;
	int connect_policy = POLICY_MULTIPLE_LOGIN;

	conf = g_new0(struct nuauth_params, 1);
	*result = conf;

	conf->client_srv = nubase_config_table_get_or_default("nuauth_client_listen_addr", AUTHREQ_CLIENT_LISTEN_ADDR);
	conf->nufw_srv = nubase_config_table_get_or_default("nuauth_nufw_listen_addr", AUTHREQ_NUFW_LISTEN_ADDR);
	gwsrv_addr = nubase_config_table_get_or_default("nufw_gw_addr", GWSRV_ADDR);
	conf->authreq_port = nubase_config_table_get_or_default("nuauth_gw_packet_port", str_itoa(AUTHREQ_PORT));
	conf->userpckt_port = nubase_config_table_get_or_default("nuauth_user_packet_port", str_itoa(USERPCKT_PORT));

	conf->nbuser_check = nubase_config_table_get_or_default_int("nuauth_number_usercheckers", NB_USERCHECK);
	conf->nbacl_check = nubase_config_table_get_or_default_int("nuauth_number_aclcheckers", NB_ACLCHECK);
	conf->nbipauth_check = nubase_config_table_get_or_default_int("nuauth_number_ipauthcheckers", NB_ACLCHECK);
	conf->log_users = nubase_config_table_get_or_default_int("nuauth_log_users", 9);
	conf->log_users_sync = nubase_config_table_get_or_default_int("nuauth_log_users_sync", 0);
	conf->log_users_strict = nubase_config_table_get_or_default_int("nuauth_log_users_strict", 1);
	conf->log_users_without_realm =	nubase_config_table_get_or_default_int("nuauth_log_users_without_realm", 1);
	conf->prio_to_nok = nubase_config_table_get_or_default_int("nuauth_prio_to_nok", 1);
	conf->single_user_client_limit = nubase_config_table_get_or_default_int("nuauth_single_user_client_limit", 0);
	conf->single_ip_client_limit = nubase_config_table_get_or_default_int("nuauth_single_ip_client_limit", 0);
	connect_policy = nubase_config_table_get_or_default_int("nuauth_connect_policy", POLICY_MULTIPLE_LOGIN);
	conf->reject_after_timeout =
	    nubase_config_table_get_or_default_int("nuauth_reject_after_timeout", 0);
	conf->reject_authenticated_drop =
	    nubase_config_table_get_or_default_int("nuauth_reject_authenticated_drop", 0);
	conf->nbloggers = nubase_config_table_get_or_default_int("nuauth_number_loggers", NB_LOGGERS);
	conf->nb_session_loggers =
	    nubase_config_table_get_or_default_int("nuauth_number_session_loggers", NB_LOGGERS);
	conf->nb_auth_checkers =
	    nubase_config_table_get_or_default_int("nuauth_number_authcheckers", NB_AUTHCHECK);
	conf->packet_timeout = nubase_config_table_get_or_default_int("nuauth_packet_timeout", PACKET_TIMEOUT);
	conf->session_duration =
	    nubase_config_table_get_or_default_int("nuauth_session_duration", SESSION_DURATION);
	conf->datas_persistance =
	    nubase_config_table_get_or_default_int("nuauth_datas_persistance", 9);
	conf->push = nubase_config_table_get_or_default_int("nuauth_push_to_client", 1);
	conf->do_ip_authentication =
	    nubase_config_table_get_or_default_int("nuauth_do_ip_authentication", 0);
	conf->acl_cache = nubase_config_table_get_or_default_int("nuauth_acl_cache", 0);
	conf->user_cache = nubase_config_table_get_or_default_int("nuauth_user_cache", 0);
#if USE_UTF8 
	conf->uses_utf8 = nubase_config_table_get_or_default_int("nuauth_uses_utf8", 1);
#else
	conf->uses_utf8 = nubase_config_table_get_or_default_int("nuauth_uses_utf8", 0);
#endif
	conf->hello_authentication =
	    nubase_config_table_get_or_default_int("nuauth_hello_authentication", 0);
	conf->debug_areas = nubase_config_table_get_or_default_int("nuauth_debug_areas", DEFAULT_DEBUG_AREAS);
	conf->debug_level = nubase_config_table_get_or_default_int("nuauth_debug_level", DEFAULT_DEBUG_LEVEL);
	conf->nufw_has_conntrack =
	    nubase_config_table_get_or_default_int("nufw_has_conntrack", 1);
	conf->nufw_has_fixed_timeout =
	    nubase_config_table_get_or_default_int("nufw_has_fixed_timeout", 1);
	conf->nuauth_uses_fake_sasl =
	    nubase_config_table_get_or_default_int("nuauth_uses_fake_sasl", 1);
#ifdef BUILD_NUAUTH_COMMAND
	conf->use_command_server =
	    nubase_config_table_get_or_default_int("nuauth_use_command_server", 1);
#endif
	conf->proto_wait_delay =
	    nubase_config_table_get_or_default_int("nuauth_proto_wait_delay", DEFAULT_PROTO_WAIT_DELAY);
	conf->drop_if_no_logging =
	    nubase_config_table_get_or_default_int("nuauth_drop_if_no_logging", FALSE);
	conf->max_unassigned_messages =
	    nubase_config_table_get_or_default_int("nuauth_max_unassigned_messages", MAX_UNASSIGNED_MESSAGES);
	conf->push_delay =
	    nubase_config_table_get_or_default_int("nuauth_push_delay", PUSH_DELAY);

	if (conf->debug_level > 9) {
		conf->debug_level = 9;
	}

	build_prenuauthconf(conf, gwsrv_addr, connect_policy);

	//g_free(gwsrv_addr);
	return 1;
}

void free_nuauth_params(struct nuauth_params *conf)
{
	destroy_periods(nuauthconf->periods);
	g_free(conf->authreq_port);
	g_free(conf->userpckt_port);
	g_free(conf->authorized_servers);
	g_free(conf->configfile);
}

void apply_new_config(struct nuauth_params *conf)
{
	/* checking nuauth tuning parameters */
	g_thread_pool_set_max_threads(nuauthdatas->user_checkers,
			conf->nbuser_check, NULL);
	g_thread_pool_set_max_threads(nuauthdatas->acl_checkers,
			conf->nbacl_check, NULL);
	if (conf->do_ip_authentication) {
		g_thread_pool_set_max_threads(nuauthdatas->
				ip_authentication_workers,
				conf->nbipauth_check,
				NULL);
	}
	if (conf->log_users_sync) {
		g_thread_pool_set_max_threads(nuauthdatas->
				decisions_workers,
				conf->nbloggers,
				NULL);
	}
	g_thread_pool_set_max_threads(nuauthdatas->user_loggers,
			conf->nbloggers, NULL);
	g_thread_pool_set_max_threads(nuauthdatas->
			user_session_loggers,
			conf->nb_session_loggers,
			NULL);
}

static gboolean compare_nuauthparams(
		struct nuauth_params *current,
		struct nuauth_params *new);

/**
 * exit function if a signal is received in daemon mode.
 *
 * Argument: signal number
 * Return: None
 */
gboolean nuauth_reload(int signum)
{
	struct nuauth_params *newconf = NULL;
	gboolean restart;

	g_message("[+] Reload NuAuth server");
	nuauth_install_signals(FALSE);

	init_nuauthconf(&newconf);
	g_message("nuauth module reloading");

	/* block threads of pool at start */
	block_thread_pools();
	/* we have to wait that all threads are blocked */
	stop_all_thread_pools(TRUE);
	/* unload modules */
	unload_modules();

	/* Only duplicate configfile info, if configfile has not been set */
	if (! newconf->configfile) {
		newconf->configfile = g_strdup(nuauthconf->configfile);
	}

	/* switch conf before loading modules */
	restart = compare_nuauthparams(nuauthconf, newconf);

	/* start "pure" pool threads */
	start_all_thread_pools();

	if (restart == FALSE) {
		apply_new_config(newconf);
		/* debug is set via command line thus duplicate */
		newconf->debug_level = nuauthconf->debug_level;
		free_nuauth_params(nuauthconf);
		g_free(nuauthconf);
		nuauthconf = newconf;
	} else {
		free_nuauth_params(newconf);
	}

	/* reload modules with new conf */
	load_modules();
	/* init period */
	nuauthconf->periods = init_periods(nuauthconf);
	/* ask cache to reset */
	if (nuauthconf->acl_cache) {
		cache_reset(nuauthdatas->acl_cache);
	}

	release_thread_pools();
	nuauth_install_signals(TRUE);

	g_message("[+] NuAuth server reloaded");
	return restart;
}

static gboolean compare_nuauthparams(
		struct nuauth_params *current,
		struct nuauth_params *new)
{
	gboolean restart = FALSE;
	if (strcmp(current->authreq_port, new->authreq_port) != 0) {
		g_warning("authreq_port has changed, please restart");
		restart = TRUE;
	}

	if (strcmp(current->userpckt_port, new->userpckt_port) != 0) {
		g_warning("userpckt_port has changed, please restart");
		restart = TRUE;
	}

	if (current->log_users_sync != new->log_users_sync) {
		g_warning("log_users_sync has changed, please restart");
		restart = TRUE;
	}

	if (current->log_users_strict != new->log_users_strict) {
		g_warning("log_users_strict has changed, please restart");
		restart = TRUE;
	}

	if (current->push != new->push) {
		g_warning
		    ("switch between push and poll mode has been asked, please restart");
		restart = TRUE;
	}

	if (current->acl_cache != new->acl_cache) {
		g_warning
		    ("switch between acl caching or not has been asked, please restart");
		restart = TRUE;
	}

	if (current->user_cache != new->user_cache) {
		g_warning
		    ("switch between user caching or not has been asked, please restart");
		restart = TRUE;
	}

	if (current->hello_authentication != new->hello_authentication) {
		g_warning
		    ("switch on ip authentication feature has been asked, please restart");
		restart = TRUE;
	}

	if (strcmp(current->nufw_srv, new->nufw_srv) != 0) {
		g_warning("nufw listening ip has changed, please restart");
		restart = TRUE;
	}

	if (strcmp(current->client_srv, new->client_srv) != 0) {
		g_warning
		    ("client listening ip has changed, please restart");
		restart = TRUE;
	}

	if (current->nufw_has_conntrack != new->nufw_has_conntrack) {
		g_warning
		    ("nufw conntrack mode has changed, please restart");
		restart = TRUE;
	}

#ifdef BUILD_NUAUTH_COMMAND
	if (current->use_command_server != new->use_command_server) {
		g_warning
		    ("command server option has been modified, please restart");
		restart = TRUE;
	}
#endif

	if (current->do_ip_authentication != new->do_ip_authentication) {
		g_warning
		    ("nuauth_do_ip_authentication has been modified, please restart");
		restart = TRUE;
	}
	return restart;
}

/** @} */

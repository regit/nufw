/*
 ** Copyright(C) 2004-2008 INL
 ** Written by Eric Leblond <regit@inl.fr>
 **
 ** $Id$
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, version 3 of the License.
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

/**
 * \defgroup Nuauth Nuauth
 *
 * @{
 */

/* } */

/*! \file nuauth/authsrv.c
	\brief Main file

	It takes care of init stuffs and runs sheduled tasks at a given interval.
*/


#include <auth_srv.h>
#include <sasl/saslutil.h>
#include "sasl.h"
#include "security.h"
#include <sys/resource.h>	/* setrlimit() */

#include <nussl.h>
#include <nubase.h>

#include "nuauthconf.h"

#ifdef HAVE_GETOPT_H
# include <getopt.h>
#endif

typedef struct {
	int daemonize;
	int debug_level;
	char *configfile;
	char *userpckt_port;
	char *authreq_port;
	char *client_srv;
	char *nufw_srv;
} command_line_params_t;

int nuauth_running = 1;

GList *cleanup_func_list = NULL;

/**
 * Add a cleanup function: it would be called every second.
 * Functions are stored in ::cleanup_func_list list.
 *
 * See also cleanup_func_remove()
 */
void cleanup_func_push(cleanup_func_t func)
{
	cleanup_func_list = g_list_append(cleanup_func_list, func);
}

/**
 * Remove a cleanup function from ::cleanup_func_list list.
 *
 * See also cleanup_func_push()
 */
void cleanup_func_remove(cleanup_func_t func)
{
	cleanup_func_list = g_list_remove(cleanup_func_list, func);
}

/*
 * wait one thread pool
 */
void wait_thread_pool(const char *name, GThreadPool *pool)
{
	gint count = 1;
	while (count) {
		count = g_thread_pool_unprocessed(pool);
		usleep(10000);
	}
	log_message(DEBUG, DEBUG_AREA_MAIN,
			"thread pool '%s' free", name);
}

void wait_all_thread_pools()
{
	wait_thread_pool("session logger", nuauthdatas->user_session_loggers);
	wait_thread_pool("packet logger", nuauthdatas->user_loggers);
	wait_thread_pool("acl checker", nuauthdatas->acl_checkers);
	wait_thread_pool("users worker", nuauthdatas->user_workers);

	if (nuauthconf->log_users_sync) {
		wait_thread_pool("decision worker",
				nuauthdatas->decisions_workers);
	}

	if (nuauthconf->do_ip_authentication) {
		wait_thread_pool("ip auth worker",
				nuauthdatas->ip_authentication_workers);
	}
}

void block_thread_pools()
{
	nuauthdatas->need_reload = 1;
}

void release_thread_pools()
{
	/* liberate threads by broadcasting condition */
	nuauthdatas->need_reload = 0;

	g_mutex_lock(nuauthdatas->reload_cond_mutex);
	g_cond_broadcast(nuauthdatas->reload_cond);
	g_mutex_unlock(nuauthdatas->reload_cond_mutex);
}

void start_all_thread_pools()
{
	if (nuauthconf->do_ip_authentication) {
		/* create thread of pool */
		nuauthdatas->ip_authentication_workers =
		    g_thread_pool_new((GFunc) external_ip_auth, NULL,
				      nuauthconf->nbipauth_check,
				      POOL_TYPE, NULL);
	} else {
		nuauthdatas->ip_authentication_workers = NULL;
	}
	/* create acl checker workers */
	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN, "Creating %d acl checker threads",
		    nuauthconf->nbacl_check);
	nuauthdatas->acl_checkers =
	    g_thread_pool_new((GFunc) acl_check_and_decide, NULL,
			      nuauthconf->nbacl_check, POOL_TYPE, NULL);

	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN, "Creating %d user worker threads",
		    nuauthconf->nbuser_check);
	nuauthdatas->user_workers =
	    g_thread_pool_new((GFunc) user_worker, NULL,
			      nuauthconf->nbuser_check, POOL_TYPE, NULL);

	/* create user logger workers */
	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN, "Creating %d user logger threads",
		    nuauthconf->nbloggers);
	nuauthdatas->user_loggers =
	    g_thread_pool_new((GFunc) real_log_user_packet, NULL,
			      nuauthconf->nbloggers, POOL_TYPE, NULL);
	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		    "Creating %d user session logger threads",
		    nuauthconf->nbloggers);
	nuauthdatas->user_session_loggers =
	    g_thread_pool_new((GFunc) log_user_session_thread, NULL,
			      nuauthconf->nbloggers, POOL_TYPE, NULL);

	/* create decisions workers (if needed) */
	if (nuauthconf->log_users_sync) {
		log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
			    "Creating %d decision worker threads",
			    nuauthconf->nbloggers);
		nuauthdatas->decisions_workers =
		    g_thread_pool_new((GFunc) decisions_queue_work, NULL,
				      nuauthconf->nbloggers, POOL_TYPE,
				      NULL);
	}
}

/**
 * Stop one thread pool
 */
void stop_thread_pool(const char *name, GThreadPool **pool)
{
	log_message(DEBUG, DEBUG_AREA_MAIN,
			"Stopping thread pool '%s'", name);
	g_thread_pool_free(*pool, TRUE, TRUE);
	*pool = NULL;
}

/**
 * Stop all nuauth thread pools
 * If soft is true, destroy pools.
 */
void stop_all_thread_pools(gboolean soft)
{
	/* end logging threads */
	if (soft) {
		stop_thread_pool("session logger", &nuauthdatas->user_session_loggers);
		stop_thread_pool("packet logger", &nuauthdatas->user_loggers);
		stop_thread_pool("acl checker", &nuauthdatas->acl_checkers);
		stop_thread_pool("users workers", &nuauthdatas->user_workers);

		if (nuauthconf->log_users_sync) {
			stop_thread_pool("decision worker",
					&nuauthdatas->decisions_workers);
		}

		if (nuauthconf->do_ip_authentication) {
			stop_thread_pool("ip auth worker",
					&nuauthdatas->ip_authentication_workers);
		}
	}
	g_thread_pool_stop_unused_threads();
}
/**
 * Ask all threads to stop (by locking their mutex), and then wait
 * until they really stop (if wait is TRUE) using g_thread_join()
 * and g_thread_pool_free().
 *
 * \param wait If wait is TRUE, the function will block until all threads
 *             stopped. Else, it will just ask all threads to stop.
 */
void stop_threads(gboolean wait)
{
	log_message(INFO, DEBUG_AREA_MAIN, "Asking threads to stop.");

#ifdef BUILD_NUAUTH_COMMAND
	/* stop command server */
	if (nuauthconf->use_command_server) {
		thread_stop(&nuauthdatas->command_thread);
	}
#endif

	/* ask theads to stop */
	if (nuauthconf->push && nuauthconf->hello_authentication) {
		thread_stop(&nuauthdatas->localid_auth_thread);
	}

	/* wait thread end */
	if (wait) {
		log_message(INFO, DEBUG_AREA_MAIN, "Waiting for threads end ...");
	}

	/* kill push worker */
	thread_stop(&nuauthdatas->tls_pusher);
	if (wait) {
		log_message(DEBUG, DEBUG_AREA_MAIN, "Waiting for thread 'tls pusher'");
		g_thread_join(nuauthdatas->tls_pusher.thread);
	}

	/* kill entries point */
	thread_list_stop_ev(nuauthdatas->tls_auth_servers);
	thread_list_stop(nuauthdatas->tls_nufw_servers);
	thread_stop(&nuauthdatas->pre_client_thread);
	if (wait) {
		thread_list_wait_end(nuauthdatas->tls_auth_servers);
		thread_list_wait_end(nuauthdatas->tls_nufw_servers);
		thread_wait_end(&nuauthdatas->pre_client_thread);
	}

	/* Close nufw and client connections */
	log_message(INFO, DEBUG_AREA_MAIN, "Closing nufw connections");
	close_nufw_servers();

	log_message(INFO, DEBUG_AREA_MAIN, "Closing client connections");
	close_clients();

	thread_stop(&nuauthdatas->limited_connections_handler);
	thread_stop(&nuauthdatas->search_and_fill_worker);
	if (wait) {
		thread_wait_end(&nuauthdatas->limited_connections_handler);
		thread_wait_end(&nuauthdatas->search_and_fill_worker);
	}

#ifdef BUILD_NUAUTH_COMMAND
	if (nuauthconf->use_command_server) {
		thread_wait_end(&nuauthdatas->command_thread);
	}
#endif
	if (nuauthconf->push && nuauthconf->hello_authentication && wait) {
		thread_wait_end(&nuauthdatas->localid_auth_thread);
	}

	stop_all_thread_pools(wait);
	/* done! */
	log_message(INFO, DEBUG_AREA_MAIN, "Threads stopped.");
}

void free_threads()
{
	/* free all thread mutex */
	thread_destroy(&nuauthdatas->tls_pusher);
	thread_destroy(&nuauthdatas->search_and_fill_worker);
	thread_list_destroy(nuauthdatas->tls_auth_servers);
	thread_list_destroy(nuauthdatas->tls_nufw_servers);
	thread_destroy(&nuauthdatas->limited_connections_handler);
	if (nuauthconf->push && nuauthconf->hello_authentication) {
		thread_destroy(&nuauthdatas->localid_auth_thread);
	}
}

/**
 * Delete all items (call g_free()) of nuauthdatas->tls_push_queue queue.
 */
void clear_push_queue()
{
	struct internal_message *message;
	do
	{
		message = g_async_queue_try_pop(nuauthdatas->tls_push_queue);
		if (!message) break;

		if (message->type == INSERT_MESSAGE
		    || message->type == WARN_MESSAGE)
		{
			g_free(message->datas);
		}
		g_free(message);
	} while (1);
}

/**
 * Deinit NuAuth:
 *    - Stop NuAuth: close_nufw_servers(), close_clients(), end_tls(), end_audit() ;
 *    - Free memory ;
 *    - Unload modules: unload_modules() ;
 *    - Destroy pid file ;
 *    - And finally exit.
*
 */
void nuauth_deinit(gboolean soft)
{
	log_message(CRITICAL, DEBUG_AREA_MAIN, "[+] NuAuth deinit");
#if 0
	signal(SIGTERM, SIG_DFL);
	signal(SIGKILL, SIG_DFL);
	signal(SIGHUP, SIG_DFL);
#endif

	stop_threads(soft);

	log_message(INFO, DEBUG_AREA_MAIN, "Unloading modules");
	unload_modules();

#if 0
	end_tls();
#endif

	log_message(INFO, DEBUG_AREA_MAIN, "Ending audit");
	end_audit();

	log_message(INFO, DEBUG_AREA_MAIN, "Freeing memory");
	free_nuauth_params(nuauthconf);
	if (nuauthconf->acl_cache) {
		cache_destroy(nuauthdatas->acl_cache);
	}
	if (nuauthconf->user_cache) {
		cache_destroy(nuauthdatas->user_cache);
	}
	g_free(nuauthdatas->program_fullpath);
	free_threads();
	clear_push_queue();

	g_hash_table_destroy(conn_list);

	g_static_mutex_free(&insert_mutex);

	/* destroy pid file */
	unlink(NUAUTH_PID_FILE);
}

/**
 * Call this function to stop nuauth.
 */
void nuauth_ask_exit()
{
	if (g_atomic_int_compare_and_exchange(&nuauth_running, 1, 0)) {
		kill(getpid(), SIGTERM);
	}
}

/**
 * This is exit() handler. It's used on fatal error of NuAuth.
 * nuauth_cleanup() also call it, but this call is ignored,
 * because nuauth_cleanup() set nuauth_running to 0.
 */
void nuauth_atexit()
{
	if (g_atomic_int_compare_and_exchange(&nuauth_running, 1, 0)) {
		log_message(FATAL, DEBUG_AREA_MAIN,
			    "[+] Stopping NuAuth server (exit)");
		nuauth_deinit(FALSE);
	}
}

/**
 * Function called when a SIGTERM or SIGINT is received:
 *    - Reinstall old signal handlers (for SIGTERM and SIGINT) ;
 *    - Deinit NuAuth: call nuauth_deinit() (in soft mode)
 *
 * \param recv_signal Code of raised signal
 */
void nuauth_cleanup(int recv_signal)
{
	(void) g_atomic_int_dec_and_test(&nuauth_running);
	/* first of all, reinstall old handlers (ignore errors) */
	nuauth_install_signals(FALSE);

	if (recv_signal == SIGINT)
		log_message(CRITICAL, DEBUG_AREA_MAIN,
			    "[+] Stopping NuAuth server (SIGINT)");
	else if (recv_signal == SIGTERM)
		log_message(CRITICAL, DEBUG_AREA_MAIN,
			    "[+] Stopping NuAuth server (SIGTERM)");

	nuauth_deinit(TRUE);

	log_message(FATAL, DEBUG_AREA_MAIN, "[+] NuAuth exiting");
	exit(EXIT_SUCCESS);
}

/**
 * Daemonize the process:
 *    - If a pid file already exists: if it's valid, just quit, else delete it
 *    - Call fork(): the child will just write the pid in the pid file
 *      and then exit
 *    - Set current directory to "/"
 *    - Call setsid()
 *    - Install log handler: call set_glib_loghandlers(),
 *      close stdin, stdout and stderr
 */
void daemonize()
{
	FILE *pf;
	pid_t pidf;

	if (access(NUAUTH_PID_FILE, R_OK) == 0) {
		/* Check if the existing process is still alive. */
		pid_t pidv;

		pf = fopen(NUAUTH_PID_FILE, "r");
		if (pf != NULL &&
		    fscanf(pf, "%d", &pidv) == 1 && kill(pidv, 0) == 0) {
			fclose(pf);
			log_message(FATAL, DEBUG_AREA_MAIN,
			    "pid file exists. Is nuauth already running? Aborting!\n");
			exit(EXIT_FAILURE);
		}

		if (pf != NULL)
			fclose(pf);
	}

	pidf = fork();
	if (pidf < 0) {
		log_message(FATAL, DEBUG_AREA_MAIN, "Unable to fork");
		exit(EXIT_FAILURE);	/* this should be useless !! */
	} else {
		if (pidf > 0) {
			/* child process */
			pf = fopen(NUAUTH_PID_FILE, "w");
			if (pf != NULL) {
				fprintf(pf, "%d\n", (int) pidf);
				fclose(pf);
			} else {
				printf("Dying, can not create PID file \""
				       NUAUTH_PID_FILE "\".\n");
				exit(EXIT_FAILURE);
			}
			exit(EXIT_SUCCESS);
		}
	}

	setsid();

	set_glib_loghandlers();

	/* Close stdin, stdout, stderr. */
	(void) close(STDIN_FILENO);
	(void) close(STDOUT_FILENO);
	(void) close(STDERR_FILENO);
}

static struct option long_options[] = {
	{"help", 0, NULL, 'h'},
	{"config", 1, NULL, 'c'},
	{"daemon", 0, NULL, 'D'},
	{"version", 0, NULL, 'V'},
	{"verbose", 0, NULL, 'v'},
	{"nufw-port", 1, NULL, 'p'},
	{"client-port", 1, NULL, 'l'},
	{"nufw-address", 1, NULL, 'L'},
	{"client-address", 1, NULL, 'C'},
	{"timeout", 1, NULL, 't'},

	{0, 0, 0, 0}
};


/**
 * Display all command line options of NuAuth
 */
void print_usage()
{
	fprintf(stdout,
		"nuauth [-hDVv[v[v[v[v[v[v[v[v]]]]]]]]] [-l user_packet_port] [-C local_addr] [-L local_addr] \n"
		"\t\t[-t packet_timeout]\n"
		"\t-h (--help          ): display this help and exit\n"
		"\t-c (--config        ): use alternate configuration file\n"
		"\t-D (--daemon        ): run as a daemon, send debug messages to syslog (else stdout/stderr)\n"
		"\t-V (--version       ): display version and exit\n"
		"\t-v (--verbose       ): increase debug level (+1 for each 'v') (max useful number : 10)\n"
		"\t-p (--nufw-port     ): specify listening TCP port (this port waits for nufw) (default : 4128)\n"
		"\t-l (--client-port   ): specify listening TCP port (this port waits for clients) (default : 4129)\n"
		"\t-L (--nufw-address  ): specify NUFW listening IP address (local) (this address waits for nufw data) (default : 127.0.0.1)\n"
		"\t-C (--client-address): specify clients listening IP address (local) (this address waits for clients auth) (default : 0.0.0.0)\n"
		"\t-t (--timeout       ): timeout to forget about packets when they don't match (default : 15 s)\n");
}

/**
 * Parse command line options using getopt library.
 */
void parse_options(int argc, char **argv, command_line_params_t * params)
{
	char *options_list = "DhVvc:l:L:C:p:t:T:";
	int option;
	int local_debug_level = 0;

	/*parse options */
	while ((option = getopt_long(argc, argv, options_list, long_options, NULL)) != -1) {
		switch (option) {
		case 'c':
			/* configuration file */
			g_free(params->configfile);
			params->configfile = g_strdup(optarg);
			break;

		case 'V':
			fprintf(stdout, "nuauth (version %s)\n",
				NUAUTH_FULL_VERSION);
			exit(EXIT_SUCCESS);
			break;

		case 'v':
			local_debug_level++;
			break;

		case 'l':
			/* port we listen for auth answer */
			g_free(params->userpckt_port);
			params->userpckt_port = g_strdup(optarg);
			break;

		case 'p':
			/* port we listen for auth answer */
			g_free(params->authreq_port);
			params->authreq_port = g_strdup(optarg);
			break;

		case 'L':
			/* Address we listen on for NUFW originating packets */
			g_free(params->nufw_srv);
			params->nufw_srv = g_strdup(optarg);
			break;

		case 'C':
			/* Address we listen on for client originating packets */
			g_free(params->client_srv);
			params->client_srv = g_strdup(optarg);
			break;

		case 't':
			/* packet timeout */
			sscanf(optarg, "%d",
			       &(nuauthconf->packet_timeout));
			break;

		case 'D':
			params->daemonize = 1;
			break;

		case 'h':
			print_usage();
			exit(EXIT_SUCCESS);
		}
	}
	if (local_debug_level) {
		params->debug_level = local_debug_level;
	}
}

void no_action_signals(int recv_signal);

/**
 * Install all signals used in NuAuth:
 *    - SIGTERM and SIGINT: install nuauth_cleanup() handler ;
 *    - SIGHUP: install nuauth_reload() handler ;
 *    - SIGPIPE: ignore signal.
 *
 * \see init_audit()
 */
void nuauth_install_signals(gboolean sig_action)
{
	struct sigaction action;

	atexit(nuauth_atexit);

	memset(&action, 0, sizeof(action));

	if (sig_action) {
		action.sa_handler = nuauth_cleanup;
	} else {
		action.sa_handler = no_action_signals;
	}
	sigemptyset(&(action.sa_mask));
	action.sa_flags = 0;

	/* intercept SIGTERM */
	if (sigaction(SIGTERM, &action, &nuauthdatas->old_sigterm_hdl) !=
	    0) {
		log_message(FATAL, DEBUG_AREA_MAIN, "Error modifying sigaction");
		exit(EXIT_FAILURE);
	}

	/* intercept SIGINT */
	if (sigaction(SIGINT, &action, &nuauthdatas->old_sigint_hdl) != 0) {
		log_message(FATAL, DEBUG_AREA_MAIN, "Error modifying sigaction");
		exit(EXIT_FAILURE);
	}

	/* intercept SIGHUP */
	memset(&action, 0, sizeof(action));
	action.sa_handler = (__sighandler_t) nuauth_reload;
	sigemptyset(&(action.sa_mask));
	action.sa_flags = 0;
	if (sigaction(SIGHUP, &action, &nuauthdatas->old_sighup_hdl) != 0) {
		log_message(FATAL, DEBUG_AREA_MAIN, "Error modifying sigaction");
		exit(EXIT_FAILURE);
	}

	/* ignore SIGPIPE */
	signal(SIGPIPE, SIG_IGN);
}

void no_action_signals(int recv_signal)
{
	switch (recv_signal) {
		case SIGINT:
		log_message(CRITICAL, DEBUG_AREA_MAIN,
			    "[+] Nuauth received SIGINT (leaving)");
		tls_common_deinit();
		exit(EXIT_FAILURE);
		break;
		case SIGTERM:
		log_message(CRITICAL, DEBUG_AREA_MAIN,
				"[+] Nuauth received SIGTERM (leaving)");
		tls_common_deinit();
		exit(EXIT_FAILURE);
		break;
		case SIGHUP:
		log_message(CRITICAL, DEBUG_AREA_MAIN,
				"[+] Nuauth received SIGHUP (ignoring)");
		tls_common_deinit();
		break;
	}
}

#define OVERWRITE_DATA(x) \
	if (params->x) { \
		g_free(nuauthconf->x); \
		nuauthconf->x = g_strdup(params->x); \
	}

static void nuauthconf_from_cmdline(command_line_params_t *params)
{
	OVERWRITE_DATA(client_srv);
	OVERWRITE_DATA(nufw_srv);
	OVERWRITE_DATA(userpckt_port);
	OVERWRITE_DATA(authreq_port);

	nuauthconf->debug_level = params->debug_level;
}

#undef OVERWRITE_DATA

/**
 * Configure NuAuth:
 *   - Init. glib threads: g_thread_init() ;
 *   - Read command line options: parse_options() ;
 *   - Read NuAuth configuration file: init_nuauthconf() ;
 *   - Build configuration options: build_prenuauthconf() ;
 *   - Init SSL library: nussl_init() ;
 *   - Create credentials: create_x509_credentials() ;
 *   - Daemonize the process if asked: daemonize().
 */
void configure_app(int argc, char **argv)
{
	command_line_params_t params;
	int ret;
	struct rlimit r_limit;
	struct nuauth_params initconf;
	struct nuauth_params *conf;

	/* Avoid creation of core file which may contains username and password */
	if (getrlimit(RLIMIT_CORE, &r_limit) == 0) {
#ifdef DEBUG_ENABLE
		r_limit.rlim_cur = RLIM_INFINITY;
#else
		r_limit.rlim_cur = 0;
#endif
		setrlimit(RLIMIT_CORE, &r_limit);
	}

	if (getrlimit(RLIMIT_NOFILE, &r_limit) == 0) {
		r_limit.rlim_cur = 8096;
		r_limit.rlim_max = 8096;
		setrlimit(RLIMIT_NOFILE, &r_limit);
	}

#ifndef DEBUG_ENABLE
	/* Move to root directory to not block current working directory */
	(void) chdir("/");
#endif

#ifdef DEBUG_MEMORY
	g_mem_set_vtable(glib_mem_profiler_table);
#endif

	/* Initialize glib thread system */
	g_thread_init(NULL);
	g_thread_pool_set_max_unused_threads(5);

	/* init nuauthdatas */
	nuauthdatas = g_new0(struct nuauth_datas, 1);
	nuauthdatas->is_starting = TRUE;
	nuauthdatas->reload_cond = g_cond_new();
	nuauthdatas->reload_cond_mutex = g_mutex_new();
	nuauthdatas->program_fullpath = g_strdup(argv[0]);


	/* set default parameters */
	params.debug_level = 0;
	params.daemonize = 0;
	params.client_srv = NULL;
	params.nufw_srv = NULL;
	params.userpckt_port = NULL;
	params.authreq_port = NULL;
	params.configfile = NULL;

	nuauthconf = &initconf;
	/* check if configuration file is not given on command line */
	parse_options(argc, argv, &params);

	if (params.debug_level) {
		nuauthconf->debug_level = params.debug_level;
	} else {
		nuauthconf->debug_level = DEFAULT_DEBUG_LEVEL;
	}
	nuauthconf->debug_areas = DEFAULT_DEBUG_AREAS;

	if (params.configfile == NULL) {
		nuauthconf->configfile = g_strdup(DEFAULT_CONF_FILE);
	} else {
		nuauthconf->configfile = g_strdup(params.configfile);
	}

	ret = nuauth_parse_configuration(nuauthconf->configfile);
	if (ret < 0) {
		log_message(FATAL, DEBUG_AREA_MAIN,
			    "Cannot load configuration (file '%s')",
			    nuauthconf->configfile);
		exit(EXIT_FAILURE);
	}

	/* load configuration */
	if (!init_nuauthconf(&conf)) {
		log_message(FATAL, DEBUG_AREA_MAIN,
				"Unable to load configuration");
		exit(EXIT_FAILURE);
	}

	conf->configfile = nuauthconf->configfile;
	nuauthconf = conf;
	/* build configuration by overwritting config file option by
	 * command line one */
	nuauthconf_from_cmdline(&params);

	build_prenuauthconf(nuauthconf, NULL, 0);

	ret = nussl_init();
	if ( ret != NUSSL_OK ) {
		log_message(FATAL, DEBUG_AREA_MAIN,
			"FATAL ERROR: NuSSL global initialisation failed.");
		exit(EXIT_FAILURE);

	}

	if (nuauthconf->uses_utf8) {
		setlocale(LC_ALL, "");
	}

	/* debug cannot be above 10 */
	if (nuauthconf->debug_level > MAX_DEBUG_LEVEL)
		nuauthconf->debug_level = MAX_DEBUG_LEVEL;
	if (nuauthconf->debug_level < MIN_DEBUG_LEVEL)
		nuauthconf->debug_level = MIN_DEBUG_LEVEL;
	log_message(INFO, DEBUG_AREA_MAIN,
			"Debug_level is %i", nuauthconf->debug_level);

#if 0
	/* init credential */
	if (! create_x509_credentials()) {
		log_area_printf(DEBUG_AREA_MAIN, DEBUG_LEVEL_FATAL,
				"Certificate initialization failed");
		exit(EXIT_FAILURE);
	}
#endif
	/* free command line structure */
	g_free(params.client_srv);
	g_free(params.nufw_srv);
	g_free(params.userpckt_port);
	g_free(params.authreq_port);
	g_free(params.configfile);

	/* init gcrypt and gnutls */
	if (params.daemonize == 1) {
		daemonize();
	} else {
		log_message(FATAL, DEBUG_AREA_MAIN,
				"[+] NuAuth ($Revision$) with config %s",
				nuauthconf->configfile);
		log_message(FATAL, DEBUG_AREA_MAIN,
		"Nuauth started in foreground (without -D option), "
		"logging on stderr and stdout only (no syslog)");
	}

	/* declare default capabilities */
	register_client_capa("HELLO", &(nuauthdatas->hello_capa));
	register_client_capa("TCP", &(nuauthdatas->tcp_capa));
	register_client_capa("UDP", &(nuauthdatas->udp_capa));
}

/**
 * Initialize all data:
 *   - Create different queues:
 *      - tls_push_queue: read in push_worker() ;
 *      - connections_queue: read in search_and_fill() ;
 *      - localid_auth_queue: read in localid_auth().
 *   - Create hash table ::conn_list
 *   - Init. modules: init_modules_system(), load_modules()
 *   - Init. periods: init_periods()
 *   - Init. cache: init_acl_cache() and init_user_cache() (if enabled)
 *   - Create thread pools:
 *      - ip_authentication_workers with external_ip_auth() (if enabled) ;
 *      - acl_checkers with acl_check_and_decide() ;
 *      - user_loggers with real_log_user_packet() ;
 *      - user_session_loggers with log_user_session_thread() ;
 *      - decisions_workers with decisions_queue_work().
 *   - Create threads:
 *      - tls_pusher with push_worker() ;
 *      - search_and_fill_worker with search_and_fill() ;
 *      - localid_auth_thread with localid_auth() (if needed) ;
 *      - tls_auth_servers with tls_user_start_servers() ;
 *      - tls_nufw_servers with tls_nufw_start_servers() ;
 *      - limited_connections_handler with limited_connection_handler().
 *
 * Other queue, threads, etc. are created elsewhere:
 *      - in tls_user_init(): tls_sasl_worker thread pool, tls_sasl_connect().
 */
void init_nuauthdata()
{
	block_thread_pools();
	nuauthdatas->tls_push_queue = g_async_queue_new();
	if (!nuauthdatas->tls_push_queue)
		exit(EXIT_FAILURE);

	/* initialize packets list */
	conn_list = g_hash_table_new_full((GHashFunc) hash_connection,
					  (GEqualFunc) tracking_equal,
					  NULL, (GDestroyNotify)
					  free_connection);

	/* async queue initialisation */
	nuauthdatas->connections_queue = g_async_queue_new();
	if (!nuauthdatas->connections_queue)
		exit(EXIT_FAILURE);

	init_protocol_extension(nuauthdatas);

	/* init and load modules */
	init_modules_system();
	if (!load_modules())
		exit(EXIT_FAILURE);

	/* init periods */
	nuauthconf->periods = init_periods(nuauthconf);

	if (nuauthconf->acl_cache)
		init_acl_cache();

	/* create user cache thread */
	if (nuauthconf->user_cache)
		init_user_cache();

	start_all_thread_pools();

	null_message = g_new0(struct cache_message, 1);
	null_queue_datas = g_new0(gchar, 1);

	/* init private datas for pool thread */
	nuauthdatas->aclqueue =
	    g_private_new((GDestroyNotify) g_async_queue_unref);
	nuauthdatas->userqueue =
	    g_private_new((GDestroyNotify) g_async_queue_unref);

	g_static_mutex_init(&insert_mutex);
	/* create thread for search_and_fill thread */
	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		    "Creating search_and_fill thread");
	thread_new(&nuauthdatas->search_and_fill_worker,
		      "search&fill", search_and_fill);

	if (nuauthconf->push && nuauthconf->hello_authentication) {
		log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
			    "Creating hello mode authentication thread");
		nuauthdatas->localid_auth_queue = g_async_queue_new();
		thread_new(&nuauthdatas->localid_auth_thread,
			      "localid", localid_auth);
	}

#ifdef BUILD_NUAUTH_COMMAND
	if (nuauthconf->use_command_server) {
		log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
			    "Creating command thread");
		thread_new(&nuauthdatas->command_thread,
			      "command", command_server);
	}
#endif

	/* create thread for client request sender */
	thread_new(&nuauthdatas->tls_pusher, "tls pusher", push_worker);

	if (nuauthconf->nufw_has_conntrack) {
		thread_new(&nuauthdatas->limited_connections_handler,
			      "limited connections",
			      limited_connection_handler);
	}

	/* create TLS authentication server threads (auth + nufw) */
	tls_common_init();

	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		    "Creating tls authentication server threads");
	tls_user_start_servers(nuauthdatas->tls_auth_servers);

	log_message(VERBOSE_DEBUG, DEBUG_AREA_MAIN,
		    "Creating tls nufw server threads");

	tls_nufw_start_servers(nuauthdatas->tls_nufw_servers);

	log_message(INFO, DEBUG_AREA_MAIN, "Threads system started");
	release_thread_pools();
	nuauthdatas->is_starting = FALSE;
}

/**
 * Function called every second to cleanup things:
 *   - remove old connections
 *   - refresh ACL cache
 *   - refresh localid auth cache
 *   - refresh limited connection
 */
void main_cleanup()
{
	struct cache_message *cmessage;
	struct internal_message *int_message;

	/* remove old connections */
	clean_connections_list();

	/* info message about thread pools */
	if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO, DEBUG_AREA_MAIN)) {
		if (g_thread_pool_unprocessed(nuauthdatas->user_workers)
		    || g_thread_pool_unprocessed(nuauthdatas->
						 acl_checkers)
		    || g_thread_pool_unprocessed(nuauthdatas->
						 user_loggers)) {
			g_message
			    ("%u user/%u acl/%u log unassigned task(s), %d "
			     "connection(s)",
			     g_thread_pool_unprocessed(nuauthdatas->
						       user_workers),
			     g_thread_pool_unprocessed(nuauthdatas->
						       acl_checkers),
			     g_thread_pool_unprocessed(nuauthdatas->
						       user_loggers),
			     g_hash_table_size(conn_list)
			    );
		}
	}

	act_on_loggers_processing();

	if (nuauthconf->acl_cache) {
		/* send refresh message to acl cache thread */
		cmessage = g_new0(struct cache_message, 1);
		cmessage->type = REFRESH_MESSAGE;
		g_async_queue_push(nuauthdatas->acl_cache->queue,
				   cmessage);
	}

	if (nuauthconf->push && nuauthconf->hello_authentication) {
		/* refresh localid_auth_queue queue */
		int_message = g_new0(struct internal_message, 1);
		int_message->type = REFRESH_MESSAGE;
		g_async_queue_push(nuauthdatas->localid_auth_queue,
				   int_message);
	}

	if (nuauthconf->nufw_has_conntrack) {
		/* refresh limited_connections_queue queue */
		int_message = g_new0(struct internal_message, 1);
		int_message->type = REFRESH_MESSAGE;
		g_async_queue_push(nuauthdatas->limited_connections_queue,
				   int_message);
	}
}

/**
 * Main loop: refresh connection queue and all other queues
 */
void nuauth_main_loop()
{
	struct timespec sleep;
	GList *cleanup_it;
	GTimer *timer;

	log_message(FATAL, DEBUG_AREA_MAIN, "[+] NuAuth started.");

	/* create timer and add main cleanup function to cleanup list */
	timer = g_timer_new();
	cleanup_func_push(main_cleanup);
	cleanup_func_push(kill_expired_clients_session);

	/* first sleep is one full second */
	sleep.tv_sec = 1;
	sleep.tv_nsec = 0;

	/*
	 * Main loop: call functions listed in ::cleanup_func_list every second.
	 * If functions take long time, next sleep will be shorter.
	 */
	for (;;) {
		/* a little sleep (one second) */
		nanosleep(&sleep, NULL);

		for (cleanup_it = cleanup_func_list;
		     cleanup_it != NULL; cleanup_it = cleanup_it->next) {
			cleanup_func_t cleanup = cleanup_it->data;
			cleanup();
		}
		sleep.tv_sec = 1;
		sleep.tv_nsec = 0;
	}
	g_timer_destroy(timer);
}

/**
 * NuAuth entry point:
 *   - Configure application with: configure_app()
 *   - Install signals: nuauth_install_signals()
 *   - Init. all data: init_nuauthdata()
 *   - Init. autdit: init_audit()
 *   - Run main loop: nuauth_main_loop()
 */
int main(int argc, char *argv[])
{
	configure_app(argc, argv);
	init_nuauthdata();
	nuauth_install_signals(TRUE);
	init_audit();
	nuauth_main_loop();
	return EXIT_SUCCESS;
}

/** @} */

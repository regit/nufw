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
#if 0
#ifdef G_THREADS_IMPL_POSIX
//#warning "this may be a source of problems"
#include <pthread.h>
#ifndef GCRY_THREAD
#define GCRY_THREAD 1
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif
#else
#error "Code need to be written to have gcrypt support other threading type"
#endif
#endif

#include "tls.h"
#include "sasl.h"

/* gcrypt init function */
static int gcry_gthread_mutex_init (void **priv)			     //to check 
{									      
	GMutex* lock = g_mutex_new();
	if (!lock)								      
		return ENOMEM;							      
	*priv = lock;							      
	return 0;								      
}									      

static int gcry_gthread_mutex_destroy (void **lock)			      
{ 
	g_mutex_free (*lock);
	return 0; 
}

static int gcry_gthread_mutex_lock (void **lock)			      
{ 
	g_mutex_lock(*lock);
	return 0;
}				      

static int gcry_gthread_mutex_unlock (void **lock)			      
{ 
	g_mutex_unlock(*lock);
	return 0;
}				      

static struct gcry_thread_cbs gcry_threads_gthread =			      
{
	GCRY_THREAD_OPTION_USER, NULL,					      
	gcry_gthread_mutex_init, gcry_gthread_mutex_destroy,			      
	gcry_gthread_mutex_lock, gcry_gthread_mutex_unlock 
};


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
	GThread *tls_auth_server,
		*tls_nufw_server,
		*tls_pusher,
		*search_and_fill_worker,
		*localid_auth_thread;
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
	int nbipauth_check=NB_ACLCHECK;
	int nbuser_check=NB_USERCHECK;
	int nuauth_number_loggers=NB_ACLCHECK;
confparams nuauth_vars[] = {
	{ "nuauth_client_listen_addr" ,  G_TOKEN_STRING, 0 , g_strdup(AUTHREQ_CLIENT_LISTEN_ADDR) },
	{ "nuauth_nufw_listen_addr" ,  G_TOKEN_STRING, 0 , g_strdup(AUTHREQ_NUFW_LISTEN_ADDR) },
	{ "nuauth_gw_packet_port" , G_TOKEN_INT , AUTHREQ_PORT,NULL },
	{ "nuauth_user_packet_port" , G_TOKEN_INT , USERPCKT_PORT ,NULL},
	{ "nufw_gw_addr" , G_TOKEN_STRING , 0, GWSRV_ADDR },
	{ "nuauth_packet_timeout" , G_TOKEN_INT , PACKET_TIMEOUT, NULL },
	{ "nuauth_number_usercheckers" , G_TOKEN_INT , NB_USERCHECK, NULL},
	{ "nuauth_number_aclcheckers" , G_TOKEN_INT , NB_ACLCHECK, NULL },
	{ "nuauth_number_ipauthcheckers" , G_TOKEN_INT , NB_ACLCHECK, NULL },
	{ "nuauth_number_loggers" , G_TOKEN_INT , NB_LOGGERS, NULL },
	{ "nuauth_log_users" , G_TOKEN_INT , 1, NULL },
	{ "nuauth_log_users_sync" , G_TOKEN_INT , 0, NULL },
	{ "nuauth_log_users_strict" , G_TOKEN_INT , 1, NULL },
	{ "nuauth_log_users_without_realm" , G_TOKEN_INT , 1, NULL },
        { "nuauth_prio_to_nok" , G_TOKEN_INT , 1, NULL },
	{ "nuauth_datas_persistance" , G_TOKEN_INT , 10, NULL },
	{ "nuauth_aclcheck_state_ready" , G_TOKEN_INT , 1,NULL },
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
	tracking empty_header;
	gpointer vpointer;
	pid_t pidf;
	struct hostent *nufw_list_srv, *client_list_srv;
	struct sigaction action;
	gchar *nuauth_multi_users=NULL;
	gchar *nuauth_multi_servers=NULL;

	/* initialize variables */

	authreq_port = AUTHREQ_PORT;
	userpckt_port = USERPCKT_PORT; 
	packet_timeout = PACKET_TIMEOUT;
	nuauth_prio_to_nok= PRIO_TO_NOK;
	nuauth_push=1;
	nuauth_do_ip_authentication=0;
	nuauth_acl_cache=0;
	nuauth_user_cache=0;


	/* 
	 * Minimum debug_level value is 2 -> for 1) fatal and 2) critical messages to always
	 * be outputed
	 */
	debug_level=0;
	debug_areas=DEFAULT_DEBUG_AREAS;



        /* init gcrypt and gnutls */
//        gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_gthread);

       	/* Initialize glib thread system */
	g_thread_init(NULL);
	our_sasl_init();
	g_thread_pool_set_max_unused_threads (5);
        gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_gthread);

	gnutls_global_init();
	/* initi credential */
	create_x509_credentials();

	tls_push = g_async_queue_new ();
	if (!tls_push)
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


	/* parse conf file */
	parse_conffile(configfile,sizeof(nuauth_vars)/sizeof(confparams),nuauth_vars);
	/* set variable value from config file */

	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_client_listen_addr");
	nuauth_client_listen_addr=(char *)(vpointer) ; //);//?vpointer:nuauth_client_listen_addr);
	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_nufw_listen_addr");
	nuauth_nufw_listen_addr=(char *)(vpointer);//?vpointer:nuauth_nufw_listen_addr);
	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nufw_gw_addr");
	gwsrv_addr=(char*)(vpointer);//?vpointer:gwsrv_addr);
	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_gw_packet_port");
	authreq_port=*(int*)(vpointer);//?vpointer:&authreq_port);
	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_user_packet_port");
	userpckt_port=*(int*)(vpointer);//?vpointer:&userpckt_port);
	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_number_usercheckers");
	nbuser_check=*(int*)(vpointer);//?vpointer:&nbuser_check);
	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_number_aclcheckers");
	nbacl_check=*(int*)(vpointer);//?vpointer:&nbacl_check);
	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_number_ipauthcheckers");
	nbipauth_check=*(int*)(vpointer);//?vpointer:&nbipauth_check);
	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_log_users");
	nuauth_log_users=*(int*)(vpointer);//?vpointer:&nuauth_log_users);

	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_log_users_sync");
	nuauth_log_users_sync=*(int*)(vpointer);//?vpointer:&nuauth_log_users_sync);

	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_log_users_strict");
	nuauth_log_users_strict=*(int*)(vpointer);//?vpointer:&nuauth_log_users_strict);

	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_log_users_without_realm");
	nuauth_log_users_without_realm=*(int*)(vpointer);//?vpointer:&nuauth_log_users_without_realm);

	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_prio_to_nok");
	nuauth_prio_to_nok=*(int*)(vpointer);//?vpointer:&nuauth_prio_to_nok);

	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_number_loggers");
	nuauth_number_loggers=*(int*)(vpointer);//?vpointer:&nuauth_number_loggers);

	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_packet_timeout");
	packet_timeout=*(int*)(vpointer);//?vpointer:&packet_timeout);
	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_datas_persistance");
	nuauth_datas_persistance=*(int*)(vpointer);//?vpointer:&nuauth_datas_persistance);

	nuauth_aclcheck_state_ready=1;
	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_aclcheck_state_ready");
	nuauth_aclcheck_state_ready=*(int*)(vpointer);//?vpointer:&nuauth_aclcheck_state_ready);

	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_push_to_client");
	nuauth_push=*(int*)(vpointer);//?vpointer:&nuauth_push);

	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_do_ip_authentication");
	nuauth_do_ip_authentication=*(int*)(vpointer);//?vpointer:&nuauth_do_ip_authentication);

	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_acl_cache");
	nuauth_acl_cache=*(int*)(vpointer);//?vpointer:&nuauth_acl_cache);

	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_user_cache");
	nuauth_user_cache=*(int*)(vpointer);//?vpointer:&nuauth_user_cache);

	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_multi_users");
	nuauth_multi_users=(char*)(vpointer);//?vpointer:nuauth_multi_users);

	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_multi_servers");
	nuauth_multi_servers=(char*)(vpointer);//?vpointer:nuauth_multi_servers);

	if ((nuauth_multi_users || nuauth_multi_servers)&&(!(nuauth_multi_servers&&nuauth_multi_users))){
		g_error("The two options nuauth_multi_users and nuauth_multi_servers need to set simultaneoulsy");
	}

	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_uses_utf8");
	nuauth_uses_utf8=*(int*)(vpointer);

	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_hello_authentication");
	nuauth_hello_authentication=*(int*)(vpointer);

	if((!  nuauth_push) && nuauth_hello_authentication ){
		g_message("nuauth_hello_authentication required nuauth_push to be 1, resetting to 0");
		nuauth_hello_authentication=0;
	}

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
				printf("Waiting for user packets on TCP port %d\n",value);
				userpckt_port=value;
				break;
				/* Adress we listen for NUFW originating packets */
			case 'L' :
				// strncpy(nufw_listen_address,optarg,HOSTNAME_SIZE);
				g_free(nuauth_nufw_listen_addr);
				nuauth_nufw_listen_addr = (char *)calloc(HOSTNAME_SIZE,sizeof(char));
				if (nuauth_nufw_listen_addr == NULL){return -1;}
				strncpy(nuauth_nufw_listen_addr,optarg,HOSTNAME_SIZE);
				printf("Waiting for Nufw daemon packets on %s\n",nuauth_nufw_listen_addr);
				//printf("Waiting for Nufw daemon packets on %s\n",nufw_listen_address);
				break;
				/* Adress we listen for NUFW originating packets */
			case 'C' :
				g_free(nuauth_client_listen_addr);
				nuauth_client_listen_addr = (char *)calloc(HOSTNAME_SIZE,sizeof(char));
				if (nuauth_client_listen_addr == NULL){return -1;}
				strncpy(nuauth_client_listen_addr,optarg,HOSTNAME_SIZE);
				printf("Waiting for clients auth packets on %s\n",nuauth_client_listen_addr);
				break;
				/* destination IP */
			case 'd' :
				strncpy(gwsrv_addr,optarg,HOSTNAME_SIZE);
				printf("Sending Auth answers to gw at %s\n",gwsrv_addr);
				break;
				/* packet timeout */
			case 't' :
				sscanf(optarg,"%d",&packet_timeout);
				break;
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
						\t-l : specify listening TCP port (this port waits for clients) (default : 4130)\n\
						\t-L : specify NUFW listening IP address (local) (this address waits for nufw data) (default : 127.0.0.1)\n\
						\t-C : specify clients listening IP address (local) (this address waits for clients auth) (default : 0.0.0.0)\n\
						\t-d : (remote) address of the nufw (gateway) server\n\
						\t-t : timeout to forget about packets when they don't match (default : 15 s)\n");
				return 1;
		}
	}


	if (nuauth_uses_utf8){
		setlocale(LC_ALL,"");	
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

	signal(SIGPIPE,SIG_IGN);

	/* initialize packets list */
	conn_list = g_hash_table_new_full ((GHashFunc)hash_connection,
			compare_connection,
			NULL,
			(GDestroyNotify) free_connection); 


	/* parse nufw server address */
	authorized_servers= generate_inaddr_list(gwsrv_addr);
	/* parse multi user auth users */
	if (nuauth_multi_users){
		nuauth_multi_users_array =  g_strsplit(nuauth_multi_users,",",0);
	}
	/* parse multi user clients */
	if (nuauth_multi_servers){
		nuauth_multi_servers_array =  generate_inaddr_list(nuauth_multi_servers);
	}

	/* socket ready */
	//listening adress for clients requests
	memset(&client_srv,0,sizeof client_srv);

	/* hostname conversion */
	client_list_srv=gethostbyname(nuauth_client_listen_addr);
	client_srv.sin_addr=*(struct in_addr *)client_list_srv->h_addr;
        /* client addr can now be freed */
        g_free(nuauth_client_listen_addr);

	if (client_srv.sin_addr.s_addr == INADDR_NONE ){
		if (DEBUG_OR_NOT(DEBUG_LEVEL_CRITICAL,DEBUG_AREA_MAIN))
			g_warning("Bad Address was passed with \"-C\" parameter. Ignored. Using INADDR_ANY instead!");
		client_srv.sin_addr.s_addr = INADDR_ANY;
	}

	// INIT adress for listening to nufw
	memset(&nufw_srv,0,sizeof nufw_srv);

	/* hostname conversion */
	nufw_list_srv=gethostbyname(nuauth_nufw_listen_addr);
	nufw_srv.sin_addr=*(struct in_addr *)nufw_list_srv->h_addr;
        g_free(nuauth_nufw_listen_addr);

	if (nufw_srv.sin_addr.s_addr == INADDR_NONE ){
		if (DEBUG_OR_NOT(DEBUG_LEVEL_CRITICAL,DEBUG_AREA_MAIN))
			g_warning("Bad Address was passed with \"-L\" parameter. Ignored. Using INADDR_ANY instead!");
		nufw_srv.sin_addr.s_addr = INADDR_ANY;
	}


	/* async  queue initialisation */

	connexions_queue = g_async_queue_new();
	if (!connexions_queue)
		exit(1);

	/* init modules system */
	init_modules_system();
	/* load modules */
	load_modules();

	/* internal Use */
	ALLGROUP=NULL;
	ALLGROUP=g_slist_prepend(ALLGROUP, GINT_TO_POINTER(0) );


	if (nuauth_acl_cache) {
		init_acl_cache();
	}

	/* create user cache thread */
	if (nuauth_user_cache && (nuauth_multi_users && nuauth_multi_servers) ){
		init_user_cache();
	}

	null_message=g_new0(struct cache_message,1);
	null_queue_datas=g_new0(gchar,1);

	if (nuauth_do_ip_authentication){
		/* create thread of pool */
		ip_authentication_workers = g_thread_pool_new  ((GFunc) external_ip_auth,
				NULL,
				nbipauth_check,
				TRUE,
				NULL);
	}

	/* fill empty header to be able to run push_control */
	empty_header.saddr=INADDR_ANY;
	/* create thread for client request sender */
	tls_pusher = g_thread_create ( (GThreadFunc)push_worker,
			NULL,
			FALSE,
			NULL);
	if (! tls_pusher )
		exit(1);


	/* init private datas for pool thread */
	aclqueue = g_private_new(g_free);
	userqueue = g_private_new(g_free);

	/* create thread for search_and_fill thread */
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
		g_message("Creating search_and_fill thread");
	search_and_fill_worker = g_thread_create ( (GThreadFunc) search_and_fill,
			NULL,
			FALSE,
			NULL);
	if (! search_and_fill_worker )
		exit(1);

	if (nuauth_push && nuauth_hello_authentication){
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
			g_message("Creating hello mode authentication thread");
		localid_auth_queue = g_async_queue_new ();
		localid_auth_thread = g_thread_create ( (GThreadFunc) localid_auth,
				NULL,
				FALSE,
				NULL);
		if (! localid_auth_thread )
			exit(1);
	}

	/* create pckt workers */

	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
		g_message("Creating %d acl checkers",nbacl_check);
	acl_checkers = g_thread_pool_new  ((GFunc) acl_check_and_decide,
			NULL,
			nbacl_check,
			TRUE,
			NULL);

	/* create user worker */

	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
		g_message("Creating %d user checkers",nbuser_check);
	user_checkers = g_thread_pool_new  ((GFunc) user_check_and_decide,
			NULL,
			nbuser_check,
			TRUE,
			NULL);


	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
		g_message("Creating %d user loggers", nuauth_number_loggers);
	user_loggers = g_thread_pool_new  ((GFunc)  real_log_user_packet,
			NULL,
			nuauth_number_loggers,
			TRUE,
			NULL);

	if ( nuauth_log_users_sync ){
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
			g_message("Creating %d decision workers", nuauth_number_loggers);
		decisions_workers = g_thread_pool_new  ((GFunc)  decisions_queue_work,
				NULL,
                                //GRYZOR THIS IS WEIRD
				nuauth_number_loggers,
				TRUE,
				NULL);
	}


	/* create thread for tsl  auth server */
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
		g_message("Creating tls authentication server thread");
	tls_auth_server = g_thread_create ( tls_user_authsrv,
			NULL,
			FALSE,
			NULL);
	if (! tls_auth_server )
		exit(1);
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
		g_message("Creating tls nufw server thread");
	tls_nufw_server = g_thread_create ( tls_nufw_authsrv,
			NULL,
			FALSE,
			NULL);
	if (! tls_nufw_server )
		exit(1);

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
			if (g_thread_pool_unprocessed(user_checkers) || g_thread_pool_unprocessed(acl_checkers)){
				g_message("%u user/%u acl unassigned task(s), %d connection(s)\n",
						g_thread_pool_unprocessed(user_checkers),
						g_thread_pool_unprocessed(acl_checkers),
						g_hash_table_size(conn_list)
					 );  
			}
		}
		if (nuauth_acl_cache){
			/* send update message to cache thread */
			message=g_new0(struct cache_message,1);
			message->type=REFRESH_MESSAGE;
			g_async_queue_push(acl_cache->queue,message);
		}
		if (nuauth_push){
			if (nuauth_hello_authentication) {
				struct internal_message * message=g_new0(struct internal_message,1);
				message->type=REFRESH_MESSAGE;
				g_async_queue_push(localid_auth_queue,message);
			}
		}
		/* a little sleep */
		usleep(500000);	
	}

}



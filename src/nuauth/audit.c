#include <auth_srv.h>
#include <signal.h>

/**
 * Print performance information.
 * This is the handler of SIGPOLL signal. 
 */
void nuauth_process_poll(int signum)
{
  g_message("AUDIT : users   threads : %u/%u max/unassigned",
            g_thread_pool_get_max_threads(myaudit->users),
            g_thread_pool_unprocessed(myaudit->users));
  g_message("AUDIT : acls    threads : %u/%u max/unassigned",
            g_thread_pool_get_max_threads(myaudit->acls),
            g_thread_pool_unprocessed(myaudit->acls));
  if (nuauthconf->acl_cache){
  g_message("AUDIT :  acls cache : - contains %d elements",
            (g_hash_table_size(myaudit->aclcache)));
  g_message("AUDIT :               - %u/%u hits/requests",
            myaudit->cache_hit_nb,
            myaudit->cache_req_nb);
  }
  g_message("AUDIT : loggers threads : %u/%u max/unassigned",
            g_thread_pool_get_max_threads(myaudit->loggers),
            g_thread_pool_unprocessed(myaudit->loggers));
  g_message("AUDIT : %d connections waiting to be sent packets for.",
            (g_hash_table_size(myaudit->conn_list)));
/*  g_message("AUDIT : overall number of unused threads : %u",
            g_thread_pool_get_num_unused_threads());*/
  g_mem_profile();
}

/**
 * Increase debug level (see ::nuauthconf->debug_level).
 * This is the handler of SIGUSR1 signal. 
 */
void nuauth_process_usr1(int signum)
{
  nuauthconf->debug_level+=1;
  if (nuauthconf->debug_level>20)
      nuauthconf->debug_level = 20;
  g_message("USR1 : setting debug level to %d",nuauthconf->debug_level);
}


/**
 * Decrease debug level (see ::nuauthconf->debug_level).
 * This is the handler of SIGUSR2 signal. 
 */
void nuauth_process_usr2(int signum)
{
  nuauthconf->debug_level-=1;
  if (nuauthconf->debug_level <0)
      nuauthconf->debug_level = 0;
  g_message("USR2 : setting debug level to %d",nuauthconf->debug_level);
}

/**
 * Install signals used in audit:
 *   - Set SIGPOLL handler to nuauth_process_poll() ;
 *   - Set SIGUSR1 handler to nuauth_process_usr1() ;
 *   - Set SIGUSR2 handler to nuauth_process_usr2() ;
 */
void init_audit()
{

	struct sigaction act;
	myaudit=g_new0(struct audit_struct,1);
	myaudit->users = nuauthdatas->user_checkers;
	myaudit->acls  = nuauthdatas->acl_checkers;
	myaudit->loggers = nuauthdatas->user_loggers;
	myaudit->conn_list = conn_list;
	if (nuauthconf->acl_cache){
		myaudit->aclcache = nuauthdatas->acl_cache->hash;
	}
	myaudit->cache_req_nb = 0;
	myaudit->cache_hit_nb = 0;


	memset(&act,0,sizeof(act));
	act.sa_handler=&nuauth_process_poll;
	act.sa_flags = SIGPOLL;
	if (sigaction(SIGPOLL,&act,NULL) == -1){
		printf("could not set signal");
		exit(EXIT_FAILURE);
	}

	memset(&act,0,sizeof(act));
	act.sa_handler=&nuauth_process_usr1;
	act.sa_flags = SIGUSR1;

	if (sigaction(SIGUSR1,&act,NULL) == -1){
		printf("could not set signal");
		exit(EXIT_FAILURE);
	}

	memset(&act,0,sizeof(act));
	act.sa_handler=&nuauth_process_usr2;
	act.sa_flags = SIGUSR2;

	if (sigaction(SIGUSR2,&act,NULL) == -1){
		printf("could not set signal");
		exit(EXIT_FAILURE);
	}


}

void end_audit()
{
	g_free(myaudit);
}

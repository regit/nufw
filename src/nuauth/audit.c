#include <auth_srv.h>


/**
 * process signal POLL and print performance information.
 */
void process_poll(int signum)
{
  g_message("AUDIT : users   threads : %u/%u max/unassigned",
            g_thread_pool_get_max_threads(myaudit->users),
            g_thread_pool_unprocessed(myaudit->users));
  g_message("AUDIT : acls    threads : %u/%u max/unassigned",
            g_thread_pool_get_max_threads(myaudit->acls),
            g_thread_pool_unprocessed(myaudit->acls));
  if (nuauth_acl_cache){
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
 * process USR1 signal : increase debug level.
 */
void process_usr1(int signum)
{
  debug_level+=1;
  if (debug_level>20)
      debug_level = 20;
  g_message("USR1 : setting debug level to %d",debug_level);
}


/**
 * process USR2 signal : decrease debug level.
 */
void process_usr2(int signum)
{
  debug_level-=1;
  if (debug_level <0)
      debug_level = 0;
  g_message("USR2 : setting debug level to %d",debug_level);
}


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
  { "nuauth_addr" ,  G_TOKEN_STRING, 0 , AUTHREQ_ADDR },
  { "nuauth_gw_packet_port" , G_TOKEN_INT , AUTHREQ_PORT,NULL },
  { "nuauth_user_packet_port" , G_TOKEN_INT , AUTHREQ_PORT ,NULL},
  { "nufw_gw_addr" , G_TOKEN_STRING , 0, GWSRV_ADDR },
  { "nufw_gw_port" , G_TOKEN_INT , GWSRV_PORT, NULL },
  { "nuauth_prio" , G_TOKEN_INT , PRIO , NULL},
  { "nuauth_packet_timeout" , G_TOKEN_INT , PACKET_TIMEOUT, NULL },
  { "nuauth_number_usercheckers" , G_TOKEN_INT , NB_USERCHECK, NULL},
  { "nuauth_number_aclcheckers" , G_TOKEN_INT , NB_ACLCHECK, NULL },
  { "nuauth_log_users" , G_TOKEN_INT , 1, NULL },
  { "nuauth_auth_module" , G_TOKEN_STRING , 1, NULL },
};
#endif 

int main(int argc,char * argv[]) {
  GThread * pckt_server, * auth_server;
  /* option */
  char * options_list = "DhVvl:d:p:t:T:";
  int option,daemonize = 0;
  int value;
  char* authreq_addr=AUTHREQ_ADDR;
  char* version=VERSION;
  char* gwsrv_addr=GWSRV_ADDR;
  char *configfile=DEFAULT_CONF_FILE;
  int nbacl_check=NB_ACLCHECK;
  int nbuser_check=NB_USERCHECK;
  char * nuauth_auth_module=DEFAULT_AUTH_MODULE;
  gpointer vpointer;
  pid_t pidf;

  /* initialize variables */

  authreq_port = AUTHREQ_PORT;
  gwsrv_port = GWSRV_PORT;
  userpckt_port = USERPCKT_PORT; 
  packet_timeout = PACKET_TIMEOUT;

  /* 
   * Minimum debug_level value is 2 -> for 1) fatal and 2) critical messages to always
   * be outputed
   */
  debug_level=0;
  debug_areas=DEFAULT_DEBUG_AREAS;
 
  /* parse conf file */
  parse_conffile(configfile,sizeof(nuauth_vars)/sizeof(confparams),nuauth_vars);
  /* set variable value from config file */

  vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_addr");
  authreq_addr=(char *)(vpointer?vpointer:authreq_addr);
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
  vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_auth_module");
  nuauth_auth_module=(char*)(vpointer?vpointer:nuauth_auth_module);
  
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
      fprintf (stdout ,"nuauth [-hDVv[v[v[v[v[v[v[v[v]]]]]]]]] [-l user_packet_port] [-d nufw_gw_addr] [-p nufw_gw_port]  [-t packet_timeout]\n");
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
  if ((pidf = fork()) < 0){
  	g_error("Unable to fork\n");
	exit (-1); /* this should be useless !! */
  } else {
 	 if (pidf > 0) {
		exit(0);
	}
  }

 setsid();


 if ((pidf = fork()) < 0){
  	printf("Unable to fork\n");
	exit (-1);
  } else {
 	 if (pidf > 0) {
		exit(0);
	}
  }


 set_glib_loghandlers();

}

 signal(SIGPIPE,SIG_IGN);

  /* initialize packets list */
 conn_list = g_hash_table_new_full (g_int_hash, //(GHashFunc)hash_connection,
				    compare_connection
				    ,NULL,
				    (GDestroyNotify) lock_and_free_connection); 
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



  /* Initialize glib thread system */
  g_thread_init(NULL);

 /* external auth module loading */
  
  module_acl_check=NULL;
  module_user_check=NULL;

  auth_module=g_module_open (g_module_build_path("/usr/local/lib/nuauth/modules/",
						 nuauth_auth_module)
			     ,0);
  if (!g_module_symbol (auth_module, "ldap_acl_check", 
			(gpointer*)&module_acl_check))
    {
      g_warning ("Unable to load acl function\n");
    }
   if (!g_module_symbol (auth_module, "ldap_user_check", 
			(gpointer*)&module_user_check))
    {
      g_warning ("Unable to load user function\n");
    }

  /* internal Use */
  ALLGROUP=NULL;
  ALLGROUP=g_slist_prepend(ALLGROUP, GINT_TO_POINTER(0) );

  DUMMYACL.groups = ALLGROUP;
  DUMMYACL.answer = OK;
  DUMMYACLS = g_slist_prepend(NULL,&DUMMYACL);

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

  acl_checkers = g_thread_pool_new  ((GFunc) acl_check,
				     NULL,
				     nbacl_check,
				     TRUE,
				     NULL);

  /* create user worker */
  user_checkers = g_thread_pool_new  ((GFunc) user_check,
				     NULL,
				     nbuser_check,
				     TRUE,
				     NULL);

  /* admin task */
  for(;;){
    clean_connections_list();
     if (DEBUG_OR_NOT(DEBUG_LEVEL_MESSAGE,DEBUG_AREA_MAIN)){
      g_message("%u unassigned task(s) and %d connection(s)\n",
		g_thread_pool_unprocessed(user_checkers),
		g_hash_table_size(conn_list));  
      //	print_users_list();
     }
    sleep(2);	
  }

}


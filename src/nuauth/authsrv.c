
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
#include <syslog.h>


int main(int argc,char * argv[]) {
  static GStaticMutex insert_mutex = G_STATIC_MUTEX_INIT;
  GThread * pckt_server, * auth_server;
  /* option */
  char * options_list = "DhVvl:d:p:t:T:";
  int option,daemonize = 0;
  int value;
  int track_size;
  char authreq_addr[HOSTNAME_SIZE];
  char* version=VERSION;
  char gwsrv_addr[HOSTNAME_SIZE]=GWSRV_ADDR;
  pid_t pidf;

  /* initialize variables */

  authreq_port = AUTHREQ_PORT;
  gwsrv_port = GWSRV_PORT;
  userpckt_port = USERPCKT_PORT; 
  packet_timeout = PACKET_TIMEOUT;
  track_size = TRACK_SIZE;
  strncpy(authreq_addr,AUTHREQ_ADDR,HOSTNAME_SIZE);
  /* debug=DEBUG; */
  /*Minimum debug_level value is 2 -> for 1) fatal and 2) critical messages to always
   * be outputed*/
  debug_level=0;
  debug_areas=DEFAULT_DEBUG_AREAS;
 

  /*parse options */
  while((option = getopt ( argc, argv, options_list)) != -1 ){
    switch (option){
    case 'V' :
      fprintf (stdout, "authsrv (version %s)\n",version);
      return 1;
    case 'v' :
      /*fprintf (stdout, "Debug should be On (++)\n");*/
      debug_level+=1;
      break;
      /* port we listen for auth answer */
    case 'l' :
      sscanf(optarg,"%d",&value);
      printf("Listen on UDP port %d\n",value);
      userpckt_port=value;
      break;
      /* destination port */
    case 'p' :
      sscanf(optarg,"%d",&value);
      printf("Auth Answer sent to port %d\n",value);
      gwsrv_port=value;
      break;
      /* destination IP */
    case 'd' :
      strncpy(gwsrv_addr,optarg,HOSTNAME_SIZE);
      printf("Sending Auth Answer to %s\n",gwsrv_addr);
      break;
      /* packet timeout */
    case 't' :
      sscanf(optarg,"%d",&packet_timeout);
      break;
      /* max size of packet list */
    case 'T' :
      sscanf(optarg,"%d",&track_size);
      break;
    case 'D' :
      daemonize=1;
      break;
    case 'h' :
      fprintf (stdout ,"authsrv [-hDVv[v[v[v[v[v[v[v[v]]]]]]]]]] [-l local_port] [-d remote_addr] [-p remote_port]  [-t packet_timeout] [-T track_size]\n");
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
 
#if USE_LDAP
  /* create a private object to point at ldap connection */
  ldap_priv = g_private_new (g_free);
#endif

  /* private data for crypt */
  crypt_priv = g_private_new (g_free);

  /* create pckt workers */

  acl_checkers = g_thread_pool_new  ((GFunc) acl_check,
				     NULL,
				     NB_ACLCHECK,
				     TRUE,
				     NULL);

  /* create user worker */
  user_checkers = g_thread_pool_new  ((GFunc) user_check,
				     NULL,
				     NB_USERCHECK,
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



/*
** Copyright(C) 2003 Eric Leblond <eric@regit.org>
**		     Vincent Deffontaines <vincent@gryzor.com>
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
#include <log_pgsql.h>
#include <string.h>
#include <errno.h>


confparams pgsql_nuauth_vars[] = {
  { "pgsql_server_addr" , G_TOKEN_STRING, 0 , PGSQL_SERVER },
  { "pgsql_server_port" ,G_TOKEN_INT , PGSQL_SERVER_PORT,NULL },
  { "pgsql_user" , G_TOKEN_STRING , 0 ,PGSQL_USER},
  { "pgsql_password" , G_TOKEN_STRING , 0 ,PGSQL_PASSWD},
  { "pgsql_ssl" , G_TOKEN_STRING , 0 ,PGSQL_SSL},
  { "pgsql_db_name" , G_TOKEN_STRING , 0 ,PGSQL_DB_NAME},
  { "pgsql_request_timeout" , G_TOKEN_INT , PGSQL_REQUEST_TIMEOUT , NULL }
};

/* Init pgsql system */
G_MODULE_EXPORT gchar* 
g_module_check_init(GModule *module){
  char *configfile=DEFAULT_CONF_FILE;
  gpointer vpointer; 
  //char *ldap_base_dn=LDAP_BASE;

  /* init global variables */
  pgsql_user=PGSQL_USER;
  pgsql_passwd=PGSQL_PASSWD;
  pgsql_server=PGSQL_SERVER;
  pgsql_server_port=PGSQL_SERVER_PORT;
  pgsql_ssl=PGSQL_SSL;
  pgsql_db_name=PGSQL_DB_NAME;
  pgsql_request_timeout=PGSQL_REQUEST_TIMEOUT;

  /* parse conf file */
  parse_conffile(configfile,sizeof(pgsql_nuauth_vars)/sizeof(confparams),pgsql_nuauth_vars);
  /* set variables */
  vpointer=get_confvar_value(pgsql_nuauth_vars,sizeof(pgsql_nuauth_vars)/sizeof(confparams),"pgsql_server_addr");
  pgsql_server=(char *)(vpointer?vpointer:pgsql_server);
  vpointer=get_confvar_value(pgsql_nuauth_vars,sizeof(pgsql_nuauth_vars)/sizeof(confparams),"pgsql_server_port");
  pgsql_server_port=*(int *)(vpointer?vpointer:&pgsql_server_port);
  vpointer=get_confvar_value(pgsql_nuauth_vars,sizeof(pgsql_nuauth_vars)/sizeof(confparams),"pgsql_user");
  pgsql_user=(char *)(vpointer?vpointer:pgsql_user);
  vpointer=get_confvar_value(pgsql_nuauth_vars,sizeof(pgsql_nuauth_vars)/sizeof(confparams),"pgsql_passwd");
  pgsql_passwd=(char *)(vpointer?vpointer:pgsql_passwd);
  vpointer=get_confvar_value(pgsql_nuauth_vars,sizeof(pgsql_nuauth_vars)/sizeof(confparams),"pgsql_ssl");
  pgsql_ssl=(char *)(vpointer?vpointer:pgsql_ssl);
  vpointer=get_confvar_value(pgsql_nuauth_vars,sizeof(pgsql_nuauth_vars)/sizeof(confparams),"pgsql_db_name");
  pgsql_db_name=(char *)(vpointer?vpointer:pgsql_db_name);
  vpointer=get_confvar_value(pgsql_nuauth_vars,sizeof(pgsql_nuauth_vars)/sizeof(confparams),"pgsql_request_timeout");
  pgsql_request_timeout=*(int *)(vpointer?vpointer:&pgsql_request_timeout);

  /* init thread private stuff */
  pgsql_priv = g_private_new (g_free);

  return NULL;
}

/* 
 * Initialize connection to ldap server
 */

G_MODULE_EXPORT PGSQL* pgsql_conn_init(void){
  PGconn *ld = NULL;
  char *pgsql_conninfo;
  int pgsql_status,err,version=3;
  char *port,*timeout;
  sprintf(port,"%d",pgsql_server_port);
  sprintf(timeout,"%d",pgsql_request_timeout);

  pgsql_conninfo = (char *)calloc(strlen(pgsql_user) + strlen(pgsql_passwd) + 
      strlen(pgsql_server) + strlen(pgsql_ssl) + strlen(pgsql_server_port) + strlen(pgsql_db_name) +
      strlen(port) + strlen(timeout) +
      strlen("hostaddr='' port= dbname='' user='' password='' connect_timeout= sslmode='' ") + 1, 
      sizeof(char));
  //Build string we will pass to PQconnectdb
  strcat(pgsql_conninfo,"hostaddr='");
  strcat(pgsql_conninfo,pgsql_server);
  strcat(pgsql_conninfo,"' port=");
  strcat(pgsql_conninfo,port);
  strcat(pgsql_conninfo," dbname='");
  strcat(pgsql_conninfo,pgsql_db_name);
  strcat(pgsql_conninfo,"' user='");
  strcat(pgsql_conninfo,pgsql_user);
  strcat(pgsql_conninfo,"' password='");
  strcat(pgsql_conninfo,pgsql_passwd);
  strcat(pgsql_conninfo,"' connect_timeout=");
  strcat(pgsql_conninfo,timeout);
  strcat(pgsql_conninfo," sslmode='");
  strcat(pgsql_conninfo,pgsql_ssl);
  strcat(pgsql_conninfo,"'");
  /* init connection */
  ld = PQconnectdb(pgsql_conninfo);
  pgsql_status=PQStatus(ld);
  
  if(pgsql_status != CONNECTION_OK) {
    if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
      g_warning("pgsql init error : %s\n",strerror(errno));
    return NULL;
  }
  return ld;
}


G_MODULE_EXPORT gint user_packet_logs (connection *element, int state){
  PGConn *ld = g_private_get (pgsql_priv);
  char request[512];
  if (ld == NULL){
    ld=pgsql_conn_init();
    if (ld == NULL){
      if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_MAIN))
          g_warning("Can not initiate PGSQL conn\n");
      return NULL;
    }
    g_private_set(pgsql_priv,ld);
  }
  /* contruct request */
  if (state == 1){
      if ((element->tracking_hdrs).protocol == IPPROTO_TCP){
          //
          // FIELD          IN NUAUTH STRUCTURE               IN ULOG
          //user_id               u_int16_t                   integer
          //ip_protocol           u_int8_t                    smallint        2 bytes
          //ip_saddr              u_int32_t                   inet            12 or 24 bytes (ipv4 or ipv6)
          //ip_daddr              u_int32_t                   inet
          //tcp_sport             u_int16_t                   integer         4 bytes
          //tcp_dport             u_int16_t                   integer
          //udp_sport             u_int16_t                   integer
          //udp_dport             u_int16_t                   integer
          //icmp_type             u_int8_t                    smallint        2 bytes
          //icmp_code             u_int8_t                    smallint        2 bytes
          //start_timestamp       long                        bigint          8 bytes
          //end_timestamp         long                        bigint
          //
          //
          //
          snprintf(request,511,"INSERT INTO %s (user_id,ip_protocol,ip_saddr,ip_daddr,tcp_sport,tcp_dport) VALUES (%d,%hu,,,,,,,,),element->user_id,"
}


G_MODULE_EXPORT GSList* acl_check (connection* element){
  GSList * g_list = NULL;
  char filter[512];
  char ** attrs_array, ** walker;
  int attrs_array_len,i,group;
  struct timeval timeout;
  struct acl_group * this_acl;
  LDAPMessage * res , *result;
  int err;
  LDAP *ld = g_private_get (ldap_priv);

  if (ld == NULL){
    /* init ldap has never been done */
    ld = ldap_conn_init();
    if (ld == NULL) {
	if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_AUTH))
		g_warning("Can not initiate LDAP conn\n");
	return NULL;
    }
    g_private_set(ldap_priv,ld);
  }
  /* contruct filter */
  if ((element->tracking_hdrs).protocol == IPPROTO_TCP || (element->tracking_hdrs).protocol == IPPROTO_UDP ){
    snprintf(filter,511,
	     "(&(objectClass=NuAccessControlList)(SrcIPStart<=%lu)(SrcIPEnd>=%lu)(DstIPStart<=%lu)(DstIPEnd>=%lu)(Proto=%d)(SrcPortStart<=%d)(SrcPortEnd>=%d)(DstPortStart<=%d)(DstPortEnd>=%d))",
	     (long unsigned int)(element->tracking_hdrs).saddr,
	     (long unsigned int)(element->tracking_hdrs).saddr,
	     (long unsigned int)(element->tracking_hdrs).daddr,
	     (long unsigned int)(element->tracking_hdrs).daddr,
	     (element->tracking_hdrs).protocol,
	     (element->tracking_hdrs).source,
	     (element->tracking_hdrs).source,
	     (element->tracking_hdrs).dest,
	     (element->tracking_hdrs).dest
	     );
  } else if ((element->tracking_hdrs).protocol == IPPROTO_ICMP ) {
    snprintf(filter,511,
	     "(&(objectClass=AccessControlList)(SrcIPStart<=%lu)(SrcIPEnd>=%lu)(DstIPStart<=%lu)(DstIPEnd>=%lu)(Proto=%d)(SrcPortStart<=%d)(SrcPortEnd>=%d)(DstPortStart<=%d)(DstPortEnd>=%d))",
	     (long unsigned int)(element->tracking_hdrs).saddr,
	     (long unsigned int)(element->tracking_hdrs).saddr,
	     (long unsigned int)(element->tracking_hdrs).daddr,
	     (long unsigned int)(element->tracking_hdrs).daddr,
	     (element->tracking_hdrs).protocol,
	     (element->tracking_hdrs).type,
	     (element->tracking_hdrs).type,
	     (element->tracking_hdrs).code,
	     (element->tracking_hdrs).code
	     ); 
  }

  /* send query and wait result */
  timeout.tv_sec = ldap_request_timeout;
  timeout.tv_usec = 0;
  /* TODO : just get group and decision */
  /* if (debug)
     printf("Filter : %s\n",filter); */
    
  err =  ldap_search_st(ld, ldap_acls_base_dn, LDAP_SCOPE_SUBTREE,filter,NULL,0,
			&timeout,
			&res) ;
  if ( err !=  LDAP_SUCCESS ) {
    if (err == LDAP_SERVER_DOWN ){
      /* we lost connection, so disable current one */
      ldap_unbind(ld);
      ld=NULL;
      g_private_set(ldap_priv,ld);
    }
    if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
      g_warning ("invalid return from ldap_search_st : %s\n",ldap_err2string(err));
    return NULL;
  }
  /* parse result to feed a group_list */
  if (ldap_count_entries(ld,res) >= 1) {
    result = ldap_first_entry(ld,res);
    while ( result ) {
      /* allocate a new acl_group */
      this_acl=g_new0(struct acl_group,1);
      this_acl->groups=NULL;
	g_list = g_slist_prepend(g_list,this_acl);
	/* get decision */
	attrs_array=ldap_get_values(ld, result, "Decision");
	sscanf(*attrs_array,"%c",&(this_acl->answer));
	ldap_value_free(attrs_array);
	/* build groups  list */
	attrs_array = ldap_get_values(ld, result, "Group");
	attrs_array_len = ldap_count_values(attrs_array);
	walker = attrs_array;
	for(i=0; i<attrs_array_len; i++){
	  sscanf(*walker,"%d",&group);
	  this_acl->groups = g_slist_prepend(this_acl->groups, GINT_TO_POINTER(group));
	  walker++;
	}
	ldap_value_free(attrs_array);
	result = ldap_next_entry(ld,result);
      }
    if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_AUTH))
      g_message("acl group at %p\n",g_list);
    ldap_msgfree (res);
    return g_list;
  } else {
    if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_AUTH))
      g_message("No acl found\n");
    ldap_msgfree (res);
  }
  return NULL;
}

/* TODO return List */
G_MODULE_EXPORT GSList * user_check (u_int16_t userid,char *passwd){
  char filter[512];
  LDAP *ld = g_private_get (ldap_priv);
  LDAPMessage * res , *result;
  char ** attrs_array, ** walker;
  int attrs_array_len,i,group,err;
  struct timeval timeout;
  GSList * outelt=NULL;


  if (ld == NULL){
    /* init ldap has never been done */
    ld = ldap_conn_init();
    g_private_set(ldap_priv,ld);
    if (ld == NULL){
	if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_AUTH))
		g_message("Can't initiate LDAP conn\n");
	return -1;
    }
  }
  snprintf(filter,511,"(&(objectClass=NuAccount)(uidNumber=%d))",userid);
  
  /* send query and wait result */
  timeout.tv_sec = ldap_request_timeout;
  timeout.tv_usec = 0;
  /* TODO : just get group and decision */
  err =  ldap_search_st(ld, ldap_users_base_dn, LDAP_SCOPE_SUBTREE,filter,NULL,0,
			&timeout,
			&res) ;
  if ( err !=  LDAP_SUCCESS ) {
	if (err == LDAP_SERVER_DOWN ){
    	  /* we lost connection, so disable current one */
     	 ldap_unbind(ld);
     	 ld=NULL;
    	  g_private_set(ldap_priv,ld);
   	 }
    if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_AUTH))
      g_warning ("invalid return of ldap_search_st : %s\n",ldap_err2string(err));
    return NULL;
  }

   if (ldap_count_entries(ld,res) == 1) {
     /* parse result to feed a user_list */
     result = ldap_first_entry(ld,res);
     if (result == NULL ){
       if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_AUTH))
	 g_message("Can not get entry for %d\n",userid);
       ldap_msgfree(res);
       return NULL;
     }
     /* build groups  list */
     attrs_array = ldap_get_values(ld, result, "Group");
     attrs_array_len = ldap_count_values(attrs_array);
     walker = attrs_array;
     for(i=0; i<attrs_array_len; i++){
       sscanf(*walker,"%d",&group);
       outelt = g_slist_prepend(outelt, GINT_TO_POINTER(group));
       walker++;
     }
     ldap_value_free(attrs_array);
     /* get password */
     attrs_array = ldap_get_values(ld, result, "userPassword");
     attrs_array_len = ldap_count_values(attrs_array);
     if (attrs_array_len == 0){
       if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_AUTH))
         g_message ("what ! no password found!\n");
     } else {
       sscanf(*attrs_array,"%s",passwd);
       if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_AUTH))
	 g_message("reading password\n");
     }
     ldap_value_free(attrs_array);
     ldap_msgfree(res);
     return outelt;
   } else {
     if (DEBUG_OR_NOT(DEBUG_LEVEL_MESSAGE,DEBUG_AREA_AUTH))
       g_message("No or too many users found with userid %d\n",userid);
     ldap_msgfree(res);
     return NULL;
   }
  ldap_msgfree(res);
  return 0;
}


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
#include <auth_ldap.h>


//#ifndef _LDAPVARS
//#define _LDAPVARS
confparams ldap_nuauth_vars[] = {
  { "ldap_server_addr" , G_TOKEN_STRING, 0 , LDAP_SERVER },
  { "ldap_server_port" ,G_TOKEN_INT , LDAP_SERVER_PORT,NULL },
  { "ldap_users_base_dn" , G_TOKEN_STRING , 0 ,LDAP_BASE},
  { "ldap_acls_base_dn" , G_TOKEN_STRING , 0 ,LDAP_BASE},
  { "ldap_bind_dn" , G_TOKEN_STRING , 0 ,LDAP_USER},
  { "ldap_bind_password" , G_TOKEN_STRING , 0, LDAP_CRED },
  { "ldap_request_timeout" , G_TOKEN_INT , LDAP_REQUEST_TIMEOUT , NULL }
};
//#endif 


/* Init ldap system */
G_MODULE_EXPORT gchar* 
g_module_check_init(GModule *module){
  char *configfile=DEFAULT_CONF_FILE; 
  gpointer vpointer; 



  /* init global variables */
  
  binddn=LDAP_USER;
  bindpasswd=LDAP_CRED;
  ldap_server=LDAP_SERVER;
  ldap_server_port=LDAP_SERVER_PORT;
  ldap_users_base_dn=LDAP_BASE;
  ldap_acls_base_dn=LDAP_BASE;
  /* parse conf file */
  parse_conffile(configfile,sizeof(ldap_nuauth_vars)/sizeof(confparams),ldap_nuauth_vars);
  /* set variables */
  vpointer=get_confvar_value(ldap_nuauth_vars,sizeof(ldap_nuauth_vars)/sizeof(confparams),"ldap_server_addr");
  ldap_server=(char *)(vpointer?vpointer:ldap_server);
  vpointer=get_confvar_value(ldap_nuauth_vars,sizeof(ldap_nuauth_vars)/sizeof(confparams),"ldap_server_port");
  ldap_server_port=*(int *)(vpointer?vpointer:&ldap_server_port);
  vpointer=get_confvar_value(ldap_nuauth_vars,sizeof(ldap_nuauth_vars)/sizeof(confparams),"ldap_bind_dn");
  binddn=(char *)(vpointer?vpointer:binddn);
  vpointer=get_confvar_value(ldap_nuauth_vars,sizeof(ldap_nuauth_vars)/sizeof(confparams),"ldap_users_base_dn");
  ldap_users_base_dn=(char *)(vpointer?vpointer:ldap_users_base_dn);
  vpointer=get_confvar_value(ldap_nuauth_vars,sizeof(ldap_nuauth_vars)/sizeof(confparams),"ldap_acls_base_dn");
  ldap_acls_base_dn=(char *)(vpointer?vpointer:ldap_acls_base_dn);
  vpointer=get_confvar_value(ldap_nuauth_vars,sizeof(ldap_nuauth_vars)/sizeof(confparams),"ldap_bind_password");
  bindpasswd=(char *)(vpointer?vpointer:bindpasswd);
  ldap_request_timeout=LDAP_REQUEST_TIMEOUT;
  vpointer=get_confvar_value(ldap_nuauth_vars,sizeof(ldap_nuauth_vars)/sizeof(confparams),"ldap_request_timeout");
  ldap_request_timeout=*(int *)(vpointer?vpointer:&ldap_request_timeout);

  /* init thread private stuff */
  ldap_priv = g_private_new (g_free);

  return NULL;
}

/* 
 * Initialize connection to ldap server
 */

G_MODULE_EXPORT LDAP* ldap_conn_init(void){
  LDAP* ld = NULL;
  int err,version=3;

  /* init connection */
  ld = ldap_init(ldap_server,ldap_server_port);
  if(!ld) {
    if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
      g_warning("ldap init error\n");
    return NULL;
  }
  if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION,
                                   &version) == LDAP_OPT_SUCCESS) {
    err = ldap_bind_s(ld, binddn, bindpasswd,LDAP_AUTH_SIMPLE);
  if ( err !=  LDAP_SUCCESS ){
    if (err == LDAP_SERVER_DOWN ){
      /* we lost connection, so disable current one */
      ldap_unbind(ld);
      ld=NULL;
      g_private_set(ldap_priv,ld);
      return NULL;
    } 
    if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_AUTH)){
      g_warning("ldap bind error : %s \n",ldap_err2string(err));
    }
    return NULL;
  }
  }
  return ld;
}

G_MODULE_EXPORT GSList* ldap_acl_check (connection* element){
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
G_MODULE_EXPORT GSList * ldap_user_check (connection * element,u_int16_t userid,char *passwd){
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
      g_message ("invalid return of ldap_search_st : %s\n",ldap_err2string(err));
    return -1;
  }

   if (ldap_count_entries(ld,res) == 1) {
     /* parse result to feed a user_list */
     result = ldap_first_entry(ld,res);
     if (result == NULL ){
       if (DEBUG_OR_NOT(DEBUG_LEVEL_INFO,DEBUG_AREA_AUTH))
	 g_message("Can not get entry for %d\n",userid);
       free_connection(element);
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

   } else {
     if (DEBUG_OR_NOT(DEBUG_LEVEL_MESSAGE,DEBUG_AREA_AUTH))
       g_message("No or too many users found with userid %d\n",userid);
     free_connection(element);
     return NULL;
   }
  ldap_msgfree(res);
  return 0;
}

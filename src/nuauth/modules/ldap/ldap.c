
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


confparams ldap_nuauth_vars[] = {
  { "ldap_server_addr" , G_TOKEN_STRING, 0 , LDAP_SERVER },
  { "ldap_server_port" ,G_TOKEN_INT , LDAP_SERVER_PORT,NULL },
  { "ldap_base_dn" , G_TOKEN_STRING , 0 ,LDAP_BASE},
  { "ldap_users_base_dn" , G_TOKEN_STRING , 0 ,LDAP_BASE},
  { "ldap_acls_base_dn" , G_TOKEN_STRING , 0 ,LDAP_BASE},
  { "ldap_bind_dn" , G_TOKEN_STRING , 0 ,LDAP_USER},
  { "ldap_bind_password" , G_TOKEN_STRING , 0, LDAP_CRED },
  { "ldap_request_timeout" , G_TOKEN_INT , LDAP_REQUEST_TIMEOUT , NULL }
};

/* Init ldap system */
G_MODULE_EXPORT gchar* 
g_module_check_init(GModule *module){
  char *configfile=DEFAULT_CONF_FILE;
  gpointer vpointer; 
  char *ldap_base_dn=LDAP_BASE;

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
  vpointer=get_confvar_value(ldap_nuauth_vars,sizeof(ldap_nuauth_vars)/sizeof(confparams),"ldap_base_dn");
  ldap_base_dn=(char *)(vpointer?vpointer:ldap_base_dn);
  vpointer=get_confvar_value(ldap_nuauth_vars,sizeof(ldap_nuauth_vars)/sizeof(confparams),"ldap_users_base_dn");
  ldap_users_base_dn=(char *)(vpointer?vpointer:ldap_users_base_dn);
  vpointer=get_confvar_value(ldap_nuauth_vars,sizeof(ldap_nuauth_vars)/sizeof(confparams),"ldap_acls_base_dn");
  ldap_acls_base_dn=(char *)(vpointer?vpointer:ldap_acls_base_dn);

  if (! strcmp(ldap_acls_base_dn,LDAP_BASE) )
    ldap_acls_base_dn=ldap_base_dn;
  if (! strcmp(ldap_users_base_dn,LDAP_BASE) )
    ldap_users_base_dn=ldap_base_dn;

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
      /* Goes to ssl if needed */
#ifdef LDAP_OPT_X_TLS
      if (ldap_server_port ==  LDAPS_PORT){
        int tls_option;
        tls_option = LDAP_OPT_X_TLS_TRY;
        ldap_set_option(ld, LDAP_OPT_X_TLS, (void *)&tls_option);
      }
#endif /* LDAP_OPT_X_TLS */
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

G_MODULE_EXPORT GSList* acl_check (connection* element){
  GSList * g_list = NULL;
  char filter[LDAP_QUERY_SIZE];
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
    if (snprintf(filter,LDAP_QUERY_SIZE-1,
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
	     ) >= (LDAP_QUERY_SIZE -1)){
        if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
          g_warning ("LDAP query too big (more than %d bytes)\n",LDAP_QUERY_SIZE);
        return NULL;
    }
  } else if ((element->tracking_hdrs).protocol == IPPROTO_ICMP ) {
    if (snprintf(filter,LDAP_QUERY_SIZE-1,
	     "(&(objectClass=NuAccessControlList)(SrcIPStart<=%lu)(SrcIPEnd>=%lu)(DstIPStart<=%lu)(DstIPEnd>=%lu)(Proto=%d)(SrcPortStart<=%d)(SrcPortEnd>=%d)(DstPortStart<=%d)(DstPortEnd>=%d))",
	     (long unsigned int)(element->tracking_hdrs).saddr,
	     (long unsigned int)(element->tracking_hdrs).saddr,
	     (long unsigned int)(element->tracking_hdrs).daddr,
	     (long unsigned int)(element->tracking_hdrs).daddr,
	     (element->tracking_hdrs).protocol,
	     (element->tracking_hdrs).type,
	     (element->tracking_hdrs).type,
	     (element->tracking_hdrs).code,
	     (element->tracking_hdrs).code
	     ) >= (LDAP_QUERY_SIZE-1)){
        if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
          g_warning ("LDAP query too big (more than %d bytes)\n",LDAP_QUERY_SIZE);
        return NULL;
    }
  }

  /* send query and wait result */
  timeout.tv_sec = ldap_request_timeout;
  timeout.tv_usec = 0;
    
  err =  ldap_search_st(ld, ldap_acls_base_dn, LDAP_SCOPE_SUBTREE,filter,NULL,0,
			&timeout,
			&res) ;
  if ( err !=  LDAP_SUCCESS ) {
    if (err == LDAP_SERVER_DOWN ){
      /* we lost connection, so disable current one */
        if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
                g_warning ("disabling current connection");
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
      g_assert(this_acl);
      this_acl->groups=NULL;
	/* get decision */
	attrs_array=ldap_get_values(ld, result, "Decision");
	sscanf(*attrs_array,"%d",(int *)&(this_acl->answer));
        if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_AUTH))
                g_message("Acl found with decision %d\n",this_acl->answer);
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
	/* add when acl is filled */
	if (this_acl->groups !=NULL){
	  g_list = g_slist_prepend(g_list,this_acl);
	} else {
	  g_free(this_acl);
	}
      }
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
  char filter[LDAP_QUERY_SIZE];
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
	return NULL;
    }
  }
  if (snprintf(filter,LDAP_QUERY_SIZE-1,"(&(objectClass=NuAccount)(uidNumber=%d))",userid) >= (LDAP_QUERY_SIZE-1)){
    if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
       g_warning ("LDAP query too big (more than %d bytes)\n",LDAP_QUERY_SIZE);
     return NULL;
  }
  
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
        if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
                g_warning ("disabling current connection");
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
       sscanf(*attrs_array,"%127s",passwd);
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
  return NULL;
}

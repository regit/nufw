
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
#include <auth_dbm.h>


confparams dbm_nuauth_vars[] = {
  { "dbm_users_file" , G_TOKEN_STRING, 0 , DBM_USERS_FILE }
};

struct dbm_data_struct analyse_dbm_char(char *data)
{
	char *tmpchar, *tmp2;
	struct dbm_data_struct myresult;
	int i=0;//stupid counter
	tmpchar = (char *) malloc (strlen(data) +1);
	myresult.outelt = NULL;
	if (tmpchar == NULL)
	{
		if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
			g_warning("Could not malloc for tmpchar\n");
		return NULL;
	}
	strncpy(tmpchar,data,strlen(data) +1);
	while (data=strchr(tmpchar,32)) // 32 is ASCII code for space " "
	{
		if  (i==0)
		{
			i++;
			myresult.passwd = (char *) malloc (data-tmpchar);
			strncpy(myresult.passwd,tmpchar,(data-tmpchar)-1);
			strncpy(myresult.passwd + (data-tmpchar),"\0",1);
		}else{
			tmp2 = (char *) malloc (data-tmpchar);
			strncpy(tmp2,tmpchar,(data-tmpchar)-1);
			strncpy(tmp2 + (data-tmpchar),"\0",1);
			myresult.outelt = g_slist_prepend(myresult.outelt, GINT_TO_POINTER(atoi(tmp2)));
			free (tmp2);
		}
		tmpchar = data++;
	}
	return (myresult);
}



/* Init dbm system */
G_MODULE_EXPORT gchar* 
g_module_check_init(GModule *module){
  char *configfile=DEFAULT_CONF_FILE; 
  gpointer vpointer; 

  /* init global variables */
  users_file = DBM_USERS_FILE;
  
  /* parse conf file */
  parse_conffile(configfile,sizeof(dbm_nuauth_vars)/sizeof(confparams),dbm_nuauth_vars);
  /* set variables */
  vpointer=get_confvar_value(ldap_nuauth_vars,sizeof(ldap_nuauth_vars)/sizeof(confparams),"dbm_users_file");
  users_file=(char *)(vpointer?vpointer:users_file);

  /* init thread private stuff */
  dbm_priv = g_private_new (g_free);

  return NULL;
}

/* 
 * Initialize dbm file access
 */

G_MODULE_EXPORT LDAP* dbm_file_init(void){
  GDBM_FILE dbf = NULL;
  int err;

  /* init connection */
  dbf = gdbm_open(users_file,DBM_BLOCK_SIZE,DBM_FILE_ACCESS_MODE,DBM_FILE_MODE,DBM_FATAL_FUNCTION);
  if(dbf == NULL) {
    if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
      g_warning("dbm init error : %s\n",gdbm_strerror ( errno ));
    g_private_set(dbm_priv,dbf);
    return NULL;
  }
  return dbf;
}

#if 0
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
    // init ldap has never been done 
    ld = ldap_conn_init();
    if (ld == NULL) {
	if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_AUTH))
		g_warning("Can not initiate LDAP conn\n");
	return NULL;
    }
    g_private_set(ldap_priv,ld);
  }
  // contruct filter 
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

  // send query and wait result 
  timeout.tv_sec = ldap_request_timeout;
  timeout.tv_usec = 0;
  // TODO : just get group and decision 
  // if (debug)
  //   printf("Filter : %s\n",filter); 
    
  err =  ldap_search_st(ld, ldap_acls_base_dn, LDAP_SCOPE_SUBTREE,filter,NULL,0,
			&timeout,
			&res) ;
  if ( err !=  LDAP_SUCCESS ) {
    if (err == LDAP_SERVER_DOWN ){
      // we lost connection, so disable current one 
      ldap_unbind(ld);
      ld=NULL;
      g_private_set(ldap_priv,ld);
    }
    if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
      g_warning ("invalid return from ldap_search_st : %s\n",ldap_err2string(err));
    return NULL;
  }
  // parse result to feed a group_list 
  if (ldap_count_entries(ld,res) >= 1) {
    result = ldap_first_entry(ld,res);
    while ( result ) {
      // allocate a new acl_group 
      this_acl=g_new0(struct acl_group,1);
      this_acl->groups=NULL;
	g_list = g_slist_prepend(g_list,this_acl);
	// get decision 
	attrs_array=ldap_get_values(ld, result, "Decision");
	sscanf(*attrs_array,"%c",&(this_acl->answer));
	ldap_value_free(attrs_array);
	// build groups  list 
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

#endif

G_MODULE_EXPORT GSList * user_check (u_int16_t userid,char *passwd){
  GDBM_FILE dbf = g_private_get (ldap_priv);
  datum dbm_key, dbm_data;

  char ** attrs_array, ** walker;
  int attrs_array_len,i,group,err;
  struct timeval timeout;
  struct dbm_data_struct return_data;
  GSList * outelt=NULL;

  if (dbf == NULL){
    /* init ldap has never been done */
    dbf = dbm_file_init();
    g_private_set(dbm_priv,dbf);
    if (dbf == NULL){
	if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_AUTH))
		g_message("Can't access DBM database\n");
	return -1;
    }
  }
  //Initialize our data structure
  if (sprintf(dbm_key.dptr,"%hi",userid) <= 0)
  {
	  if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_AUTH))
		  g_message("Could not convert userid %hi\n",userid);
  	  return NULL;
  }
  dbm_key.dsize = strlen(dbm_key.dptr);
  
  if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_AUTH))
	  g_message("user id is %s, size %i\n",dbm_key.dptr,dbm_key.dsize);
 
  //Check key exists before trying to fetch its value
  if (! gdbm_exists(dbf,dbm_key))
  {
	  if (DEBUG_OR_NOT(DEBUG_LEVEL_MESSAGE,DEBUG_AREA_AUTH))
		  g_message("no key \"%s, size %i\" could be found in database\n",dbm_key.dptr,dbm_key.dsize);
	  return NULL;
  }
  dbm_data = gdbm_fetch(dbf,dbm_key);
  if (dbm_data == NULL)
  {
	  if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_AUTH))
		  g_message("key \"%s, size %i\" exists in database, but cannot be fetched ?!\n",dbm_key.dptr,dbm_key.dsize);
	  return NULL;
  }
  if (strlen(dbm_data.dptr) != dbm_data.dsize)
  {
	  if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_AUTH))
		  g_message("inconsistency in database? advertized data size is not actual size for key %s (size %i)\n",dbm_key.dptr,dbm_key.dsize);
	  return NULL;
  }
  return_data = analyse_dbm_char(dbm_data.dptr);
  if (strcmp ( passwd , return_data.passwd ) == 0 )
	  return (return_data.outelt);
  return NULL;
}

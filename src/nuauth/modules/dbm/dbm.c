
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
#include <math.h>


confparams dbm_nuauth_vars[] = {
  { "dbm_users_file" , G_TOKEN_STRING, 0 , DBM_USERS_FILE }
};

int analyse_dbm_char(char *data, struct dbm_data_struct *mystruct)
{
	char *tmpchar, *tmp2;
	int i=0;//stupid counter

	tmpchar = (char *) malloc (strlen(data) +1);
	mystruct->outelt = NULL;
	if (tmpchar == NULL)
	{
		if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
			g_warning("Could not malloc for tmpchar\n");
		return -1;
	}
	strncpy(tmpchar,data,strlen(data) +1);
	data=strchr(tmpchar,32);
	while (data != NULL ) // 32 is ASCII code for space " "
	{
		if  (i==0)
		{
			if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
				g_message("Extracting password...");
			i++;
			mystruct->passwd = (char *) malloc (data-tmpchar);
			strncpy(mystruct->passwd,tmpchar,(data-tmpchar));
			strncpy(mystruct->passwd + (data-tmpchar),"\0",1);
		}else{
			if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
				g_message("Extracting a group we found...");
			tmp2 = (char *) malloc (data-tmpchar);
			strncpy(tmp2,tmpchar,(data-tmpchar));
			strncpy(tmp2 + (data-tmpchar),"\0",1);
			mystruct->outelt = g_slist_prepend(mystruct->outelt, GINT_TO_POINTER(atoi(tmp2)));
			if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
				g_message("got *%s*\n",tmp2);
			free (tmp2);
		}
		tmpchar = ++data;
		data=strchr(tmpchar,32);
	}
	return 0;
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
  vpointer=get_confvar_value(dbm_nuauth_vars,sizeof(dbm_nuauth_vars)/sizeof(confparams),"dbm_users_file");
  users_file=(char *)(vpointer?vpointer:users_file);

  /* init thread private stuff */
  dbm_priv = g_private_new (g_free);
  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
	  g_message("We are leaving g_module_check_init()\n");

  return NULL;
}

/* 
 * Initialize dbm file access
 */


GDBM_FILE dbm_file_init(void){
  GDBM_FILE dbf;

  /* init connection */
  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
	  g_message("We are entering dbm_file_init()\n");
  dbf = gdbm_open(users_file,DBM_BLOCK_SIZE,DBM_FILE_ACCESS_MODE,DBM_FILE_MODE,DBM_FATAL_FUNCTION);
  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
    g_message("dbm_file_init : file should be open now()\n");
  if(dbf == NULL) {
    if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_MAIN))
      g_warning("dbm init error\n");
    return NULL;
  }
  
  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
	  g_message("We are leaving dbm_file_init()\n");
  return dbf;
}

G_MODULE_EXPORT GSList * user_check (u_int16_t userid,char *passwd){
  GDBM_FILE dbf = g_private_get (dbm_priv);
  datum dbm_key, dbm_data;
  struct dbm_data_struct effective_data, *return_data;

  return_data = &effective_data;
  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
	  g_message("We are entering dbm_user_check()\n");
  if (dbf == NULL){
    /* dbm init has not been done yet*/
    if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
	    g_message("calling dbm_file_init() now\n");

    dbf = dbm_file_init();
    g_private_set(dbm_priv,dbf);
    if (dbf == NULL){
	if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_AUTH))
		g_message("Can't access DBM database\n");
	return NULL;
    }
  }
  //Initialize our data structure
  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_AUTH))
	  g_message("Initializing our data structure, with %hi\n",userid);
  dbm_key.dptr = (char *) malloc (sizeof(rint(log(userid)/log(10)))+1);
  if (dbm_key.dptr == NULL)
	  g_error("Could not malloc()\n");
  if (sprintf(dbm_key.dptr,"%hi",userid) <= 0)
  {
	  if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_AUTH))
		  g_message("Could not convert userid %hi\n",userid);
  	  return NULL;
  }
  dbm_key.dsize = strlen(dbm_key.dptr);
  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_AUTH))
	  g_message("data structure now initialized");
  
  if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_AUTH))
	  g_message("user id is %s, size %i\n",dbm_key.dptr,dbm_key.dsize);
 
  //Check key exists before trying to fetch its value
  if (! gdbm_exists(dbf,dbm_key))
  {
	  if (DEBUG_OR_NOT(DEBUG_LEVEL_MESSAGE,DEBUG_AREA_AUTH))
		  g_message("no key \"%s, size %i\" could be found in database\n",dbm_key.dptr,dbm_key.dsize);
	  return NULL;
  }
  if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_AUTH))
	  g_message("key %s, size %i was found. good\n",dbm_key.dptr,dbm_key.dsize);
  dbm_data = gdbm_fetch(dbf,dbm_key);
  if (dbm_data.dptr == NULL)
  {
	  if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_AUTH))
		  g_warning("key \"%s, size %i\" exists in database, but cannot be fetched ?!\n",dbm_key.dptr,dbm_key.dsize);
	  return NULL;
  }
/*  if (strlen(dbm_data.dptr) != dbm_data.dsize)
  {
	  if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_AUTH))
		  g_warning("inconsistency in database? advertized data size is not actual size for key %s (data size %i), found size %i\n",dbm_key.dptr,dbm_data.dsize,strlen(dbm_data.dptr));
	  return NULL;
  }*/
  if (DEBUG_OR_NOT(DEBUG_LEVEL_DEBUG,DEBUG_AREA_AUTH))
	  g_message("Data shall now be analysed : %s\n",dbm_data.dptr);
  if (analyse_dbm_char(dbm_data.dptr,return_data) != 0)
  {
    if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_AUTH))
	    g_message("A problem occured when analysing data for key %s, size %i\n",dbm_key.dptr, dbm_key.dsize);
    return NULL;
  }
  if (return_data->outelt == NULL )
  {
	  if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_AUTH))
		  g_warning("inconsistency in database? unable to parse data for key %s (size %i)\n",dbm_key.dptr,dbm_key.dsize);
	  return NULL;
  }
  if (strcmp ( passwd , return_data->passwd ) == 0 )
  {
	  if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_AUTH))
		  g_message("Correct auth received for user %s\n",dbm_key.dptr);
	  return (return_data->outelt);
  }
  return NULL;
}

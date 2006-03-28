
/*
 ** Copyright(C) 2003-2004 Eric Leblond <eric@regit.org>
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

#include "../../nuauth_gcrypt.h"

/*TODO : add a gdbm_close() routine somewhere - Same for ldap (and any module
 * too), probably...*/


confparams dbm_nuauth_vars[] = {
    { "dbm_users_file" , G_TOKEN_STRING, 0 , DBM_USERS_FILE }
};

int analyse_dbm_char(char *datas, struct dbm_data_struct *mystruct)
    /* IN : char containing, space separated, in this order (it MUST end with a
     * space, else last group isnt read): 
     * password userid group1 group2 ... group N
     * OUT : the data string gets scrambled over, it shouldnt be used anymore after
     * call this function. The structure gets filled with password and groups.
     */
    /*TODO : limit the size of acceptable password, and groups. Even if there
     * should not be any buffer overflow with this, those should probably never
     * exceed a well-chosen value*/
{
  char **split_datas;
  char **way_datas;

  mystruct->outelt = NULL;
  split_datas=g_strsplit(datas," ",0);
  debug_log_message(VERBOSE_DEBUG, AREA_MAIN, "Extracting password...");
  mystruct->passwd=g_strdup(*split_datas);
  way_datas = split_datas++;
  mystruct->uid=atoi(*split_datas);
  split_datas++;
  debug_log_message(VERBOSE_DEBUG, AREA_MAIN, "it's %s",mystruct->passwd);
  while(*split_datas){
      if(atoi(*split_datas)>0){
          mystruct->outelt = g_slist_prepend(mystruct->outelt, GINT_TO_POINTER(atoi(*split_datas)));
          debug_log_message(VERBOSE_DEBUG, AREA_MAIN, "got *%s*\n",*split_datas);
      }
      split_datas++;
  }
  g_strfreev(way_datas);
  return 0;
}


G_MODULE_EXPORT gboolean module_params_unload(gpointer params_p)
{
  struct dbm_params* params=(struct dbm_params*)params_p;
  if (params) {
      GDBM_FILE dbf = g_private_get (params->dbm_priv);
      gdbm_close(dbf);
  }
  g_free(params);
  return TRUE;
}

/* Init dbm system */
G_MODULE_EXPORT gboolean init_module_from_conf(module_t* module)
{
  char *configfile=DEFAULT_CONF_FILE; 
  gpointer vpointer; 
  struct dbm_params* params=g_new0(struct dbm_params,1);

  /* init global variables */
  params->users_file = DBM_USERS_FILE;

  /* parse conf file */
  if (module->configfile){
      parse_conffile(module->configfile,sizeof(dbm_nuauth_vars)/sizeof(confparams),dbm_nuauth_vars);
  } else {
      parse_conffile(configfile,sizeof(dbm_nuauth_vars)/sizeof(confparams),dbm_nuauth_vars);
  }
  /* set variables */
  vpointer=get_confvar_value(dbm_nuauth_vars,sizeof(dbm_nuauth_vars)/sizeof(confparams),"dbm_users_file");
  params->users_file=(char *)(vpointer?vpointer:params->users_file);

  /* init thread private stuff */
  params->dbm_priv = g_private_new (g_free);
  debug_log_message(VERBOSE_DEBUG, AREA_MAIN, "We are leaving g_module_check_init()\n");

  return TRUE;
}

/* 
 * Initialize dbm file access
 */


GDBM_FILE dbm_file_init(struct dbm_params *params){
    GDBM_FILE dbf;

    /* init connection */
	debug_log_message(VERBOSE_DEBUG, AREA_MAIN, "We are entering dbm_file_init()\n");
    dbf = gdbm_open(params->users_file,DBM_BLOCK_SIZE,DBM_FILE_ACCESS_MODE,DBM_FILE_MODE,DBM_FATAL_FUNCTION);
	debug_log_message(VERBOSE_DEBUG, AREA_MAIN, "dbm_file_init : file should be open now()\n");
	if(dbf == NULL) {
		log_message(WARNING, AREA_MAIN, "dbm init error\n");
		return NULL;
	}

	debug_log_message(VERBOSE_DEBUG, AREA_MAIN, "We are leaving dbm_file_init()\n");
    return dbf;
}


G_MODULE_EXPORT int user_check(const char *username, const char *pass,unsigned passlen,uint32_t *uid,GSList **groups,gpointer params_p)
{
  struct dbm_params* params=(struct dbm_params*)params_p;
  GDBM_FILE dbf = g_private_get (params->dbm_priv);
  datum dbm_key, dbm_data;
  struct dbm_data_struct return_data;
  char* user;
  static GStaticMutex dbm_initmutex = G_STATIC_MUTEX_INIT;

  debug_log_message(VERBOSE_DEBUG, AREA_MAIN, "We are entering dbm_user_check()\n");

  /* init has only to be done once */
  g_static_mutex_lock (&dbm_initmutex);
  if (dbf == NULL){
      /* dbm init has not been done yet*/
		debug_log_message(VERBOSE_DEBUG, AREA_MAIN, "calling dbm_file_init() now\n");
      dbf = dbm_file_init(params);
      g_private_set(params->dbm_priv,dbf);
      if (dbf == NULL){
          if (DEBUG_OR_NOT(DEBUG_LEVEL_SERIOUS_WARNING,DEBUG_AREA_AUTH))
              g_message("Can't access DBM database\n");
          return SASL_BADAUTH;
      }
  }
  g_static_mutex_unlock (&dbm_initmutex);

  /* compute user name */
  user = get_rid_of_domain(username);

  dbm_key.dsize = strlen(user);
  dbm_key.dptr = g_strdup(user);

  debug_log_message(DEBUG, AREA_AUTH, "user id is %s, size %i\n",dbm_key.dptr,dbm_key.dsize);
  /* Check key exists before trying to fetch its value */
	if (! gdbm_exists(dbf,dbm_key))
	{
		log_message(MESSAGE, AREA_AUTH, "no key \"%s, size %i\" could be found in database\n",dbm_key.dptr,dbm_key.dsize);
		g_free(dbm_key.dptr);
		return SASL_BADAUTH;
	}
	debug_log_message(DEBUG, AREA_AUTH, "key %s, size %i was found. good\n",dbm_key.dptr,dbm_key.dsize);
	
  dbm_data = gdbm_fetch(dbf,dbm_key);
  if (dbm_data.dptr == NULL)
  {
      if (DEBUG_OR_NOT(DEBUG_LEVEL_WARNING,DEBUG_AREA_AUTH))
          g_warning("key \"%s, size %i\" exists in database, but cannot be fetched ?!\n",dbm_key.dptr,dbm_key.dsize);
      g_free(dbm_key.dptr);
      return SASL_BADAUTH;
  }

	/* string is not NULL terminated */
	if (analyse_dbm_char(dbm_data.dptr,&return_data) != 0)
	{
		log_message(WARNING, AREA_AUTH, "A problem occured when analysing data for key %s, size %i\n",dbm_key.dptr, dbm_key.dsize);
		g_free(dbm_key.dptr);
		return SASL_BADAUTH;
	}
	if (return_data.outelt == NULL )
	{
		log_message(WARNING, AREA_AUTH, "inconsistency in database? unable to parse data for key %s (size %i)\n",dbm_key.dptr,dbm_key.dsize);
		g_free(dbm_key.dptr);
		return SASL_BADAUTH;
	}
	g_free(dbm_key.dptr);
	g_free(dbm_data.dptr);
	/* We found a relevant entry in database. Now check passwords match. */
	if (pass != NULL) {
		if ( return_data.passwd==NULL ){
			log_message(INFO, AREA_AUTH, "No password for user \"%s\"",user);
			return SASL_BADAUTH;
		}
		/*  if (strcmp(pass,return_data.passwd)){ */
		if (verify_user_password(pass,return_data.passwd) != SASL_OK){
			log_message(INFO, AREA_AUTH, "Bad password for user \"%s\"",user);
			return SASL_BADAUTH;
		}
	}
	*groups = return_data.outelt;
	return SASL_OK;
	}

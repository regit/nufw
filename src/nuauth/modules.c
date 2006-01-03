/*
 ** Copyright(C) 2005 INL
 ** written by  Eric Leblond <regit@inl.fr>
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
 **
 ** In addition, as a special exception, the copyright holders give
 ** permission to link the code of portions of this program with the
 ** Cyrus SASL library under certain conditions as described in each
 ** individual source file, and distribute linked combinations
 ** including the two.
 ** You must obey the GNU General Public License in all respects
 ** for all of the code used other than Cyrus SASL.  If you modify
 ** file(s) with this exception, you may extend this exception to your
 ** version of the file(s), but you are not obligated to do so.  If you
 ** do not wish to do so, delete this exception statement from your
 ** version.  If you delete this exception statement from all source
 ** files in the program, then also delete it here.
 **
 ** This product includes software developed by Computing Services
 ** at Carnegie Mellon University (http://www.cmu.edu/computing/).
 **
 */

/*! \file modules.c
    \brief Take care of interaction with modules
    
    It contains the functions that load and unload modules as well as all 
    *_check functions use in the code to interact with the modules
*/




#include <auth_srv.h>
#include "modules_definition.h"

/**
 * Check a user/password against the list of modules used for user authentication
 *  It returns the decision using SASL define return value and fill uid and list of groups
 *  the user belongs to.
 */

int user_check (const char *user, const char *pass,unsigned passlen,uint16_t *uid,GSList **groups){
	/* iter through module list and stop when user is found */
	GSList *walker=user_check_modules;
	int walker_return=0;
	for (;walker!=NULL;walker=walker->next ){
		walker_return=(*(user_check_callback*)(walker->data))(user,pass,passlen,uid,groups);
		if (walker_return == SASL_OK)
			return SASL_OK;
	}
	return SASL_NOAUTHZ;
}

/**
 * Check a connection and return a list of acl that match the information
 * contained in the connection.
 */

GSList * acl_check (connection* element){
	/* iter through module list and stop when an acl is found */
	GSList *walker=acl_check_modules;
	GSList* walker_return=NULL;

	for (;walker!=NULL;walker=walker->next ){
		walker_return=(*(acl_check_callback*)(walker->data))(element);
		if (walker_return)
			return walker_return;
	}

	return NULL;
}

/* ip auth */
gchar* ip_auth(tracking * header){
	/* iter through module list and stop when decision is made */
	GSList *walker=ip_auth_modules;
	gchar* walker_return=NULL;
	for (;walker!=NULL;walker=walker->next ){
		walker_return=(*(ip_auth_callback*)(walker->data))(header);
		if (walker_return)
			return walker_return;
	}
	return NULL;
}


/**
 * log authenticated packets
 */
int user_logs (connection element, int state){
	/* iter through all modules list */
	GSList *walker=user_logs_modules;
	for (;walker!=NULL;walker=walker->next ){
		(*(user_logs_callback*)(walker->data))(element,state);
	}

	return 0;
}

/**
 * log user connection and disconnection
 */
int user_session_logs(user_session* user , int state){
    /* iter through all modules list */
    GSList *walker=user_session_logs_modules;
    for (;walker!=NULL;walker=walker->next ){
        (*(user_session_logs_callback*)(walker->data))(user,state);
    }

    return 0;
}

/** 
 * parse time period configuration for each module
 * and fille the given hash (first argument)
 */

void parse_periods(GHashTable* periods)
{
   /* iter through all modules list */
    GSList *walker=period_modules;
    for (;walker!=NULL;walker=walker->next ){
        (*(define_period_callback*)(walker->data))(periods);
    }
}

int init_modules_system(){
	/* init modules list mutex */
	modules_mutex = g_mutex_new ();
	user_check_modules=NULL;
	acl_check_modules=NULL;
        period_modules=NULL;
	ip_auth_modules=NULL;
	user_logs_modules=NULL;
        user_session_logs_modules=NULL;
	return 1;
}
/**
 * Load module for a task
 *
 * Please not that last args is a pointer of pointer
 */
static int load_modules_from(gchar* confvar, gchar* func,GSList** target)
{
	gchar** modules_list=g_strsplit(confvar," ",0);
	GModule * module;
	gchar* module_path;
	gpointer module_func;
	int i;
        char found;
        GSList *c_module;

	for (i=0;modules_list[i]!=NULL;i++) {	
		module_path = g_module_build_path(MODULE_PATH, modules_list[i]);
		module = g_module_open (module_path 
				,0);
		g_free(module_path);
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
			g_message("\tmodule %d: %s",i, modules_list[i]);
		if (module == NULL){
			g_error("Unable to load module %s in %s",modules_list[i],MODULE_PATH);
		}

		if (!g_module_symbol (module, func, 
					(gpointer*)&module_func))
		{
			g_error ("Unable to load function %s in %s\n",func,g_module_name(module));
		}

		*target=g_slist_append(*target,(gpointer)module_func);
                /** add modules to list of modules */
                found=0;
                 for(c_module=nuauthdatas->modules;c_module;c_module=c_module->next){
                        if(!strcmp(g_module_name((GModule*)(c_module->data)),g_module_name(module))){
                                found=1;
                                break;
                        }
                 }
                 if(found == 0){
                        nuauthdatas->modules=g_slist_prepend(nuauthdatas->modules,module);
                 }
	}
        g_strfreev(modules_list);
	return 1;

}
/**
 * Load modules for user and acl checking as well as for user logging and ip authentication
 */
int load_modules()
{
	char * nuauth_acl_check_module;
	char * nuauth_user_check_module;
	char * nuauth_user_logs_module;
	char * nuauth_user_session_logs_module;
	char * nuauth_ip_authentication_module;
        char * nuauth_periods_module;
	char *configfile=DEFAULT_CONF_FILE;
	confparams nuauth_vars[] = {
		{ "nuauth_user_check_module" , G_TOKEN_STRING , 1, g_strdup(DEFAULT_USERAUTH_MODULE) },
		{ "nuauth_acl_check_module" , G_TOKEN_STRING , 1, g_strdup(DEFAULT_ACLS_MODULE) },
		{ "nuauth_periods_module" , G_TOKEN_STRING , 1, g_strdup(DEFAULT_PERIODS_MODULE) },
		{ "nuauth_user_logs_module" , G_TOKEN_STRING , 1, g_strdup(DEFAULT_LOGS_MODULE) },
		{ "nuauth_user_session_logs_module" , G_TOKEN_STRING , 1, g_strdup(DEFAULT_LOGS_MODULE) },
		{ "nuauth_ip_authentication_module" , G_TOKEN_STRING , 1, g_strdup(DEFAULT_IPAUTH_MODULE) }
	};
	gpointer vpointer;

	/* parse conf file */
	parse_conffile(configfile,sizeof(nuauth_vars)/sizeof(confparams),nuauth_vars);

	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_user_check_module");
	nuauth_user_check_module=(char*)(vpointer);
	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_user_logs_module");
	nuauth_user_logs_module=(char*)(vpointer);

	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_user_session_logs_module");
	nuauth_user_session_logs_module=(char*)(vpointer);


	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_acl_check_module");
	nuauth_acl_check_module=(char*)(vpointer);

	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_periods_module");
	nuauth_periods_module=(char*)(vpointer);

	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_ip_authentication_module");
	nuauth_ip_authentication_module=(char*)(vpointer);

	/* external auth module loading */
	g_mutex_lock(modules_mutex);

	/* loading user check modules */
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
		g_message("Loading user checking modules:");
	load_modules_from(nuauth_user_check_module,"user_check",&user_check_modules);
	g_free(nuauth_user_check_module);
	/* loading acl check module */
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
		g_message("Loading acls checking modules:");
	load_modules_from(nuauth_acl_check_module,"acl_check",&acl_check_modules);
	g_free(nuauth_acl_check_module);


	load_modules_from(nuauth_periods_module,"define_periods",&period_modules);
	g_free(nuauth_periods_module);
        
	/* user logs modules */
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
		g_message("Loading user packet logging modules:");
	load_modules_from(nuauth_user_logs_module,"user_packet_logs",&user_logs_modules);
	g_free(nuauth_user_logs_module);
	/* user logs modules */
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
		g_message("Loading user session logging modules:");
	load_modules_from(nuauth_user_session_logs_module,"user_session_logs",&user_session_logs_modules);
	g_free(nuauth_user_session_logs_module);

	if (nuauthconf->do_ip_authentication){
		/* load module */
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
			g_message("Loading ip authentication modules:");
		load_modules_from(nuauth_ip_authentication_module,"ip_authentication",&ip_auth_modules);
		g_free(nuauth_ip_authentication_module);
	}

	g_mutex_unlock(modules_mutex);
	return 1;
}

int unload_modules()
{
        GSList *c_module;
        const gchar* module_name;

	g_mutex_lock(modules_mutex);
        g_slist_free(user_check_modules);
	user_check_modules=NULL;
        g_slist_free(acl_check_modules);
	acl_check_modules=NULL;
        g_slist_free(period_modules);
        period_modules=NULL;
        g_slist_free(ip_auth_modules);
	ip_auth_modules=NULL;
        g_slist_free(user_logs_modules);
	user_logs_modules=NULL;
        g_slist_free(user_session_logs_modules);
        user_session_logs_modules=NULL;

        for(c_module=nuauthdatas->modules;c_module;c_module=c_module->next){
                module_name=g_module_name((GModule*)(c_module->data));
                if (!g_module_close((GModule*)(c_module->data))){
                       g_message("module unloading failed for %s",module_name); 
                } else {
	                if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN)){
                                g_message("module unloading done for %s",module_name); 
                        }
                }
        }
        g_slist_free(nuauthdatas->modules);
        nuauthdatas->modules=NULL;
	g_mutex_unlock(modules_mutex);
	return 1;
}


void block_on_conf_reload()
{
	g_mutex_lock(nuauthdatas->reload_cond_mutex);
	if (nuauthdatas->need_reload){
		g_mutex_unlock(nuauthdatas->reload_cond_mutex);
		g_atomic_int_inc(&(nuauthdatas->locked_threads_number));
		while(nuauthdatas->need_reload){
			g_cond_wait (nuauthdatas->reload_cond, nuauthdatas->reload_cond_mutex);
		}
	} else {
		g_mutex_unlock(nuauthdatas->reload_cond_mutex);
	}
}



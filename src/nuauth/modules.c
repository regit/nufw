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


#include <auth_srv.h>
#include "modules_definition.h"

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

int user_logs (connection element, int state){
	/* iter through all modules list */
	GSList *walker=user_logs_modules;
	for (;walker!=NULL;walker=walker->next ){
		(*(user_logs_callback*)(walker->data))(element,state);
	}

	return 0;
}

int init_modules_system(){
	/* init modules list mutex */
	modules_mutex = g_mutex_new ();
	user_check_modules=NULL;
	acl_check_modules=NULL;
	ip_auth_modules=NULL;
	user_logs_modules=NULL;
	return 1;
}

int load_modules()
{
	char * nuauth_acl_check_module;
	char * nuauth_user_check_module;
	char * nuauth_user_logs_module;
	char * nuauth_ip_authentication_module;
	char *configfile=DEFAULT_CONF_FILE;
	GModule * auth_module,*logs_module,*acl_module,*ipauth_module;
	user_check_callback * module_user_check;
	acl_check_callback * module_acl_check;
	ip_auth_callback * module_ip_auth;
	user_logs_callback * module_user_logs;
	confparams nuauth_vars[] = {
		{ "nuauth_user_check_module" , G_TOKEN_STRING , 1, g_strdup(DEFAULT_USERAUTH_MODULE) },
		{ "nuauth_acl_check_module" , G_TOKEN_STRING , 1, g_strdup(DEFAULT_ACLS_MODULE) },
		{ "nuauth_user_logs_module" , G_TOKEN_STRING , 1, g_strdup(DEFAULT_LOGS_MODULE) },
		{ "nuauth_ip_authentication_module" , G_TOKEN_STRING , 1, g_strdup(DEFAULT_IPAUTH_MODULE) }
	};
	gchar* module_path;
	gpointer vpointer;

	/* parse conf file */
	parse_conffile(configfile,sizeof(nuauth_vars)/sizeof(confparams),nuauth_vars);

	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_user_check_module");
	nuauth_user_check_module=(char*)(vpointer);//?vpointer:nuauth_user_check_module);
	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_user_logs_module");
	nuauth_user_logs_module=(char*)(vpointer);//?vpointer:nuauth_user_logs_module);


	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_acl_check_module");
	nuauth_acl_check_module=(char*)(vpointer);//?vpointer:nuauth_acl_check_module);

	vpointer=get_confvar_value(nuauth_vars,sizeof(nuauth_vars)/sizeof(confparams),"nuauth_ip_authentication_module");
	nuauth_ip_authentication_module=(char*)(vpointer);//?vpointer:nuauth_ip_authentication_module);

	/* external auth module loading */
	g_mutex_lock(modules_mutex);

	/* loading user check modules */
	module_path=g_module_build_path(MODULE_PATH,
			nuauth_user_check_module);
	auth_module=g_module_open (module_path,0);
	g_free(module_path);
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
		g_message("Auth (user) module: %s", nuauth_user_check_module);
	if (auth_module == NULL){
		g_error("Unable to load module %s in %s",nuauth_user_check_module,MODULE_PATH);
	}

	if (!g_module_symbol (auth_module, "user_check", 
				(gpointer*) &module_user_check))
	{
		g_error ("Unable to load user checking function\n");
	}

	user_check_modules=g_slist_append(user_check_modules,(gpointer)module_user_check);

	/* loading acl check module */
	if ( strcmp(nuauth_user_check_module,nuauth_acl_check_module)){
		module_path = g_module_build_path(MODULE_PATH, nuauth_acl_check_module);
		acl_module = g_module_open (module_path 
				,0);
		g_free(module_path);
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
			g_message("ACL module: %s", nuauth_acl_check_module);
		if (auth_module == NULL){
			g_error("Unable to load module %s in %s",nuauth_acl_check_module,MODULE_PATH);
		}
	} else {
		acl_module=auth_module;
	}

	if (!g_module_symbol (acl_module, "acl_check", 
				(gpointer*)&module_acl_check))
	{
		g_error ("Unable to load acl checking function\n");
	}

	acl_check_modules=g_slist_append(acl_check_modules,(gpointer)module_acl_check);
	/* free configuration variables */
	g_free(nuauth_user_check_module);
	g_free(nuauth_acl_check_module);
	
	/* user logs modules */
	user_logs_modules=NULL;
	module_path=g_module_build_path(MODULE_PATH,
			nuauth_user_logs_module);
	logs_module=g_module_open (module_path,0);
	g_free(module_path);
	if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
		g_message("User logs module: %s", nuauth_user_logs_module);
	if (logs_module == NULL){
		g_error("Unable to load module %s in %s",nuauth_user_logs_module,MODULE_PATH);
	}
	g_free(nuauth_user_logs_module);

	if (!g_module_symbol (logs_module, "user_packet_logs", 
				(gpointer*) &module_user_logs))
	{
		g_error ("Unable to load user logging function\n");
	}


	user_logs_modules=g_slist_append(user_logs_modules,(gpointer)module_user_logs);

	if (nuauth_do_ip_authentication){
		/* load module */
		module_path=g_module_build_path(MODULE_PATH,
				nuauth_ip_authentication_module);
		ipauth_module=g_module_open (module_path,0);
		g_free(module_path);
		if (DEBUG_OR_NOT(DEBUG_LEVEL_VERBOSE_DEBUG,DEBUG_AREA_MAIN))
			g_message("IP Auth (user) module: %s",nuauth_ip_authentication_module);
		if (auth_module == NULL){
			g_error("Unable to load module %s in %s",nuauth_ip_authentication_module,MODULE_PATH);
		}
		g_free(nuauth_ip_authentication_module);

		if (!g_module_symbol (ipauth_module, "ip_authentication", 
					(gpointer*) &module_ip_auth))
		{
			g_error ("Unable to load ip authentication function\n");
		}

		ip_auth_modules=g_slist_append(ip_auth_modules,(gpointer)module_ip_auth);
	}

	g_mutex_unlock(modules_mutex);
	return 1;
}

int unload_modules()
{
	g_mutex_lock(modules_mutex);
	/*TODO put unload code here */
	g_mutex_unlock(modules_mutex);
	return 1;
}

/*
 ** Copyright 2009 - INL
 ** Written by Pierre Chifflier <chifflier@inl.fr>
 ** INL http://www.inl.fr/
 **
 ** $Id$
 **
 ** This program is free software; you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, version 3 of the License.
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

/**
 * \defgroup libnuclient Libnuclient
 * @{
 */

/*! \file nuclient_plugins.c
 * \brief Plugins helper functions
 *
 * */

#include <config.h>

#include "libnuclient.h"
#include "nuclient.h"
#include "nufw_source.h"
#include "nuclient_plugins.h"
#include "nuclient_conf.h"

#include <nubase.h>

#if HAVE_DLFCN_H
# include <dlfcn.h>
#endif


static struct nuclient_plugin_t _nuclient_plugin_list;



static int _nuclient_init_plugin(struct nuclient_plugin_t *plugin) {
	nuclient_plugin_init_func func;
	int ret;

	func = dlsym(plugin->handle, NUCLIENT_PLUGIN_INIT_STR);
	if (func == NULL)
		return -1;

	ret = (*func)(PLUGIN_API_NUM, plugin);
	if (ret != 0) {
		/* plugin refused init */
		return ret;
	}

	return 0;
}

void nuclient_plugin_free(struct nuclient_plugin_t *tmp)
{
	if (tmp) {
		free(tmp->instance_name);
		// XXX we should refcount this
		if (tmp->handle)
			dlclose(tmp->handle);
		/* poison data, to prevent re-using */
		memset(tmp, 0, sizeof(*tmp));
		free(tmp);
	}
}

static void _nuclient_load_plugin(void *data, char *key, char *val)
{
	struct nuclient_plugin_t *l = data;
	struct nuclient_plugin_t *tmp;
	char *plugins_path = "/usr/lib/nuclient"; // XXX harcoded value
	void * handle;
	int dlopen_args = RTLD_LOCAL;

	if (strncmp(key,"instance",strlen("instance")) != 0)
		return;
	if (val == NULL || strlen(val) == 0)
		return;
printf("DEBUG trying to load instance : %s / %s\n", key, val);

	if (val[0] == '/')
		handle = dlopen(val, dlopen_args);
	else {
		char buffer[4096];

		snprintf(buffer, sizeof(buffer)-1,"%s/%s", plugins_path, val);
		handle = dlopen(buffer, dlopen_args);
	}

	if (handle == NULL) {
printf("WARNING Could not load plugin %s : %s\n", key, dlerror());
		return;
	}

	tmp = malloc(sizeof(*tmp));
	memset(tmp, 0, sizeof(*tmp));
	tmp->handle = handle;
	tmp->instance_name = strdup(key);

	if (_nuclient_init_plugin(tmp) != 0) {
printf("WARNING Plugin %s is not a valid plugin\n", key);
		nuclient_plugin_free(tmp);
		return;
	}

	llist_add(&(tmp->list), &(l->list));
printf("INFO Plugin %s loaded\n", key);

	/* XXX extract config section corresponding to plugin name
	 * and give it the the plugin,
	 * or find a way to give plugin access to config
	 */

	if (tmp->init != NULL) {
		(tmp->init)(tmp, NULL);
		return;
	}

}

int load_plugins(void)
{
	_nuclient_plugin_list.handle = NULL;
	_nuclient_plugin_list.instance_name = NULL;
	INIT_LLIST_HEAD(&_nuclient_plugin_list.list);

	nuclient_config_table_walk(&_nuclient_plugin_list, _nuclient_load_plugin);

	return 0;
}

int plugin_emit_event(plugin_event_t event_id, nuauth_session_t * session, const char *arg)
{
	struct nuclient_plugin_t *tmp;

printf("DEBUG event %d (%s)\n", event_id, arg);
	/* parse table */
	llist_for_each_entry(tmp, &_nuclient_plugin_list.list, list){
		printf("handle: %p instance_name: %s\n", tmp->handle, tmp->instance_name);
		if (tmp->dispatch) {
			(tmp->dispatch)(tmp, event_id, session, arg);
		}
	}


	return 0;
}

/** @} */



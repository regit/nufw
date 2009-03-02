/*
 ** Copyright(C) 2009 INL
 ** Written by Pierre Chifflier <chifflier@inl.fr>
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

#include <nubase.h>

#include "nuclient_conf.h"

#include "config-parser.h"

#include <unistd.h>
#include <stdlib.h>

static struct llist_head *nuclient_config_table_list = NULL;

/** \file nuclient_conf.c
 * \brief Read configuration file
 */

int nuclient_parse_configuration(const char *user_config, const char *global_config)
{
	struct llist_head *new_user_config = NULL, *new_global_config = NULL;

	if (access(user_config,R_OK) == 0) {
		new_user_config = parse_configuration(user_config);
	}

	if (access(global_config,R_OK) == 0) {
		new_global_config = parse_configuration(global_config);
	}

	if (nuclient_config_table_list != NULL)
		nuclient_config_table_destroy();

	if (new_user_config != NULL) {
		if (new_global_config == NULL) {
			/* user, but no global config */
			nuclient_config_table_list = new_user_config;
			return 0;
		}
		/* we have both config files, merge configs (user values
		 * override global values).
		 * Note: this is a O(n^2) operation, don't abuse it !
		 */
		 {
			 struct config_table_t *entry;

			llist_for_each_entry(entry, new_user_config, list) {
				nubase_config_table_set(new_global_config, entry->key, entry->value);
			}
			nubase_config_table_destroy(new_user_config);
			nuclient_config_table_list = new_global_config;
			return 0;
		 }
	} else {
		if (new_global_config != NULL) {
			/* global, but no user config */
			nuclient_config_table_list = new_global_config;
			return 0;
		}
		/* no global or user config, defaults to empty */
		nuclient_config_table_list = malloc(sizeof(struct llist_head));
		INIT_LLIST_HEAD( nuclient_config_table_list );
	}

	return 0;
}



char *nuclient_config_table_get(const char *key)
{
	return nubase_config_table_get(nuclient_config_table_list, key);
}

char *nuclient_config_table_get_alwaysstring(char *key)
{
	return nubase_config_table_get_alwaysstring(nuclient_config_table_list, key);
}

char *nuclient_config_table_get_or_default(char *key, char *replace)
{
	return nubase_config_table_get_or_default(nuclient_config_table_list, key, replace);
}

int nuclient_config_table_get_or_default_int(char *key, int defint)
{
	return nubase_config_table_get_or_default_int(nuclient_config_table_list, key, defint);
}

void nuclient_config_table_destroy(void)
{
	return nubase_config_table_destroy(nuclient_config_table_list);
	nuclient_config_table_list = NULL;
}

void nuclient_config_table_print(void *userdata, void (*func)(void *data, char *keyeqval))

{
	return nubase_config_table_print(nuclient_config_table_list,userdata,func);
}


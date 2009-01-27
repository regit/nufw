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

#include "nufwconf.h"

#include "config-parser.h"

#include <unistd.h>
#include <stdlib.h>

struct llist_head *nufw_config_table_list = NULL;

/** \file nufwconf.c
 * \brief Read configuration file
 */

int nufw_parse_configuration(const char *filename)
{
	struct llist_head *new_config = NULL;

	if (access(filename,R_OK) == 0) {
		new_config = parse_configuration(filename);

		if (new_config == NULL) {
			return -1;
		}
	}

	if (new_config == NULL) {
		new_config = malloc(sizeof(struct llist_head));
		INIT_LLIST_HEAD( new_config );
	}

	if (nufw_config_table_list != NULL)
		nufw_config_table_destroy();

	nufw_config_table_list = new_config;

	return 0;
}



char *nufw_config_table_get(const char *key)
{
	return nubase_config_table_get(nufw_config_table_list, key);
}

char *nufw_config_table_get_alwaysstring(char *key)
{
	return nubase_config_table_get_alwaysstring(nufw_config_table_list, key);
}

char *nufw_config_table_get_or_default(char *key, char *replace)
{
	return nubase_config_table_get_or_default(nufw_config_table_list, key, replace);
}

int nufw_config_table_get_or_default_int(char *key, int defint)
{
	return nubase_config_table_get_or_default_int(nufw_config_table_list, key, defint);
}

void nufw_config_table_destroy(void)
{
	return nubase_config_table_destroy(nufw_config_table_list);
	nufw_config_table_list = NULL;
}

void nufw_config_table_print(void *userdata, void (*func)(void *data, char *keyeqval))

{
	return nubase_config_table_print(nufw_config_table_list,userdata,func);
}


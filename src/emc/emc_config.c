/*
 ** Copyright(C) 2009 INL
 ** Written by Pierre Chifflier <chifflier@inl.fr>
 **     INL : http://www.inl.fr/
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

#include <config.h>

#include <unistd.h>
#include <string.h>

#include <nubase.h>
#include <config-parser.h>

#include "emc_server.h"
#include "emc_config.h"

static struct llist_head *emc_config_table_list = NULL;

int emc_init_config(const char *filename)
{
	struct llist_head *new_config;

	new_config = parse_configuration(filename);
	if (new_config == NULL)
		return -1;

	if (emc_config_table_list != NULL)
		emc_config_table_destroy();

	emc_config_table_list = new_config;

	return 0;
}

char *emc_config_table_get(const char *key)
{
	return nubase_config_table_get(emc_config_table_list, key);
}

char *emc_config_table_get_alwaysstring(char *key)
{
	return nubase_config_table_get_alwaysstring(emc_config_table_list, key);
}

char *emc_config_table_get_or_default(char *key, char *replace)
{
	return nubase_config_table_get_or_default(emc_config_table_list, key, replace);
}

int emc_config_table_get_or_default_int(char *key, int defint)
{
	return nubase_config_table_get_or_default_int(emc_config_table_list, key, defint);
}

void emc_config_table_destroy(void)
{
	nubase_config_table_destroy(emc_config_table_list);
	emc_config_table_list = NULL;
}



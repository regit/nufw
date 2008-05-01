/*
 ** Copyright(C) 2008 INL
 ** Written by Sebastien Tricaud <s.tricaud@inl.fr>
 **
 ** $Id$
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

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "linuxlist.h"
#include "config-table.h"

LLIST_HEAD(config_table_list);

char *nubase_config_table_get(char *key)
{
	struct config_table_t *config_table;

	llist_for_each_entry(config_table, &config_table_list, list) {
		if (!strncmp(key, config_table->key, strlen(config_table->key))) {
			return config_table->value;
		}
	}

	return NULL;
}

struct config_table_t *nubase_config_table_append(char *key, char *value)
{
	struct config_table_t *config_table;

	if (nubase_config_table_get(key)) return NULL;

	config_table = malloc(sizeof(*config_table));
	if ( ! config_table ) {
		errno = ENOMEM;
		return NULL;
	}

	config_table->key = key;
	config_table->value = value;

	llist_add_tail(&config_table->list, &config_table_list);

	return config_table;
}

#ifdef _UNIT_TEST_
#include <stdio.h>
int main(void)
{
	struct config_table_t *config_table;
	int i = 0;

	nubase_config_table_append("foo", "bar");
	nubase_config_table_append("foo", "bar");
	nubase_config_table_append("nu", "pik");
	nubase_config_table_append("tout", "foulcan");
	nubase_config_table_append("jean", "nemard");

	printf("\n........................\nllist_for_each_entry\n........................\n");

	llist_for_each_entry(config_table, &config_table_list, list) {
		printf("key=%s, value=%s\n", config_table->key, config_table->value);
	}

	printf("\n........................\nnubase_config_table_get\n........................\n");
	printf("The value for 'nu' is '%s'\n", nubase_config_table_get("nu"));

}
#endif


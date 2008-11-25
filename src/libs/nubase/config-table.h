/*
 ** Copyright(C) 2008 INL
 ** Written by Sebastien Tricaud <s.tricaud@inl.fr>
 **            Pierre Chifflier <chifflier@inl.fr>
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

#ifndef _CONFIG_TABLE_H_
#define _CONFIG_TABLE_H_

#include "linuxlist.h"

struct config_table_t {
	struct llist_head list;
	void *key;
	void *value;
} config_table_t;

char *nubase_config_table_get(struct llist_head *config_table_list, const char *key);
char *nubase_config_table_get_alwaysstring(struct llist_head *config_table_list, char *key);
char *nubase_config_table_get_or_default(struct llist_head *config_table_list, char *key, char *replace);
int nubase_config_table_get_or_default_int(struct llist_head *config_table_list, char *key, int defint);

struct config_table_t *nubase_config_table_append(struct llist_head *config_table_list, char *key, char *value);
void nubase_config_table_destroy(struct llist_head *config_table_list);
struct config_table_t *nubase_config_table_set(struct llist_head *config_table_list, char *key, char *value);
void nubase_config_table_print(struct llist_head *config_table_list, void *userdata, void (*func)(void *data, char *keyeqval));

#endif /* _CONFIG_TABLE_H_ */

